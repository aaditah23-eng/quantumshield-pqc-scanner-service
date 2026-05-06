import express from "express";
import cors from "cors";
import { execFile } from "child_process";
import { promisify } from "util";
import dns from "dns/promises";

const execFileAsync = promisify(execFile);
const app = express();
const PORT = process.env.PORT || 8080;
const API_KEY = process.env.PQC_SCANNER_API_KEY || "";

app.use(cors());
app.use(express.json({ limit: "64kb" }));

export function cleanDomain(input) {
  return String(input || "")
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .trim()
    .toLowerCase();
}

export function isValidDomain(domain) {
  if (!domain || domain.length > 253) return false;
  if (domain.includes("..")) return false;
  if (/[^a-z0-9.-]/i.test(domain)) return false;
  const parts = domain.split(".");
  if (parts.length < 2) return false;
  return parts.every((part) => part.length > 0 && part.length <= 63 && !part.startsWith("-") && !part.endsWith("-"));
}

function requireApiKey(req, res, next) {
  if (!API_KEY) return next();
  const provided = req.header("x-api-key") || "";
  if (provided !== API_KEY) {
    return res.status(401).json({ error: "Unauthorized PQC scanner request" });
  }
  next();
}

async function execOpenSSL(args, options = {}) {
  return execFileAsync("openssl", args, {
    timeout: options.timeout || 12000,
    input: options.input || "",
    maxBuffer: options.maxBuffer || 1024 * 1024 * 2,
  });
}

async function checkOpenSSLVersion() {
  try {
    const { stdout } = await execOpenSSL(["version"], { timeout: 5000 });
    return stdout.trim();
  } catch (error) {
    return `OpenSSL unavailable: ${error.message}`;
  }
}

async function listOpenSSLTlsGroups() {
  const attempts = [
    ["list", "-tls-groups"],
    ["list", "-tls1_3", "-groups"],
  ];

  for (const args of attempts) {
    try {
      const { stdout, stderr } = await execOpenSSL(args, { timeout: 7000 });
      const output = `${stdout}\n${stderr}`.trim();
      if (output) return output;
    } catch {
      // Try the next OpenSSL syntax.
    }
  }

  return "";
}

async function checkLocalPqcCapability() {
  const groupsOutput = await listOpenSSLTlsGroups();
  const supports = /X25519MLKEM768|MLKEM768|ML-KEM-768/i.test(groupsOutput);
  return {
    opensslSupportsX25519MLKEM768: supports,
    opensslGroupsEvidence: groupsOutput.slice(0, 3000),
  };
}

async function resolveDomain(domain) {
  try {
    const records = await dns.lookup(domain);
    return { resolved: true, address: records.address, family: records.family };
  } catch (error) {
    return { resolved: false, address: null, family: null, error: error.message };
  }
}

function parseHandshakeSuccess(output) {
  return (
    /CONNECTION ESTABLISHED/i.test(output) ||
    /Protocol version:\s*TLSv1\.3/i.test(output) ||
    /Protocol\s*:\s*TLSv1\.3/i.test(output) ||
    /Ciphersuite:/i.test(output) ||
    /New, TLSv1\.3,/i.test(output)
  );
}

function parseNegotiatedGroup(output) {
  const patterns = [
    /Negotiated TLS1\.3 group:\s*([^\n\r]+)/i,
    /Negotiated group:\s*([^\n\r]+)/i,
    /Server Temp Key:\s*([^\n\r]+)/i,
  ];

  for (const pattern of patterns) {
    const match = output.match(pattern);
    if (match?.[1]) return match[1].trim();
  }

  if (/X25519MLKEM768/i.test(output)) return "X25519MLKEM768";
  if (/MLKEM768|ML-KEM-768/i.test(output)) return "ML-KEM-768";
  return null;
}

async function checkPqcLevel3(domain) {
  const args = [
    "s_client",
    "-connect",
    `${domain}:443`,
    "-servername",
    domain,
    "-tls1_3",
    "-groups",
    "X25519MLKEM768",
    "-brief",
  ];

  try {
    const { stdout, stderr } = await execOpenSSL(args, { timeout: 15000, input: "" });
    const output = `${stdout}\n${stderr}`;
    const handshakeOk = parseHandshakeSuccess(output);
    const negotiatedGroup = parseNegotiatedGroup(output);

    // If the handshake succeeds while the only offered TLS group is X25519MLKEM768,
    // that is useful evidence even if this OpenSSL build does not print the negotiated group.
    const soleGroupSuccess = handshakeOk && !/invalid|unknown group|no suitable key share/i.test(output);
    const pqcLevel3Supported = Boolean(
      handshakeOk && (
        /X25519MLKEM768|MLKEM768|ML-KEM-768/i.test(String(negotiatedGroup || "")) ||
        soleGroupSuccess
      )
    );

    return {
      pqcLevel3Tested: true,
      pqcLevel3Supported,
      pqcGroupOffered: "X25519MLKEM768",
      negotiatedGroup: negotiatedGroup || (soleGroupSuccess ? "X25519MLKEM768 inferred from single offered group" : null),
      pqcAlgorithm: "ML-KEM-768 hybrid with X25519",
      nistSecurityCategory: 3,
      tlsVersionRequired: "TLS 1.3",
      evidenceSummary: pqcLevel3Supported
        ? "TLS 1.3 handshake succeeded while offering X25519MLKEM768 as the client group."
        : "TLS 1.3 handshake did not succeed with X25519MLKEM768 as the offered client group.",
      rawEvidence: output.slice(0, 6000),
      error: null,
    };
  } catch (error) {
    const output = `${error.stdout || ""}\n${error.stderr || ""}`;
    return {
      pqcLevel3Tested: true,
      pqcLevel3Supported: false,
      pqcGroupOffered: "X25519MLKEM768",
      negotiatedGroup: parseNegotiatedGroup(output),
      pqcAlgorithm: "ML-KEM-768 hybrid with X25519",
      nistSecurityCategory: 3,
      tlsVersionRequired: "TLS 1.3",
      evidenceSummary: "TLS 1.3 handshake failed when restricted to X25519MLKEM768.",
      rawEvidence: output.slice(0, 6000),
      error: error.message || "PQC Level 3 handshake failed",
    };
  }
}

function scorePqc(result, localCapability) {
  if (!localCapability.opensslSupportsX25519MLKEM768) {
    return {
      pqcScoreBoost: 0,
      pqcStatus: "Scanner OpenSSL does not expose X25519MLKEM768",
      pqcRisk: "Unknown",
    };
  }

  if (result.pqcLevel3Supported) {
    return {
      pqcScoreBoost: 30,
      pqcStatus: "Real Level 3 PQC detected",
      pqcRisk: "Low",
    };
  }

  return {
    pqcScoreBoost: 0,
    pqcStatus: "Real Level 3 PQC not detected",
    pqcRisk: "High",
  };
}

app.get("/", async (_req, res) => {
  const opensslVersion = await checkOpenSSLVersion();
  const localCapability = await checkLocalPqcCapability();
  res.json({
    service: "QuantumShield Level 3 PQC Scanner",
    status: "ok",
    opensslVersion,
    ...localCapability,
    requiredTlsGroup: "X25519MLKEM768",
    requiredKem: "ML-KEM-768",
    nistSecurityCategory: 3,
    endpoints: ["POST /scan-pqc", "POST /self-test"],
  });
});

app.post("/scan-pqc", requireApiKey, async (req, res) => {
  const domain = cleanDomain(req.body?.domain);

  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: "Enter a valid domain like example.com", domain });
  }

  const dnsResult = await resolveDomain(domain);
  if (!dnsResult.resolved) {
    return res.status(400).json({ error: "Domain could not be resolved", domain, dns: dnsResult });
  }

  const opensslVersion = await checkOpenSSLVersion();
  const localCapability = await checkLocalPqcCapability();
  const pqcResult = await checkPqcLevel3(domain);
  const scoring = scorePqc(pqcResult, localCapability);

  res.json({
    domain,
    scannedAt: new Date().toISOString(),
    opensslVersion,
    ...localCapability,
    dns: dnsResult,
    ...pqcResult,
    ...scoring,
    recommendation: pqcResult.pqcLevel3Supported
      ? "This endpoint negotiated a Level 3 hybrid PQC TLS signal using X25519MLKEM768 / ML-KEM-768. Continue validating other public and internal endpoints."
      : "Level 3 PQC was not negotiated on this public endpoint. Consider enabling TLS 1.3 hybrid ML-KEM-768 through your CDN, reverse proxy, load balancer, or TLS stack.",
  });
});

app.post("/self-test", requireApiKey, async (_req, res) => {
  const domains = ["cloudflare.com", "google.com"];
  const results = [];
  for (const domain of domains) {
    const dnsResult = await resolveDomain(domain);
    if (!dnsResult.resolved) {
      results.push({ domain, error: "DNS failed" });
      continue;
    }
    results.push(await checkPqcLevel3(domain));
  }
  res.json({ results });
});

app.listen(PORT, () => {
  console.log(`QuantumShield PQC scanner listening on port ${PORT}`);
});
