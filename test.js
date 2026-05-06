function cleanDomain(input) {
  return String(input || "")
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .trim()
    .toLowerCase();
}

function isValidDomain(domain) {
  if (!domain || domain.length > 253) return false;
  if (domain.includes("..")) return false;
  if (/[^a-z0-9.-]/i.test(domain)) return false;
  const parts = domain.split(".");
  if (parts.length < 2) return false;
  return parts.every((part) => part.length > 0 && part.length <= 63 && !part.startsWith("-") && !part.endsWith("-"));
}

const tests = [
  { name: "cleanDomain removes https and path", pass: cleanDomain("https://Example.com/login") === "example.com" },
  { name: "cleanDomain removes http", pass: cleanDomain("http://Bank.com") === "bank.com" },
  { name: "valid domain passes", pass: isValidDomain("cloudflare.com") === true },
  { name: "invalid single label fails", pass: isValidDomain("not-a-domain") === false },
  { name: "double dot domain fails", pass: isValidDomain("bad..domain.com") === false },
  { name: "hyphen at edge fails", pass: isValidDomain("-bad.com") === false && isValidDomain("bad-.com") === false },
];

const failed = tests.filter((test) => !test.pass);
if (failed.length) {
  console.error("Failed tests:", failed);
  process.exit(1);
}
console.log("All tests passed:", tests.map((test) => test.name));
