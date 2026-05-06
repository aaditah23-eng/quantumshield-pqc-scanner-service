# QuantumShield Level 3 PQC scanner service
# Uses Debian Trixie because it includes a modern OpenSSL branch with PQC TLS group support.
# After deployment, open the service root URL and confirm opensslSupportsX25519MLKEM768=true.

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    openssl \
    ca-certificates \
    nodejs \
    npm \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=8080

EXPOSE 8080

CMD ["npm", "start"]
