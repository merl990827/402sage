# Verisage.xyz

[![Docker Reproducibility](https://github.com/ptrus/verisage.xyz/actions/workflows/reproducibility-docker.yml/badge.svg)](https://github.com/ptrus/verisage.xyz/actions/workflows/reproducibility-docker.yml)
[![ROFL Reproducibility](https://github.com/ptrus/verisage.xyz/actions/workflows/reproducibility-rofl.yml/badge.svg)](https://github.com/ptrus/verisage.xyz/actions/workflows/reproducibility-rofl.yml)

**Verifiable Multi-LLM Oracle for Truth Verification**

Verisage answers objective yes/no questions by querying multiple independent AI providers (Claude, Gemini, Perplexity, OpenAI) and aggregating their responses with weighted voting. Designed as a trustless resolution mechanism for protocols requiring factual verification - an AI-powered alternative to human-based dispute systems like UMA.

Built for deployment on [Oasis ROFL](https://docs.oasis.io/rofl/), the service will provide cryptographic attestation that proves the exact code executing in the TEE.

> **Note:** While Verisage provides verifiable execution and consensus across multiple AI models, the underlying LLMs are not perfect and can still make mistakes or produce incorrect answers. Always verify critical information from authoritative sources.

**Live deployment:**
- Demo UI: https://verisage.xyz
- API for agents: [https://api.verisage.xyz](https://api.verisage.xyz/docs)
- ROFL app: [rofl1qr...v9dcs3](https://explorer.oasis.io/mainnet/sapphire/rofl/app/rofl1qrcuhqzvpr2zpjvyk4vl7t4awwemuw67wsv9dcs3) on Oasis Sapphire
- x402 server: [x402scan.com](https://www.x402scan.com/server/4cc06c47-2f7c-477b-a242-d77e2aa34f91)

---

## Key Features

**Multi-Provider Consensus**
- Concurrent queries to 4+ LLM providers with grounding/web-search enabled
- Real-time data access: all providers query up-to-date information from the web
- Weighted voting with configurable thresholds
- Full transparency: individual responses, reasoning, confidence scores

**x402 Micropayments**
- Pay-per-query via browser UI or via API directly
- Can be used by other AI agents for factual checks and verification

**Verifiable & Auditable**
- Complete source code open and auditable
- Reproducible Docker builds ensure deployed code matches repository
- ROFL attestation provides cryptographic proof of execution integrity
- Cryptographic signatures on all responses using TEE-generated SECP256K1 keys
- Public key verification against on-chain attested state

---

## Why ROFL

Protocols using oracles for resolution (like prediction markets, insurance, derivatives) need trustless verification. ROFL provides this:

- **Remote attestation** – cryptographically proves the exact Docker image running in the TEE
- **Verifiable execution** – anyone can confirm the exact code running matches this repository
- **Tamper-proof execution** – operators cannot modify code or manipulate results

---

## How Can I Trust This Service?

Verisage is designed for complete verifiability. You don't need to trust the operators - you can verify everything yourself:

### 1. Audit the Source Code

The entire codebase is open source and auditable. Key trust properties you can verify:

- **No caching, you get what you pay for** - Every request queries all configured AI models in real-time. Check `src/workers/oracle_worker.py` to verify no response caching exists and no shortcuts are taken.
- **Transparent scoring** - The weighted voting logic in `src/scoring.py` is fully visible and auditable.
- **No hidden logic** - All LLM provider clients in `src/llm_clients/` show exactly what prompts are sent and how responses are processed.

### 2. Verify the Docker Image

Verisage uses reproducible builds. You can verify the deployed Docker image matches this exact source code:

```bash
# Build and verify the image matches the deployed digest
make verify-compose-image
```

This builds the image locally with reproducible settings and compares it against the deployed image digest in `compose.yaml`. If the SHA256 digests match, it proves the deployed code hasn't been modified.

**Alternative:** Check the [![Docker Reproducibility](https://github.com/ptrus/verisage.xyz/actions/workflows/reproducibility-docker.yml/badge.svg)](https://github.com/ptrus/verisage.xyz/actions/workflows/reproducibility-docker.yml) CI job which performs these exact verification steps automatically.

### 3. Verify the ROFL Enclave

The ultimate verification: confirm the code running inside the TEE matches this repository.

```bash
# Build the entire ROFL app locally and verify measurements
oasis rofl build --verify --deployment mainnet
```

This verifies that the enclave identity (code measurements) match across:
- Your local build from source
- The deployment manifest
- The on-chain attested state

**Alternative:** Check the [![ROFL Reproducibility](https://github.com/ptrus/verisage.xyz/actions/workflows/reproducibility-rofl.yml/badge.svg)](https://github.com/ptrus/verisage.xyz/actions/workflows/reproducibility-rofl.yml) CI job which performs these exact verification steps automatically.

### 4. Ongoing Attestation

The Oasis Network continuously verifies that the running code matches the on-chain attestation:

- ROFL apps must periodically prove they're running the correct code
- The network automatically rejects apps that fail attestation
- All attestations are publicly verifiable on-chain

Learn more about continuous attestation at the [ROFL Registry](https://github.com/ptrus/rofl-registry).

### Trust Model Summary

**You don't need to trust:**
- The service operators
- That the correct code is running
- That responses haven't been manipulated
- That the service queries all providers as claimed

**You only need to trust:**
- The Oasis Network's TEE attestation mechanism
- The open source code you've audited
- The cryptographic primitives (ECDSA signatures, SGX/TDX attestation)

Everything else is verifiable.

---

## Using the API

**Browser UI:**
- Visit https://verisage.xyz to use the web interface
- Pay with crypto wallet via x402 micropayments
- Submit yes/no questions and get verified answers

**API for Agents:**

```bash
# Get payment requirements
curl https://api.verisage.xyz/api/v1/query

# Submit query with x402 payment (requires x402 client)
# See https://x402.org for client libraries

# Example using Python x402 client:
from x402.client import HTTPClient

client = HTTPClient()
response = client.post(
    "https://api.verisage.xyz/api/v1/query",
    json={"query": "Did Bitcoin reach $100k in 2024?"}
)
job_id = response.json()["job_id"]

# Poll for results
result = client.get(f"https://api.verisage.xyz/api/v1/query/{job_id}")
```

**API Documentation:**
- Full API docs: https://api.verisage.xyz/docs
- Recent resolved queries: https://api.verisage.xyz/api/v1/recent

---

## Running Locally

```bash
# Configure
cp .env.example .env
# Add API keys or set DEBUG_MOCK=true

# Start
docker compose up --build

# Access
open http://localhost:8000
```

**Testing:**
```bash
# Basic E2E (mock providers, no payments)
bash tests/e2e/test-e2e.sh

# Payment E2E (mock providers, real x402 payments on Base Sepolia)
bash tests/e2e/test-e2e-payments.sh
```

---

## Development

**Prerequisites:**
- Python 3.11+ with [uv](https://docs.astral.sh/uv/) package manager
- Node.js 20+ for frontend development
- Docker for container builds

**Setup:**
```bash
# Install Python dependencies
uv sync

# Install frontend dependencies
cd frontend-src && npm install
```

**Development:**
```bash
make dev-frontend   # Start frontend dev server
make dev-backend    # Start backend with docker compose
```

**Linting and Formatting:**
```bash
make lint           # Check code style
make format         # Format code
```

**Build Container:**
```bash
make build-docker
```

**Add LLM Provider:** Create client in `src/llm_clients/`, inherit from `BaseLLMClient`
**Modify Scoring:** Edit `src/scoring.py` weighted voting logic

---

## Links

- **Live Service:** https://verisage.xyz
- **Oasis ROFL:** https://docs.oasis.io/rofl/
- **x402 Protocol:** https://x402.org

---

Built for trustless AI verification on Oasis Network.
