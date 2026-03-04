import { Bindings } from './bindings';

export default (env: Bindings) => `# Anonymous Credit Tokens Demo

Privacy-preserving pre-paid credits with unlinkable spending and cryptographic refunds.

## What is ACT?

ACT (Anonymous Credit Tokens) lets you issue pre-paid credits that users can spend privately.
The issuer learns nothing about which user made a purchase or how purchases relate to each other.

### Security Properties

| Property | Description |
|----------|-------------|
| **Unlinkability** | Spends cannot be linked to issuance or each other |
| **Balance Privacy** | Only spend amount revealed, not total balance |
| **Double-spend Prevention** | Cryptographic nullifiers ensure one-time use |
| **Unforgeability** | Cannot spend more credits than issued |

## How It Works

ACT uses a two-step flow: **issue** and **spend (with change)**.

1. **Issue:** Client requests credits from issuer, receives a credential
2. **Spend:** Client proves balance ≥ cost, receives refund credential for remaining balance

## Quick Start

Use [act-cli](https://github.com/thibmeu/act-rs) to manage credentials:

\`\`\`bash
# Install act-cli
cargo install --git https://github.com/thibmeu/act-rs act-cli

# Issue a credential with 10 credits
act-cli issue --issuer ${env.ISSUER_URL} --credits 10

# Spend 1 credit on a request
act-cli request ${env.ORIGIN_NAME}/act-login
\`\`\`

## Demo Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| L | ${env.ACT_L} | Credit bit length (max balance: ${Math.pow(2, parseInt(env.ACT_L)) - 1}) |
| Spend Amount | 1 | Fixed cost per request |
| Issuer | \`${env.ISSUER_URL}\` | ACT credential issuer |
| Origin | \`${env.ORIGIN_NAME}\` | This demo origin |

## Endpoints

| Endpoint | Description |
|----------|-------------|
| \`/\` | This page (HTML or Markdown based on Accept header) |
| \`/act-login\` | ACT-protected endpoint - requires valid token |
| \`/debug\` | Returns request headers as JSON (for troubleshooting) |
| [Issuer Directory](${env.ISSUER_URL}/.well-known/private-token-issuer-directory) | Issuer public keys and configuration |

## Error Responses

| Code | Meaning | Action |
|------|---------|--------|
| 401 | No token or invalid signature | Re-issue credentials |
| 400 | Malformed token/proof | Bug in client - check token format |
| 402 | Insufficient credits | Re-issue with more credits |

## Client Tools

- **[act-cli](https://github.com/thibmeu/act-rs)** (Rust) - CLI for credential management
- **[act-ts](https://github.com/thibmeu/act-ts)** (TypeScript) - Library for integrations

## Specifications

### ACT Protocol
- [draft-schlesinger-cfrg-act-01](https://www.ietf.org/archive/id/draft-schlesinger-cfrg-act-01.txt) - Core protocol
- [draft-schlesinger-privacypass-act](https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/) - Privacy Pass integration

### Privacy Pass Foundation
- [RFC 9576](https://www.rfc-editor.org/rfc/rfc9576.html) - Privacy Pass Architecture
- [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577.html) - HTTP Authentication Scheme
- [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578.html) - Issuance Protocols

### Extensions
- [draft-meunier-privacypass-reverse-flow](https://datatracker.ietf.org/doc/draft-meunier-privacypass-reverse-flow/) - Refund mechanism

## Contribute

This is a research demo by [Cloudflare Research](https://research.cloudflare.com).
Contributions welcome at [github.com/thibmeu/act-ts](https://github.com/thibmeu/act-ts).
`;
