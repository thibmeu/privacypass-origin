import { Bindings } from './bindings';

export default (env: Bindings) => `# Anonymous Credit Tokens Demo

Privacy-preserving credentials with unlinkable redemptions.

## What is ACT?

ACT is a keyed-verification anonymous credential scheme. Credentials carry an integer balance
that decreases on each use. Redemptions are unlinkable to issuance and to each other.

### Security Properties

| Property | Description |
|----------|-------------|
| **Unlinkability** | Redemptions cannot be linked to issuance or to each other |
| **Balance Privacy** | Only redemption amount revealed, not total balance |
| **One-show** | Cryptographic nullifiers prevent double-spending |
| **Unforgeability** | Cannot redeem more than issued |

## How It Works

Two-phase protocol: **issuance** and **redemption**.

1. **Issuance:** Client blinds a commitment, issuer signs, client unblinds to get credential
2. **Redemption:** Client proves balance ≥ cost via range proof, issuer returns updated credential

## Quick Start

Use [act](https://github.com/thibmeu/act-rs) to manage credentials:

\`\`\`bash
# Install act
cargo install --git https://github.com/thibmeu/act-rs act

# Enroll a credential with 100 credits
act login ${env.ISSUER_URL}

# Make an authenticated request
act redeem https://${env.ORIGIN_NAME}/act-login
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
