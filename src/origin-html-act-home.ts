import { Bindings } from './bindings';

export default (env: Bindings) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Anonymous Credit Tokens Demo</title>
  <style>
* { margin: 0; padding: 0; border: none; }
html { font-size: 62.5%; }
body {
  margin: 0;
  font-family: open sans, HelveticaNeue, Helvetica Neue, Helvetica, Arial, sans-serif;
  font-size: 1.5em;
  font-weight: 400;
  line-height: 1.6;
  color: #222;
}
h1 {
  font-family: Montserrat, helvetica, arial, sans-serif;
  font-size: 5rem;
  font-weight: 700;
  line-height: 5.5rem;
  text-align: center;
  color: black;
}
h2 { font-size: 2.4rem; font-weight: 600; padding-top: 2rem; padding-bottom: 0.5rem; }
h3 { font-size: 1.8rem; font-weight: 600; padding-top: 1.5rem; padding-bottom: 0.3rem; }
p { font-size: 1.6rem; padding-bottom: 1.3rem; }
a { color: #125CCA; }
a:hover { color: #3BA3BB; }
code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 1.4rem; }
pre { background: #f4f4f4; padding: 1.5rem; border-radius: 6px; overflow-x: auto; margin: 1rem 0; }
pre code { background: none; padding: 0; }
header {
  position: relative;
  width: 100%;
  padding: 40px 0 50px;
  background-color: #DDE8EF;
}
header p { text-align: center; font-size: 1.8rem; max-width: 700px; margin: 0 auto; padding-top: 1rem; }
section { position: relative; margin: 20px 0; padding: 0 20px; }
section > * { max-width: 800px; margin-left: auto; margin-right: auto; }
table { width: 100%; margin-top: 1rem; margin-bottom: 1rem; border-collapse: collapse; }
table th, table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
table th { font-weight: 600; background: #f9f9f9; }
.highlight { background: #fff3cd; padding: 1rem; border-radius: 6px; margin-top: 1rem; margin-bottom: 1rem; }
ul, ol { margin-top: 0.5rem; margin-bottom: 1rem; padding-left: 2rem; }
li { margin-bottom: 0.5rem; }
footer { border-top: 1px solid #ccc; padding: 1rem 3rem; margin-top: 3rem; }
.text-muted { font-size: 13px; color: #888; }
  </style>
</head>
<body>
  <header>
    <h1>Anonymous Credit Tokens</h1>
    <p>Privacy-preserving credentials with unlinkable redemptions</p>
  </header>

  <section>
    <h2>What is ACT?</h2>
    <p>
      ACT is a keyed-verification anonymous credential scheme. Credentials carry an integer balance
      that decreases on each use. Redemptions are unlinkable to issuance and to each other.
    </p>
    <div class="highlight">
      <strong>Security Properties:</strong>
      <ul>
        <li><strong>Unlinkability</strong> - Redemptions cannot be linked to issuance or to each other</li>
        <li><strong>Balance Privacy</strong> - Only redemption amount revealed, not total balance</li>
        <li><strong>One-show</strong> - Cryptographic nullifiers prevent double-spending</li>
        <li><strong>Unforgeability</strong> - Cannot redeem more than issued</li>
      </ul>
    </div>

    <h2>How It Works</h2>
    <p>Two-phase protocol: <strong>issuance</strong> and <strong>redemption</strong>.</p>
    <ol>
      <li><strong>Issuance:</strong> Client blinds a commitment, issuer signs, client unblinds to get credential</li>
      <li><strong>Redemption:</strong> Client proves balance ≥ cost via range proof, issuer returns updated credential</li>
    </ol>

    <h2>Quick Start</h2>
    <p>Use <a href="https://github.com/thibmeu/act-rs">act</a> to manage credentials:</p>
    <pre><code># Install act
cargo install --git https://github.com/thibmeu/act-rs act

# Enroll a credential with 100 credits
act login ${env.ISSUER_URL}

# Make an authenticated request
act redeem https://${env.ORIGIN_NAME}/act-login</code></pre>

    <h2>Demo Parameters</h2>
    <table>
      <tr><th>Parameter</th><th>Value</th><th>Description</th></tr>
      <tr><td>L</td><td>${env.ACT_L}</td><td>Credit bit length (max balance: ${
				Math.pow(2, parseInt(env.ACT_L)) - 1
			})</td></tr>
      <tr><td>Spend Amount</td><td>1</td><td>Fixed cost per request</td></tr>
      <tr><td>Issuer</td><td><code>${env.ISSUER_URL}</code></td><td>ACT credential issuer</td></tr>
      <tr><td>Origin</td><td><code>${env.ORIGIN_NAME}</code></td><td>This demo origin</td></tr>
    </table>

    <h2>Endpoints</h2>
    <table>
      <tr><th>Endpoint</th><th>Description</th></tr>
      <tr><td><code>/</code></td><td>This page (HTML or Markdown based on Accept header)</td></tr>
      <tr><td><code>/act-login</code></td><td>ACT-protected endpoint - requires valid token</td></tr>
      <tr><td><code>/debug</code></td><td>Returns request headers as JSON (for troubleshooting)</td></tr>
      <tr><td><a href="${
				env.ISSUER_URL
			}/.well-known/private-token-issuer-directory">Issuer Directory</a></td><td>Issuer public keys and configuration</td></tr>
    </table>

    <h2>Error Responses</h2>
    <table>
      <tr><th>Code</th><th>Meaning</th><th>Action</th></tr>
      <tr><td>401</td><td>No token or invalid signature</td><td>Re-issue credentials</td></tr>
      <tr><td>400</td><td>Malformed token/proof</td><td>Bug in client - check token format</td></tr>
      <tr><td>402</td><td>Insufficient credits</td><td>Re-issue with more credits</td></tr>
    </table>

    <h2>Client Tools</h2>
    <ul>
      <li><a href="https://github.com/thibmeu/act-rs"><strong>act-cli</strong></a> (Rust) - CLI for credential management</li>
      <li><a href="https://github.com/thibmeu/act-ts"><strong>act-ts</strong></a> (TypeScript) - Library for integrations</li>
    </ul>

    <h2>Specifications</h2>
    <h3>ACT Protocol</h3>
    <ul>
      <li><a href="https://www.ietf.org/archive/id/draft-schlesinger-cfrg-act-01.txt">draft-schlesinger-cfrg-act-01</a> - Core protocol</li>
      <li><a href="https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/">draft-schlesinger-privacypass-act</a> - Privacy Pass integration</li>
    </ul>
    <h3>Privacy Pass Foundation</h3>
    <ul>
      <li><a href="https://www.rfc-editor.org/rfc/rfc9576.html">RFC 9576</a> - Privacy Pass Architecture</li>
      <li><a href="https://www.rfc-editor.org/rfc/rfc9577.html">RFC 9577</a> - HTTP Authentication Scheme</li>
      <li><a href="https://www.rfc-editor.org/rfc/rfc9578.html">RFC 9578</a> - Issuance Protocols</li>
    </ul>
    <h3>Extensions</h3>
    <ul>
      <li><a href="https://datatracker.ietf.org/doc/draft-meunier-privacypass-reverse-flow/">draft-meunier-privacypass-reverse-flow</a> - Refund mechanism</li>
    </ul>

    <h2>Contribute</h2>
    <p>
      This is a research demo by <a href="https://research.cloudflare.com">Cloudflare Research</a>.
      Contributions welcome at <a href="https://github.com/thibmeu/act-ts">github.com/thibmeu/act-ts</a>.
    </p>
  </section>

  <footer>
    <p class="text-muted">ACT Demo | Cloudflare Research | <a href="https://github.com/thibmeu/act-ts">Source</a></p>
  </footer>
</body>
</html>
`;
