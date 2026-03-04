import { Bindings } from './bindings';

export default (env: Bindings) => `<!DOCTYPE html>
<html>
<head>
<title>ACT Demo | Challenge</title>
<meta charset="utf-8">
<style>
body { font-family: monospace; background: #1a1a2e; color: #eee; padding: 2rem; line-height: 1.6; }
pre { white-space: pre-wrap; }
a { color: #6cf; }
.status { color: #f66; }
.header { color: #6f6; font-size: 1.2em; }
.section { color: #fc6; margin-top: 1.5em; }
code { background: #333; padding: 2px 6px; border-radius: 3px; }
</style>
</head>
<body>
<pre>
<span class="header">ACT (Anonymous Credit Tokens) Demo</span>
═══════════════════════════════════════════════════════════════════

Origin:    ${env.ORIGIN_NAME}
Issuer:    ${env.ISSUER_URL}
L:         ${env.ACT_L} (max balance: ${Math.pow(2, parseInt(env.ACT_L)) - 1})

Status:    <span class="status">401 Unauthorized</span>
Reason:    No valid ACT token presented

This response includes a WWW-Authenticate header with an ACT challenge.

<span class="section">═══ Option 1: OpenCode Plugin (automatic) ═══</span>

If you're using <a href="https://opencode.ai">OpenCode</a>, install the ACT plugin:

  1. Clone: git clone https://github.com/thibmeu/act-ts
  2. The plugin is at .opencode/plugins/act-privacy-pass.ts
  3. Enroll a credential:
     <code>act login ${env.ISSUER_URL}</code>
  4. OpenCode will automatically authenticate ACT-protected requests

Plugin: <a href="https://github.com/thibmeu/act-ts/tree/main/.opencode/plugins">github.com/thibmeu/act-ts/.opencode/plugins</a>

<span class="section">═══ Option 2: act CLI (manual) ═══</span>

  1. Install: <code>cargo install --git https://github.com/thibmeu/act-rs</code>
  2. Enroll:  <code>act login ${env.ISSUER_URL}</code>
  3. Request: <code>act redeem https://${env.ORIGIN_NAME}/act-login</code>

CLI: <a href="https://github.com/thibmeu/act-rs">github.com/thibmeu/act-rs</a>

<span class="section">═══ Specifications ═══</span>

  • <a href="https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/">draft-schlesinger-privacypass-act</a>
  • <a href="https://datatracker.ietf.org/doc/draft-meunier-privacypass-reverse-flow/">draft-meunier-privacypass-reverse-flow</a>
</pre>
</body>
</html>
`;
