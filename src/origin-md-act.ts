import { Bindings } from './bindings';

export default (env: Bindings) => `# ACT Demo | Challenge

**Status:** 401 Unauthorized

Origin: \`${env.ORIGIN_NAME}\`
Issuer: \`${env.ISSUER_URL}\`
L: ${env.ACT_L} (max balance: ${Math.pow(2, parseInt(env.ACT_L)) - 1})

No valid ACT token presented. This response includes a \`WWW-Authenticate\` header with an ACT challenge.

## Option 1: OpenCode Plugin (automatic)

If you're using [OpenCode](https://opencode.ai), install the ACT plugin:

1. Clone: \`git clone https://github.com/thibmeu/act-ts\`
2. The plugin is at \`.opencode/plugins/act-privacy-pass.ts\`
3. Enroll a credential: \`act login ${env.ISSUER_URL}\`
4. OpenCode will automatically authenticate ACT-protected requests

Plugin: [github.com/thibmeu/act-ts/.opencode/plugins](https://github.com/thibmeu/act-ts/tree/main/.opencode/plugins)

## Option 2: act CLI (manual)

1. Install: \`cargo install --git https://github.com/thibmeu/act-rs\`
2. Enroll: \`act login ${env.ISSUER_URL}\`
3. Request: \`act redeem https://${env.ORIGIN_NAME}/act-login\`

CLI: [github.com/thibmeu/act-rs](https://github.com/thibmeu/act-rs)

## Specifications

- [draft-schlesinger-privacypass-act](https://datatracker.ietf.org/doc/draft-schlesinger-privacypass-act/)
- [draft-meunier-privacypass-reverse-flow](https://datatracker.ietf.org/doc/draft-meunier-privacypass-reverse-flow/)
`;
