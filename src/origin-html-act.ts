import { Bindings } from './bindings';

export default (env: Bindings) => `<!DOCTYPE html>
<html>
<head>
<title>ACT Demo | Challenge</title>
<meta charset="utf-8">
</head>
<body>
<pre>
ACT (Anonymous Credit Tokens) Demo
===================================

Origin:    ${env.ORIGIN_NAME}
Issuer:    ${env.ISSUER_URL}
L:         ${env.ACT_L} (max balance: ${Math.pow(2, parseInt(env.ACT_L)) - 1})

Status: 401 Unauthorized
Reason: No valid ACT token presented

This response includes a WWW-Authenticate header with an ACT challenge.

To authenticate:
1. Obtain an ACT credential from the issuer
2. Create a spend proof for this challenge
3. Include the token in Authorization header:

   curl -H "Authorization: PrivateToken token=..." \\
        https://${env.ORIGIN_NAME}/act-login

Specification:
  - draft-schlesinger-privacypass-act-01
  - draft-meunier-privacypass-reverse-flow-03
</pre>
</body>
</html>
`;
