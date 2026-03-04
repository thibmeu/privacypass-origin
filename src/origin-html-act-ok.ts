import { Bindings } from './bindings';

export interface ACTOKParams {
	env: Bindings;
	remainingBalance: bigint;
	hasRefund: boolean;
}

const ASCII_ART = `
    ___   _____ _____   _____ _    _  _____ _____ ______  _____ _____ 
   / _ \\ / ____|_   _| / ____| |  | |/ ____/ ____|  ____|/ ____/ ____|
  | |_| | |      | |  | (___ | |  | | |   | |    | |__  | (___| (___  
  |  _  | |      | |   \\___ \\| |  | | |   | |    |  __|  \\___ \\\\___ \\ 
  | | | | |____ _| |_  ____) | |__| | |___| |____| |____ ____) |___) |
  |_| |_|\\_____|_____||_____/ \\____/ \\_____\\_____|______|_____/_____/ 
`;

export default (params: ACTOKParams) => `<!DOCTYPE html>
<html>
<head>
<title>ACT Demo | Success</title>
<meta charset="utf-8">
<style>
body { font-family: monospace; background: #1a1a2e; color: #0f0; padding: 2rem; }
pre { font-size: 12px; line-height: 1.2; }
.banner { color: #0ff; }
.success { color: #0f0; }
.info { color: #fff; }
.highlight { color: #ff0; }
</style>
</head>
<body>
<pre class="banner">${ASCII_ART}</pre>
<pre class="success">
═══════════════════════════════════════════════════════════════════════
                         TOKEN VERIFIED SUCCESSFULLY
═══════════════════════════════════════════════════════════════════════
</pre>
<pre class="info">
Origin:         ${params.env.ORIGIN_NAME}
Status:         <span class="success">200 OK</span>

Spend Details:
  Cost:           1 credit
  Refund issued:  <span class="highlight">${params.hasRefund ? 'Yes' : 'No'}</span>
  Return credits: ${params.env.ACT_RETURN_CREDITS}
${
	params.hasRefund
		? `
<span class="highlight">A PrivacyPass-Reverse header is included with your refund.</span>
Process it with act-cli to update your credential balance.`
		: `
No refund was issued for this request.`
}

Next Steps:
  1. Check PrivacyPass-Reverse header for refund credential
  2. Process refund: act-cli refund --header "&lt;header-value&gt;"
  3. Use updated credential for next request

Specifications:
  - draft-schlesinger-cfrg-act-01
  - draft-meunier-privacypass-reverse-flow-03
</pre>
</body>
</html>
`;
