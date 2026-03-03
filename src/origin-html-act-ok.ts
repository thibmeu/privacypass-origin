import { Bindings } from './bindings';

export interface ACTOKParams {
	env: Bindings;
	remainingBalance: bigint;
	hasRefund: boolean;
}

export default (params: ACTOKParams) => `<!DOCTYPE html>
<html>
<head>
<title>ACT Demo | Authenticated</title>
<meta charset="utf-8">
</head>
<body>
<pre>
ACT (Anonymous Credit Tokens) Demo
===================================

Origin:    ${params.env.ORIGIN_NAME}

Status: 200 OK
Result: ACT token verified successfully!

Spend Details:
  - Refund issued:    ${params.hasRefund ? 'Yes' : 'No'}
  - Return credits:   ${params.env.ACT_RETURN_CREDITS}

${
	params.hasRefund
		? `A PrivacyPass-Reverse header is included with your refund.
Process it to update your credential balance.`
		: `No refund was issued for this request.`
}

Next Steps:
  - The refund (if any) is in the PrivacyPass-Reverse response header
  - Process the refund to restore remaining balance
  - Use your updated credential for the next request

Specification:
  - draft-schlesinger-privacypass-act-01
  - draft-meunier-privacypass-reverse-flow-03
</pre>
</body>
</html>
`;
