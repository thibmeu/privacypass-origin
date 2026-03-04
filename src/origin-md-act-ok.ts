import { Bindings } from './bindings';

export interface ACTOKParams {
	env: Bindings;
	remainingBalance: bigint;
	hasRefund: boolean;
}

export default (params: ACTOKParams) => `# ACT Demo | Success

\`\`\`
    ___   _____ _____   _____ _    _  _____ _____ ______  _____ _____ 
   / _ \\ / ____|_   _| / ____| |  | |/ ____/ ____|  ____|/ ____/ ____|
  | |_| | |      | |  | (___ | |  | | |   | |    | |__  | (___| (___  
  |  _  | |      | |   \\___ \\| |  | | |   | |    |  __|  \\___ \\\\___ \\ 
  | | | | |____ _| |_  ____) | |__| | |___| |____| |____ ____) |___) |
  |_| |_|\\_____|_____||_____/ \\____/ \\_____\\_____|______|_____/_____/ 
\`\`\`

## Token Verified Successfully

| Field | Value |
|-------|-------|
| Origin | \`${params.env.ORIGIN_NAME}\` |
| Status | **200 OK** |
| Cost | 1 credit |
| Refund issued | ${params.hasRefund ? 'Yes' : 'No'} |
| Return credits | ${params.env.ACT_RETURN_CREDITS} |

${
	params.hasRefund
		? `> **Note:** A \`PrivacyPass-Reverse\` header is included with your refund. Process it with act-cli to update your credential balance.`
		: `No refund was issued for this request.`
}

## Next Steps

1. Check \`PrivacyPass-Reverse\` header for refund credential
2. Process refund: \`act-cli refund --header "<header-value>"\`
3. Use updated credential for next request

## Specifications

- [draft-schlesinger-cfrg-act-01](https://datatracker.ietf.org/doc/draft-schlesinger-cfrg-act/)
- [draft-meunier-privacypass-reverse-flow-03](https://datatracker.ietf.org/doc/draft-meunier-privacypass-reverse-flow/)
`;
