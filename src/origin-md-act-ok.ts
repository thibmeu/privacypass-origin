import { Bindings } from './bindings';

export interface ACTOKParams {
	env: Bindings;
	remainingBalance: bigint;
	hasRefund: boolean;
}

export default (params: ACTOKParams) => `# ACT Demo | Success

\`\`\`
    _    ____ _____   ____  _   _  ____ ____ _____ ____ ____
   / \\  / ___|_   _| / ___|| | | |/ ___/ ___| ____/ ___/ ___|
  / _ \\| |     | |   \\___ \\| | | | |  | |   |  _| \\___ \\___ \\
 / ___ \\ |___  | |    ___) | |_| | |__| |___| |___ ___) |__) |
/_/   \\_\\____| |_|   |____/ \\___/ \\____\\____|_____|____/____/
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
