// Service binding interface for issuer RPC
interface IssuerService extends Fetcher {
	actVerifySpend(opts: {
		keyID: number;
		proofBytes: Uint8Array;
		returnCredits: bigint;
		serviceInfo: { url: string; route: string; service: string };
	}): Promise<{ valid: boolean; refund?: Uint8Array }>;
}

export interface Bindings {
	// variables and secrets
	ENVIRONMENT: string;
	ISSUER_URL: string;
	ORIGIN_NAME: string;

	// ACT configuration
	ACT_DOMAIN_SEPARATOR: string;
	ACT_L: string;
	ACT_INITIAL_CREDITS: string;
	ACT_REQUEST_COST: string;
	ACT_RETURN_CREDITS: string;

	// Service Bindings
	ISSUER: Fetcher;
	ACT_ISSUER: IssuerService;
}
