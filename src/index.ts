import {
	IssuerConfig,
	PRIVATE_TOKEN_ISSUER_DIRECTORY,
	WWWAuthenticateHeader,
	TOKEN_TYPES,
	Token,
	TokenChallenge,
	util,
	act,
} from '@cloudflare/privacypass-ts';
import { base64UrlToUint8Array, verifyToken } from './redemption.js';

import originHTML from './origin-html.js';
import tokenOKHTML from './origin-html-to-remove-token-ok.js';
import actOriginHTML from './origin-html-act.js';
import actTokenOKHTML from './origin-html-act-ok.js';
import { Bindings } from './bindings.js';

const { ACTTokenChallenge, ACTToken, ACT_TOKEN_TYPE, Origin: ACTOrigin, ACT } = act;

export default {
	async fetch(request: Request, env: Bindings) {
		return handleRequest(request, env);
	},
};

function generateFetchIssuerEndpoint(
	env: Bindings
): (input: RequestInfo, info?: RequestInit) => Promise<Response> {
	return (input: RequestInfo, info?: RequestInit) => {
		if (env.ISSUER) {
			return env.ISSUER.fetch(input, info);
		}
		return fetch(input, info);
	};
}

/**
 * Fetch public keys and identifiers from the designated Privacy Pass issuer service.
 * @param {String} issuerURL
 * @returns a list with three ArrayBuffer elements
 */
async function fetchBasicIssuerKeys(env: Bindings, issuerURL: string) {
	// Fetch the issuer configuration
	const init = {
		headers: {
			'content-type': 'application/json',
		},
	};
	const configURL = `${issuerURL}${PRIVATE_TOKEN_ISSUER_DIRECTORY}`;
	const configResponse = await generateFetchIssuerEndpoint(env)(configURL, init);
	const config: IssuerConfig = await configResponse.json();

	// Parse out the token keys (in legacy format too)
	const token = config['token-keys'].find(
		token => token['token-type'] == TOKEN_TYPES.BLIND_RSA.value
	);

	if (!token) {
		throw new Error('Could not find BlindRSA token key on issuer');
	}

	const clientRequestKeyEnc = base64UrlToUint8Array(token['token-key']);

	return clientRequestKeyEnc;
}

async function issuerKeys(env: Bindings): Promise<[CryptoKey, Uint8Array]> {
	// Fetch issuer keys
	const clientRequestKeyEnc = await fetchBasicIssuerKeys(env, env.ISSUER_URL);
	const spkiEnc = util.convertRSASSAPSSToEnc(clientRequestKeyEnc);
	// Import the public key that we'll use for verification
	const tokenKey = await crypto.subtle.importKey(
		'spki',
		spkiEnc,
		{
			name: 'RSA-PSS',
			hash: { name: 'SHA-384' },
		},
		false,
		['verify']
	);

	return [tokenKey, clientRequestKeyEnc];
}

async function handleLogin(request: Request, env: Bindings) {
	const tokenType = TOKEN_TYPES.BLIND_RSA;
	let tokenKey, clientRequestKeyEnc;
	try {
		[tokenKey, clientRequestKeyEnc] = await issuerKeys(env);
	} catch (err) {
		return new Response('Failure to decode token verification key. ' + err, { status: 404 });
	}

	const fixedRedemptionContext = new Uint8Array(32);
	fixedRedemptionContext.fill(0xfe);
	const issuerName = new URL(env.ISSUER_URL).host;
	const challenge = new TokenChallenge(tokenType.value, issuerName, fixedRedemptionContext, [
		env.ORIGIN_NAME,
	]);
	const wwwAuthHeader = new WWWAuthenticateHeader(challenge, clientRequestKeyEnc, 10);

	// If the request is for the /login resource, check to see if the request
	// has the WWW-Authenticate header carrying a token.
	const authenticator = request.headers.get('Authorization') ?? '';
	if (authenticator.startsWith('PrivateToken token=')) {
		const tokenChallenge = challenge.serialize();
		const context = new Uint8Array(await crypto.subtle.digest('SHA-256', tokenChallenge));
		const valid = await verifyToken(authenticator, tokenKey, context);
		if (valid) {
			return new Response(tokenOKHTML(env), {
				headers: {
					'content-type': 'text/html;charset=UTF-8',
				},
				status: 200,
			});
		}
		return new Response('Token verification failed', {
			headers: {
				'content-type': 'text/html;charset=UTF-8',
			},
			status: 400,
		});
	}

	return new Response(originHTML(env), {
		headers: {
			'content-type': 'text/html;charset=UTF-8',
			'WWW-Authenticate': wwwAuthHeader.toString(),
		},
		status: 401,
	});
}

/**
 * Fetch ACT public key from issuer directory
 */
async function fetchACTIssuerKey(env: Bindings): Promise<Uint8Array> {
	const configURL = `${env.ISSUER_URL}${PRIVATE_TOKEN_ISSUER_DIRECTORY}`;
	const configResponse = await generateFetchIssuerEndpoint(env)(configURL, {
		headers: { 'content-type': 'application/json' },
	});
	const config: IssuerConfig = await configResponse.json();

	const actKey = config['token-keys'].find(token => token['token-type'] === ACT_TOKEN_TYPE);
	if (!actKey) {
		throw new Error('Could not find ACT token key on issuer');
	}

	return base64UrlToUint8Array(actKey['token-key']);
}

/**
 * Handle ACT login request
 */
async function handleACTLogin(request: Request, env: Bindings) {
	// Get ACT issuer public key
	let issuerPkBytes: Uint8Array;
	try {
		issuerPkBytes = await fetchACTIssuerKey(env);
	} catch (err) {
		return new Response('Failed to fetch ACT issuer key: ' + err, { status: 500 });
	}

	// Create ACT origin
	const domainSeparator = new TextEncoder().encode(env.ACT_DOMAIN_SEPARATOR);
	const L = parseInt(env.ACT_L);
	const origin = ACTOrigin.create(domainSeparator, L, issuerPkBytes, [env.ORIGIN_NAME]);

	// Create challenge
	const credentialContext = crypto.getRandomValues(new Uint8Array(32));
	const redemptionContext = crypto.getRandomValues(new Uint8Array(32));
	const challenge = origin.createChallenge(credentialContext, redemptionContext);

	// Check for ACT token in Authorization header
	const authenticator = request.headers.get('Authorization') ?? '';
	if (authenticator.startsWith('PrivateToken token=')) {
		try {
			// Parse the token
			const tokenB64 = authenticator.split('=')[1].replace(/"/g, '');
			const tokenBytes = base64UrlToUint8Array(tokenB64);
			const token = ACTToken.deserialize(tokenBytes);

			// Decode token structure (verification requires issuer private key)
			const decoded = origin.decodeToken(token);
			if (!decoded.valid) {
				return new Response('Invalid ACT token: issuer key ID mismatch', { status: 401 });
			}

			// Get truncated key ID from token's issuer_key_id (last byte)
			const keyID = token.issuerKeyId[token.issuerKeyId.length - 1];

			// Forward spend proof to issuer for verification
			const returnCredits = BigInt(env.ACT_RETURN_CREDITS);
			const verifyResult = await env.ACT_ISSUER.actVerifySpend({
				keyID,
				proofBytes: token.spendProof,
				returnCredits,
				serviceInfo: {
					url: env.ISSUER_URL,
					route: '/act-verify-spend',
					service: 'act-issuer',
				},
			});

			if (!verifyResult.valid) {
				return new Response('ACT spend proof verification failed', { status: 401 });
			}

			// Build response headers
			const responseHeaders: Record<string, string> = {
				'Content-Type': 'text/html;charset=UTF-8',
			};

			// Include refund in PrivacyPass-Reverse header (draft-meunier-privacypass-reverse-flow-03 §6)
			if (verifyResult.refund) {
				const refundB64 = uint8ToBase64Url(verifyResult.refund);
				responseHeaders['PrivacyPass-Reverse'] = refundB64;
			}

			return new Response(
				actTokenOKHTML({
					env,
					remainingBalance: 0n, // We don't know actual balance
					hasRefund: !!verifyResult.refund,
				}),
				{
					status: 200,
					headers: responseHeaders,
				}
			);
		} catch (err) {
			return new Response('ACT token processing failed: ' + err, { status: 400 });
		}
	}

	// No token - return challenge
	// Create WWW-Authenticate header for ACT
	// Note: ACT uses a different challenge format than Blind RSA
	const wwwAuth = new WWWAuthenticateHeader(challenge, issuerPkBytes);

	return new Response(actOriginHTML(env), {
		headers: {
			'Content-Type': 'text/html;charset=UTF-8',
			'WWW-Authenticate': wwwAuth.toString(),
		},
		status: 401,
	});
}

// Helper: convert Uint8Array to base64url
function uint8ToBase64Url(bytes: Uint8Array): string {
	const binary = String.fromCharCode(...bytes);
	const base64 = btoa(binary);
	return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Handle a request to the demo Privacy Pass redemption server.
 * @param {Request} request
 */
async function handleRequest(request: Request, env: Bindings) {
	// If the request is for the home page, return the basic interaction form.
	const url = new URL(request.url);

	if (url.pathname.startsWith('/act-login')) {
		return handleACTLogin(request, env);
	}

	if (url.pathname.startsWith('/login')) {
		return handleLogin(request, env);
	}

	return new Response('Unsupported resource', {
		headers: {
			'content-type': 'text/html;charset=UTF-8',
		},
		status: 400,
	});
}
