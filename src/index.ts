import {
	AuthorizationHeader,
	Extension,
	Extensions,
	IssuerConfig,
	PRIVATE_TOKEN_ISSUER_DIRECTORY,
	TOKEN_TYPES,
	WWWAuthenticateHeader,
	publicVerif,
	util,
} from '@cloudflare/privacypass-ts';
const { BlindRSAMode, Origin } = publicVerif;
import { b64ToB64URL, b64Tou8, b64URLtoB64, u8ToB64 } from './base64.js';

import { Bindings } from './bindings.js';

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

	const clientRequestKeyEnc = b64Tou8(b64URLtoB64(token['token-key']));

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
	let tokenKey: CryptoKey, clientRequestKeyEnc: Uint8Array;
	try {
		[tokenKey, clientRequestKeyEnc] = await issuerKeys(env);
	} catch (err) {
		return new Response('Failure to decode token verification key. ' + err, { status: 404 });
	}

	const fixedRedemptionContext = new Uint8Array(32);
	fixedRedemptionContext.fill(0xfe);
	const issuerName = new URL(env.ISSUER_URL).host;

	// we are using privacy pass extension to communicate the public metadata we expect the client to use
	// In this case, the price
	const PRICE_EXTENSION_TYPE = 0x401d;
	const extensions = new Extensions([new Extension(PRICE_EXTENSION_TYPE, new Uint8Array([100]))]);
	const origin = new Origin(BlindRSAMode.PSS, [env.ORIGIN_NAME]);
	const challenge = origin.createTokenChallenge(issuerName, fixedRedemptionContext);

	const wwwauth = new WWWAuthenticateHeader(challenge, clientRequestKeyEnc /* no-max-age */);

	// If the request is for the /login resource, check to see if the request
	// has the WWW-Authenticate header carrying a token.
	const authenticator = request.headers.get('Authorization') ?? '';
	if (authenticator.startsWith('PrivateToken token=')) {
		const token = AuthorizationHeader.parse(tokenType, authenticator)[0].token;
		const valid = await origin.verify(token, tokenKey);
		if (valid) {
			return new Response('You got through. Here is a croissant 🥐', {
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

	return new Response('Please authenticate', {
		headers: {
			'content-type': 'text/html;charset=UTF-8',
			'WWW-Authenticate': wwwauth.toString(),
			'PrivacyPass-Extensions': b64ToB64URL(u8ToB64(extensions.serialize())),
		},
		status: 403,
	});
}

/**
 * Handle a request to the demo Privacy Pass redemption server.
 * @param {Request} request
 */
async function handleRequest(request: Request, env: Bindings) {
	return handleLogin(request, env);
}
