/**
 * Harper CSRF Protection Plugin
 *
 * Provides Cross-Site Request Forgery protection for Harper applications.
 *
 * Features:
 * - Class decorator (@withCsrfProtection) for automatic CSRF validation
 * - CsrfToken resource for clients to obtain tokens
 * - Token validation via header (X-CSRF-Token) or body field (_csrf)
 * - Timing-safe token comparison
 *
 * Usage:
 *
 * 1. Configure in config.yaml:
 *    harper-csrf:
 *      package: 'harper-csrf'
 *      tokenLength: 32        # optional, default 32
 *      headerName: 'x-csrf-token'  # optional
 *      bodyField: '_csrf'     # optional
 *
 * 2. Apply decorator to resources:
 *    import { withCsrfProtection } from 'harper-csrf';
 *
 *    @withCsrfProtection
 *    export class MyResource extends Resource {
 *      async post(target, data, request) {
 *        // CSRF already validated
 *      }
 *    }
 *
 * 3. Export CsrfToken endpoint (or use the default):
 *    import { CsrfToken } from 'harper-csrf';
 *    export { CsrfToken };
 */

import { timingSafeEqual as cryptoTimingSafeEqual } from 'node:crypto';

// Configuration (can be overridden via plugin config)
let config = {
	tokenLength: 32,
	headerName: 'x-csrf-token',
	bodyField: '_csrf',
	sessionKey: 'csrfToken',
};

/**
 * Configure the CSRF plugin. Called by Harper when loading the plugin.
 */
export function configure(options: Partial<typeof config>): void {
	config = { ...config, ...options };
}

/**
 * Generate a cryptographically secure random token
 */
function generateToken(): string {
	const bytes = new Uint8Array(config.tokenLength);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Timing-safe string comparison to prevent timing attacks
 */
function timingSafeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) {
		return false;
	}
	return cryptoTimingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Get or create CSRF token for the current session
 */
export function getCsrfToken(request: any): string {
	if (!request.session) {
		throw new Error('Session required for CSRF protection');
	}

	if (request.session[config.sessionKey]) {
		return request.session[config.sessionKey];
	}

	const token = generateToken();
	request.session[config.sessionKey] = token;
	return token;
}

/**
 * Validate CSRF token from request header or body
 * @throws Error with statusCode 403 if validation fails
 */
export function validateCsrf(request: any, body?: any): void {
	if (!request.session) {
		const error = new Error('Session required for CSRF protection');
		(error as any).statusCode = 403;
		throw error;
	}

	const sessionToken = request.session[config.sessionKey];
	if (!sessionToken) {
		const error = new Error('CSRF token not found in session');
		(error as any).statusCode = 403;
		throw error;
	}

	// Check header first
	const headerToken = request.headers?.[config.headerName];
	if (headerToken && timingSafeEqual(headerToken, sessionToken)) {
		return;
	}

	// Check body field
	const bodyToken = body?.[config.bodyField];
	if (bodyToken && timingSafeEqual(bodyToken, sessionToken)) {
		// Remove the token from body so it doesn't pollute data
		delete body[config.bodyField];
		return;
	}

	const error = new Error('Invalid CSRF token');
	(error as any).statusCode = 403;
	throw error;
}

/**
 * Class decorator that adds CSRF protection to state-changing methods.
 *
 * Automatically validates CSRF tokens on post, put, and delete methods.
 *
 * @example
 * @withCsrfProtection
 * export class MyResource extends Resource {
 *   async post(_target: string, data: any, request: any) {
 *     // CSRF already validated
 *     return { success: true };
 *   }
 * }
 */
export function withCsrfProtection<T extends new (...args: any[]) => any>(BaseClass: T): T {
	return class extends BaseClass {
		async post(...args: any[]) {
			const [_target, data, request] = args;
			validateCsrf(request, data);
			if (super.post) {
				return super.post(...args);
			}
		}

		async put(...args: any[]) {
			const [_target, data, request] = args;
			validateCsrf(request, data);
			if (super.put) {
				return super.put(...args);
			}
		}

		async delete(...args: any[]) {
			const [_target, _data, request] = args;
			validateCsrf(request);
			if (super.delete) {
				return super.delete(...args);
			}
		}
	} as T;
}

// Helper to access global Resource class
function getResourceClass(): any {
	return (globalThis as any).Resource;
}

/**
 * CSRF Token endpoint - clients GET this to retrieve their token
 *
 * Export this from your resources to expose the endpoint:
 *   export { CsrfToken } from 'harper-csrf';
 *
 * Client fetches: GET /CsrfToken
 * Response: { token: "abc123..." }
 */
export class CsrfToken extends getResourceClass() {
	static loadAsInstance = false;

	async get(_target: string, request: any): Promise<{ token: string }> {
		const token = getCsrfToken(request);
		return { token };
	}
}

/**
 * Get current configuration (useful for client-side code)
 */
export function getConfig(): Readonly<typeof config> {
	return { ...config };
}

/**
 * Export configuration constants for clients
 */
export const CSRF_CONFIG = {
	get HEADER_NAME() {
		return config.headerName;
	},
	get BODY_FIELD() {
		return config.bodyField;
	},
} as const;
