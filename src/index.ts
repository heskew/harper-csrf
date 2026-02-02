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
import type { Scope } from 'harperdb';

// Configuration type
interface CsrfConfig {
	tokenLength: number;
	headerName: string;
	bodyField: string;
	sessionKey: string;
}

// Configuration (can be overridden via plugin config)
let config: CsrfConfig = {
	tokenLength: 32,
	headerName: 'x-csrf-token',
	bodyField: '_csrf',
	sessionKey: 'csrfToken',
};

/**
 * Expand environment variable in a string value
 *
 * If the value is a string in the format `${VAR_NAME}`, it will be replaced
 * with the value of the environment variable. Non-string values are returned unchanged.
 *
 * @example
 * expandEnvVar('${MY_VAR}') // Returns process.env.MY_VAR or '${MY_VAR}' if undefined
 * expandEnvVar('literal')   // Returns 'literal'
 * expandEnvVar(123)         // Returns 123
 */
export function expandEnvVar(value: any): any {
	if (typeof value === 'string' && value.startsWith('${') && value.endsWith('}')) {
		const envVar = value.slice(2, -1);
		const envValue = process.env[envVar];
		return envValue !== undefined ? envValue : value;
	}
	return value;
}

/**
 * Expand environment variables in a config object
 */
function expandConfigEnvVars(options: Record<string, any>): Record<string, any> {
	const expanded: Record<string, any> = {};
	for (const [key, value] of Object.entries(options)) {
		expanded[key] = expandEnvVar(value);
	}
	return expanded;
}

/**
 * Configure the CSRF plugin. Called by Harper when loading the plugin.
 */
export function configure(options: Partial<CsrfConfig>): void {
	const expanded = expandConfigEnvVars(options);
	config = { ...config, ...expanded };
}

/**
 * Harper plugin entry point with runtime config change support
 *
 * This function is called by Harper when the plugin is loaded and provides
 * access to the scope object for watching configuration changes.
 */
export function handleApplication(scope: Scope): void {
	const logger = scope.logger;
	let isInitialized = false;

	/**
	 * Update CSRF configuration from scope options
	 */
	function updateConfiguration(): void {
		const rawOptions = (scope.options.getAll() || {}) as Record<string, any>;
		const options = expandConfigEnvVars(rawOptions);

		// Parse tokenLength if it's a string (from env var)
		if (typeof options.tokenLength === 'string') {
			options.tokenLength = parseInt(options.tokenLength, 10) || 32;
		}

		// Merge with defaults
		config = {
			tokenLength: options.tokenLength ?? 32,
			headerName: options.headerName ?? 'x-csrf-token',
			bodyField: options.bodyField ?? '_csrf',
			sessionKey: options.sessionKey ?? 'csrfToken',
		};

		if (isInitialized) {
			logger?.info?.('CSRF configuration updated:', config);
		} else {
			logger?.info?.('CSRF plugin loaded with config:', config);
			isInitialized = true;
		}
	}

	// Initial configuration
	updateConfiguration();

	// Watch for configuration changes
	scope.options.on('change', () => {
		updateConfiguration();
	});

	// Clean up on scope close
	scope.on('close', () => {
		logger?.info?.('CSRF plugin shutting down');
	});
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
	const headerToken = request.headers?.[config.headerName] as string | undefined;
	if (headerToken && timingSafeEqual(headerToken, sessionToken as string)) {
		return;
	}

	// Check body field
	const bodyToken = body?.[config.bodyField] as string | undefined;
	if (bodyToken && timingSafeEqual(bodyToken, sessionToken as string)) {
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
export function withCsrfProtection<T extends new (..._args: any[]) => any>(BaseClass: T): T {
	return class extends BaseClass {
		async post(...args: any[]): Promise<unknown> {
			const [, data, request] = args;
			validateCsrf(request, data);
			if (super.post) {
				return await super.post(...args);
			}
		}

		async put(...args: any[]): Promise<unknown> {
			const [, data, request] = args;
			validateCsrf(request, data);
			if (super.put) {
				return await super.put(...args);
			}
		}

		async delete(...args: any[]): Promise<unknown> {
			const [, , request] = args;
			validateCsrf(request);
			if (super.delete) {
				return await super.delete(...args);
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

	get(_target: string, request: any): { token: string } {
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
