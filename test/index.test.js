import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import {
	configure,
	getCsrfToken,
	validateCsrf,
	withCsrfProtection,
	getConfig,
	CSRF_CONFIG,
	handleApplication,
	expandEnvVar,
	CsrfToken,
} from '../dist/index.js';

// Reset config before each test to ensure isolation
beforeEach(() => {
	configure({
		tokenLength: 32,
		headerName: 'x-csrf-token',
		bodyField: '_csrf',
		sessionKey: 'csrfToken',
	});
});

describe('CSRF Protection', () => {
	describe('configure', () => {
		it('should update configuration', () => {
			configure({ tokenLength: 64 });
			const config = getConfig();
			assert.equal(config.tokenLength, 64);
		});

		it('should preserve unmodified config values', () => {
			configure({ headerName: 'x-custom-token' });
			const config = getConfig();
			assert.equal(config.headerName, 'x-custom-token');
			assert.equal(config.bodyField, '_csrf');
		});
	});

	describe('getCsrfToken', () => {
		it('should throw if no session', () => {
			const request = {};
			assert.throws(() => getCsrfToken(request), {
				message: 'Session required for CSRF protection',
			});
		});

		it('should generate a new token if none exists', () => {
			const request = { session: {} };
			const token = getCsrfToken(request);

			assert.ok(token);
			assert.equal(typeof token, 'string');
			assert.equal(token.length, 64); // 32 bytes = 64 hex chars
		});

		it('should return existing token from session', () => {
			const request = { session: { csrfToken: 'existing-token' } };
			const token = getCsrfToken(request);

			assert.equal(token, 'existing-token');
		});

		it('should store generated token in session', () => {
			const request = { session: {} };
			const token = getCsrfToken(request);

			assert.equal(request.session.csrfToken, token);
		});
	});

	describe('CsrfToken resource', () => {
		it('should return token object from get method', () => {
			const instance = new CsrfToken();
			const request = { session: {} };

			const result = instance.get('target', request);

			assert.ok(result.token);
			assert.equal(typeof result.token, 'string');
			assert.equal(result.token.length, 64);
		});

		it('should return existing session token', () => {
			const instance = new CsrfToken();
			const request = { session: { csrfToken: 'existing-token' } };

			const result = instance.get('target', request);

			assert.deepEqual(result, { token: 'existing-token' });
		});

		it('should have loadAsInstance set to false', () => {
			assert.equal(CsrfToken.loadAsInstance, false);
		});
	});

	describe('validateCsrf', () => {
		it('should throw 403 if no session', () => {
			const request = {};
			try {
				validateCsrf(request);
				assert.fail('Should have thrown');
			} catch (error) {
				assert.equal(error.message, 'Session required for CSRF protection');
				assert.equal(error.statusCode, 403);
			}
		});

		it('should throw 403 if no token in session', () => {
			const request = { session: {} };
			try {
				validateCsrf(request);
				assert.fail('Should have thrown');
			} catch (error) {
				assert.equal(error.message, 'CSRF token not found in session');
				assert.equal(error.statusCode, 403);
			}
		});

		it('should validate token from header', () => {
			const request = {
				session: { csrfToken: 'valid-token' },
				headers: { 'x-csrf-token': 'valid-token' },
			};

			assert.doesNotThrow(() => validateCsrf(request));
		});

		it('should validate token from body', () => {
			const request = {
				session: { csrfToken: 'valid-token' },
				headers: {},
			};
			const body = { _csrf: 'valid-token', data: 'test' };

			assert.doesNotThrow(() => validateCsrf(request, body));
		});

		it('should remove token from body after validation', () => {
			const request = {
				session: { csrfToken: 'valid-token' },
				headers: {},
			};
			const body = { _csrf: 'valid-token', data: 'test' };

			validateCsrf(request, body);

			assert.equal(body._csrf, undefined);
			assert.equal(body.data, 'test');
		});

		it('should throw 403 for invalid token', () => {
			const request = {
				session: { csrfToken: 'valid-token' },
				headers: { 'x-csrf-token': 'invalid-token' },
			};

			try {
				validateCsrf(request);
				assert.fail('Should have thrown');
			} catch (error) {
				assert.equal(error.message, 'Invalid CSRF token');
				assert.equal(error.statusCode, 403);
			}
		});

		it('should prefer header over body', () => {
			const request = {
				session: { csrfToken: 'valid-token' },
				headers: { 'x-csrf-token': 'valid-token' },
			};
			const body = { _csrf: 'different-token' };

			// Should pass because header is valid
			assert.doesNotThrow(() => validateCsrf(request, body));
			// Body token should remain (not used)
			assert.equal(body._csrf, 'different-token');
		});
	});

	describe('withCsrfProtection decorator', () => {
		it('should wrap a class and validate CSRF on post', async () => {
			class TestResource {
				async post(_target, data) {
					return { received: data };
				}
			}

			const ProtectedResource = withCsrfProtection(TestResource);
			const instance = new ProtectedResource();

			const request = {
				session: { csrfToken: 'test-token' },
				headers: { 'x-csrf-token': 'test-token' },
			};

			const result = await instance.post('target', { foo: 'bar' }, request);
			assert.deepEqual(result, { received: { foo: 'bar' } });
		});

		it('should throw on post without valid CSRF', async () => {
			class TestResource {
				async post() {
					return { success: true };
				}
			}

			const ProtectedResource = withCsrfProtection(TestResource);
			const instance = new ProtectedResource();

			const request = {
				session: { csrfToken: 'test-token' },
				headers: { 'x-csrf-token': 'wrong-token' },
			};

			await assert.rejects(async () => instance.post('target', {}, request), { message: 'Invalid CSRF token' });
		});

		it('should wrap put method', async () => {
			class TestResource {
				async put(_target, data) {
					return { updated: data };
				}
			}

			const ProtectedResource = withCsrfProtection(TestResource);
			const instance = new ProtectedResource();

			const request = {
				session: { csrfToken: 'test-token' },
				headers: { 'x-csrf-token': 'test-token' },
			};

			const result = await instance.put('id', { name: 'test' }, request);
			assert.deepEqual(result, { updated: { name: 'test' } });
		});

		it('should wrap delete method', async () => {
			class TestResource {
				async delete(target) {
					return { deleted: target };
				}
			}

			const ProtectedResource = withCsrfProtection(TestResource);
			const instance = new ProtectedResource();

			const request = {
				session: { csrfToken: 'test-token' },
				headers: { 'x-csrf-token': 'test-token' },
			};

			const result = await instance.delete('id', null, request);
			assert.deepEqual(result, { deleted: 'id' });
		});
	});

	describe('CSRF_CONFIG', () => {
		it('should expose header name', () => {
			assert.equal(CSRF_CONFIG.HEADER_NAME, 'x-csrf-token');
		});

		it('should expose body field', () => {
			assert.equal(CSRF_CONFIG.BODY_FIELD, '_csrf');
		});

		it('should reflect configuration changes', () => {
			configure({ headerName: 'x-custom' });
			assert.equal(CSRF_CONFIG.HEADER_NAME, 'x-custom');
		});
	});

	describe('expandEnvVar', () => {
		it('should expand environment variable syntax', () => {
			process.env.TEST_CSRF_VAR = 'expanded-value';
			const result = expandEnvVar('${TEST_CSRF_VAR}');
			assert.equal(result, 'expanded-value');
			delete process.env.TEST_CSRF_VAR;
		});

		it('should return original if env var not set', () => {
			delete process.env.NONEXISTENT_VAR;
			const result = expandEnvVar('${NONEXISTENT_VAR}');
			assert.equal(result, '${NONEXISTENT_VAR}');
		});

		it('should return literal strings unchanged', () => {
			assert.equal(expandEnvVar('literal-value'), 'literal-value');
		});

		it('should return non-strings unchanged', () => {
			assert.equal(expandEnvVar(123), 123);
			assert.equal(expandEnvVar(true), true);
			assert.equal(expandEnvVar(null), null);
		});
	});

	describe('handleApplication', () => {
		it('should initialize config from scope options', () => {
			const changeHandlers = [];
			const closeHandlers = [];
			const mockScope = {
				logger: null,
				options: {
					getAll: () => ({ tokenLength: 48, headerName: 'x-custom-csrf' }),
					on: (event, handler) => {
						if (event === 'change') changeHandlers.push(handler);
					},
				},
				on: (event, handler) => {
					if (event === 'close') closeHandlers.push(handler);
				},
			};

			handleApplication(mockScope);

			const config = getConfig();
			assert.equal(config.tokenLength, 48);
			assert.equal(config.headerName, 'x-custom-csrf');
		});

		it('should update config when change event fires', () => {
			const changeHandlers = [];
			let currentOptions = { tokenLength: 32 };
			const mockScope = {
				logger: null,
				options: {
					getAll: () => currentOptions,
					on: (event, handler) => {
						if (event === 'change') changeHandlers.push(handler);
					},
				},
				on: () => {},
			};

			handleApplication(mockScope);
			assert.equal(getConfig().tokenLength, 32);

			// Simulate config change
			currentOptions = { tokenLength: 64 };
			changeHandlers.forEach((handler) => handler());

			assert.equal(getConfig().tokenLength, 64);
		});

		it('should expand env vars in config', () => {
			process.env.TEST_HEADER_NAME = 'x-env-csrf';
			const mockScope = {
				logger: null,
				options: {
					getAll: () => ({ headerName: '${TEST_HEADER_NAME}' }),
					on: () => {},
				},
				on: () => {},
			};

			handleApplication(mockScope);

			assert.equal(getConfig().headerName, 'x-env-csrf');
			delete process.env.TEST_HEADER_NAME;
		});
	});

	describe('config changes affect validation', () => {
		it('should use custom headerName for validation', () => {
			configure({ headerName: 'x-custom-csrf' });

			const request = {
				session: { csrfToken: 'valid-token' },
				headers: { 'x-custom-csrf': 'valid-token' },
			};

			// Should pass with custom header
			assert.doesNotThrow(() => validateCsrf(request));

			// Should fail with default header
			const requestWithDefault = {
				session: { csrfToken: 'valid-token' },
				headers: { 'x-csrf-token': 'valid-token' },
			};
			assert.throws(() => validateCsrf(requestWithDefault), { message: 'Invalid CSRF token' });
		});

		it('should use custom bodyField for validation', () => {
			configure({ bodyField: 'csrfToken' });

			const request = {
				session: { csrfToken: 'valid-token' },
				headers: {},
			};
			const body = { csrfToken: 'valid-token' };

			assert.doesNotThrow(() => validateCsrf(request, body));
		});

		it('should use custom sessionKey', () => {
			configure({ sessionKey: 'myToken' });

			const request = { session: { myToken: 'custom-session-token' } };
			const token = getCsrfToken(request);

			assert.equal(token, 'custom-session-token');
		});

		it('should generate tokens with custom length', () => {
			configure({ tokenLength: 16 });

			const request = { session: {} };
			const token = getCsrfToken(request);

			// 16 bytes = 32 hex chars
			assert.equal(token.length, 32);
		});
	});
});
