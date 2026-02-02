# Claude Instructions for harper-csrf

## Project Overview

A CSRF protection plugin for Harper applications providing:

- `@withCsrfProtection` class decorator for automatic validation
- `CsrfToken` resource for token retrieval
- Timing-safe token comparison

## Key Patterns

### No Harper Runtime Dependencies

The core CSRF logic (token generation, validation) is framework-agnostic. Only the `CsrfToken` resource class uses Harper's global `Resource`.

### Global Resource Access

```typescript
function getResourceClass(): any {
	return (globalThis as any).Resource;
}

export class CsrfToken extends getResourceClass() {
	// ...
}
```

### Decorator Pattern

The `@withCsrfProtection` decorator wraps `post`, `put`, `delete` methods to validate CSRF before calling the original method.

## Project Structure

```
src/
  index.ts        # All exports: decorator, functions, CsrfToken class
dist/             # Compiled output
test/
  index.test.js   # Tests using node:test
```

## Building & Testing

```bash
npm install       # Install dependencies
npm run build     # Compile TypeScript
npm test          # Run tests
npm run lint      # ESLint check
npm run format:check  # Prettier check
```

## Code Style

Uses `@harperdb/code-guidelines` for ESLint and Prettier configuration.

## CI/CD

- `.github/workflows/checks.yml` - Lint, format, test on Node 20/22/24
- `.github/workflows/socket.yml` - Socket.dev supply chain security
