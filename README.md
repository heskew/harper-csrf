# harper-csrf

CSRF protection plugin for Harper applications.

## Installation

```bash
npm install harper-csrf
```

## Configuration

Add to your `config.yaml`:

```yaml
harper-csrf:
  package: 'harper-csrf'
  tokenLength: 32 # Optional, default 32
  headerName: 'x-csrf-token' # Optional
  bodyField: '_csrf' # Optional
```

## Usage

### 1. Protect Resources with Decorator

Apply the `@withCsrfProtection` decorator to any Resource that has state-changing methods:

```typescript
import { withCsrfProtection } from 'harper-csrf';

@withCsrfProtection
export class MyProfile extends Resource {
	static loadAsInstance = false;

	async put(target: string, data: any, request: any) {
		// CSRF is automatically validated before this code runs
		// Update profile...
		return { success: true };
	}
}
```

The decorator automatically validates CSRF tokens on `post`, `put`, and `delete` methods.

### 2. Expose Token Endpoint

Export the `CsrfToken` resource to provide an endpoint for clients:

```typescript
// In your resources.ts
export { CsrfToken } from 'harper-csrf';
```

This creates a `GET /CsrfToken` endpoint.

### 3. Client-Side Usage

Fetch the token and include it in requests:

```javascript
// 1. Get token
const response = await fetch('/CsrfToken/');
const { token } = await response.json();

// 2. Include in requests via header
await fetch('/MyProfile/', {
	method: 'PUT',
	headers: {
		'Content-Type': 'application/json',
		'X-CSRF-Token': token,
	},
	body: JSON.stringify({ name: 'New Name' }),
});

// Or via body field
await fetch('/MyProfile/', {
	method: 'PUT',
	headers: { 'Content-Type': 'application/json' },
	body: JSON.stringify({
		name: 'New Name',
		_csrf: token,
	}),
});
```

## API

### `withCsrfProtection(ResourceClass)`

Class decorator that adds CSRF validation to `post`, `put`, and `delete` methods.

### `getCsrfToken(request)`

Get or create CSRF token for the current session.

### `validateCsrf(request, body?)`

Manually validate CSRF token. Throws 403 error if invalid.

### `CsrfToken`

Resource class that provides `GET` endpoint for retrieving tokens.

### `CSRF_CONFIG`

Object with current configuration:

- `HEADER_NAME`: Header name for token (default: 'x-csrf-token')
- `BODY_FIELD`: Body field name for token (default: '\_csrf')

## Requirements

- Session support (e.g., via `@harperdb/oauth` or custom session middleware)
- Harper 4.7.0+
- Node.js 20+

## License

MIT
