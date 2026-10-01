# VaultRAG Frontend

A clean, responsive, single-page application built with React, Vite, and TypeScript for the VaultRAG multi-tenant enterprise knowledge base.

## Security & Token Storage Trade-off

<!-- Token Storage Architecture & Trade-off:
VaultRAG enforces strict token storage rules to mitigate client-side vulnerabilities:
1. ID Token (Short-lived JWT):
   - Held strictly IN-MEMORY in React state.
   - Never written to localStorage, sessionStorage, or indexedDB.
   - Trade-off: Mitigates persistent Cross-Site Scripting (XSS) credential theft because
     an attacker with storage access cannot extract the bearer token. However, a hard
     browser refresh clears the in-memory token, requiring a silent background refresh
     using the refresh token.

2. Refresh Token (Longer-lived):
   - Stored in `sessionStorage` (NEVER `localStorage`).
   - Trade-off: Unlike `localStorage` (which persists across browser restarts and all tabs
     on the origin indefinitely), `sessionStorage` is strictly scoped to the active browser tab
     and is automatically purged when the user closes the tab/window. This provides a strong
     balance: users don't have to re-enter credentials on page reloads within the same session,
     while preventing cross-tab token contamination and persistent storage harvesting.
-->

### Key Security Guardrails
- **No `localStorage`**: Tokens are never stored in `localStorage`.
- **No `dangerouslySetInnerHTML` / `eval`**: All server responses, document snippets, and answers are rendered as sanitized plain text.
- **Credential Safety**: Passwords, ID tokens, and extracted document texts are never logged to `console.log`.
- **Client-Side File Validation**: Enforces extension allowlist (`.pdf`, `.docx`, `.txt`, `.md`) and 10 MB maximum file size before network upload.
- **Clean Lifecycle**: Document polling automatically halts on component unmount and when terminal states (`READY`, `FAILED`, `QUARANTINED`) are reached.
- **Route Protection**: Unauthenticated routes redirect to `/login`.

## Development

```bash
# Install dependencies
npm ci

# Start local dev server
npm run dev

# Run linting
npm run lint

# Run unit and integration tests
npm run test -- --run

# Build production bundle
npm run build
```
