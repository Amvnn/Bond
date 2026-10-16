# Deployment

**Status:** placeholder. Written alongside `infra/` (sequence step 5 onward).

## Development

Docker Compose: PostgreSQL, Redis, backend, optional Caddy reverse proxy.
Neither PostgreSQL nor Redis is published to the host beyond what local development needs.

## Production

| Requirement | Note |
|---|---|
| HTTPS with real certificates | TLS 1.2 minimum, prefer 1.3. Certificate verification never disabled. |
| WSS for WebSocket | No plaintext WebSocket in production. |
| HSTS | Where appropriate for the deployment. |
| Secrets via environment | Never in source, never in git. See `.env.example`. |
| PostgreSQL and Redis private | **Must not be reachable from the public internet.** |
| Database backups | Encrypted; they contain ciphertext and metadata. |
| Least-privilege service accounts | Backend DB user holds only the grants it needs. |
| Firewall | Only the proxy's ports exposed. |
| Centralised security logs | Subject to the redaction rules in security-model.md. |
| Monitoring | Metrics must never require message plaintext. |

## Observability

Active WebSocket connections, queue depth, delivery latency, authentication failures,
rate-limit events, database and Redis health, API latency, error rate.
