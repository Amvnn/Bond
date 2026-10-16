# security/

Security artefacts that are not design documents. Design lives in `docs/`.

## Pre-completion checklist

Phase 1 is not done until every box is ticked. Derived from the project brief's
`definition_of_done` and `agent_behavior.after_coding`.

### Functional
- [ ] Two users can register (user #1 via the bootstrap path)
- [ ] Each user can register a device
- [ ] A user can invite another; the invitee can accept
- [ ] Users can verify each other's cryptographic identity out of band
- [ ] An encrypted 1-to-1 session can be established
- [ ] Alice can send Bob an encrypted message; Bob decrypts it locally
- [ ] Bob receives messages sent while he was offline
- [ ] Messages survive WebSocket reconnects
- [ ] Devices can be revoked

### Security
- [ ] Private keys never leave the client (verified, not assumed)
- [ ] Database contains no plaintext messages (verified by inspection)
- [ ] Authentication enforced on every protected endpoint
- [ ] Authorisation enforced server-side from the token subject
- [ ] TLS enforced in production
- [ ] Message tampering detected by the recipient
- [ ] Identity key changes detected and surfaced
- [ ] Invitation tokens high-entropy, hashed at rest, single-use, expiring, revocable
- [ ] Logs reviewed for accidental secrets
- [ ] Security tests pass

### Verification steps
- [ ] Unit tests run
- [ ] Integration tests run
- [ ] Security tests run (injection, authn/authz bypass, IDOR, rate-limit bypass,
      WebSocket auth bypass, invalid ciphertext injection, replay, malformed protocol
      messages, oversized payloads)
- [ ] Static analysis run
- [ ] Dependency audit run (`npm audit`, `dart pub outdated`)
- [ ] Threat-model review against [../docs/threat-model.md](../docs/threat-model.md)
- [ ] Remaining limitations documented

## Dependency posture

- Lock files committed for both `server/` and `client/`.
- pub `libsignal` pinned to an exact version. Upgrading it is a security-relevant change
  requiring review, not a routine bump. See [../docs/crypto-design.md](../docs/crypto-design.md).
