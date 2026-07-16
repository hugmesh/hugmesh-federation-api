# Multi-issuer security-slice — the reusable test pattern (federation-api)

This is the **reference pattern** (replicated from `snapdragon-gateway`) for proving a
Spring WebFlux OAuth2 resource server correctly handles **per-brand (multi-issuer)
Casdoor tokens**, with the security property that matters most: an **unknown issuer
fails CLOSED (401)** and a token from one brand can **never authenticate as another**.

The whole point is **determinism with no network and no live Casdoor**: each brand's
JWKS + OIDC discovery doc is served by a tiny in-process HTTP server bound to
`127.0.0.1`, so `ReactiveJwtDecoders.fromIssuerLocation(...)` validates real
RSA-signed tokens offline.

---

## What the slice asserts (the three keystones)

| # | Scenario | Expectation | Category |
|---|----------|-------------|----------|
| (a) | A brand-X-issuer JWT | resolves to brand-X's manager → **authenticated**, and `DOMAIN_brandx` is emitted | USER-SITUATIONAL |
| (b) | A token from an issuer **not** in `app.tenancy.issuers` (well-formed, correctly signed, just unlisted) | the per-issuer resolver returns `Mono.empty()` → **401 fail-closed**, never a default-accept | CROSS-USER DENY |
| (c) | A brand-Y JWT presented to the resource server | scoped to brand-Y; can **never** become brand-X (no `DOMAIN_brandx`) | CROSS-USER DENY |

Plus the cheap fail-closed neighbours: a **tampered signature** and a **garbage
bearer** both 401, and the federation-api-specific **authority-injection** guard —
a brand-X token carrying `permissions:["DOMAIN_brandy","ROLE_SUPERADMIN"]` gains
neither the forged tenant scope nor the super-role (`CasdoorAuthorities` strips
reserved-prefix permissions).

---

## The two reusable seams

### 1. `TestIssuer` — mint issuer-specific JWTs against test JWKs (no network)

`src/test/java/.../testsupport/TestIssuer.java`, copied **verbatim** (package only)
from the gateway. Each instance generates a fresh RSA keypair, starts a JDK
`HttpServer` on `127.0.0.1:<random-port>` serving the OIDC discovery doc + the public
JWK set, and exposes `issuerUri()` / `mint(subject, roleNames)` /
`mintWithClaims(subject, claims)`. A token minted by issuer A is cryptographically
valid **only** against issuer A's manager — exactly the cross-brand isolation (c).
`AutoCloseable`; stop it in `@AfterEach`.

Only dependency: `nimbus-jose-jwt`, already transitive via
`spring-boot-starter-oauth2-resource-server`.

### 2. `SecuritySliceSupport` — build the REAL `SecurityWebFilterChain` into a `WebTestClient`

`src/test/java/.../config/SecuritySliceSupport.java`. It constructs this repo's real
`SecurityConfig(domainRegistry, tenantAuthManagerResolver)` and calls its **prod**
`filterChain(ServerHttpSecurity.http())`, wraps it in a `WebFilterChainProxy`, and
installs it as a `webFilter` on `WebTestClient.bindToController(...)`. **No full Spring
Boot context** — the production `authorizeExchange` policy and OAuth2 resource-server
wiring run exactly as deployed, but the test is a fast slice.

Helpers: `provider(resolver)` (the multi-issuer swap) / `absent()` (single-issuer
`o.jwt(...)` path).

> **federation-api note.** This repo's `SecurityConfig` splits the chain into a
> `@Profile("dev","test") devFilterChain` (spec paths permitAll) and a
> `@Profile("!dev & !test") filterChain` (PROD — spec paths ADMIN/SUPERADMIN). Every
> route the slice exercises is shared, so the slice drives the stricter PROD chain.

---

## Scope of the lightweight slice vs. method security

The slice builds **only** the `SecurityWebFilterChain` (the coarse `authorizeExchange`
path gate + the JWT decoder). It does **not** activate
`@EnableReactiveMethodSecurity`'s `@PreAuthorize` gates — those need the AOP proxy from
a real application context.

So the tests are split:

- **`MultiIssuerSecuritySliceTest`** + **`SecurityConfigPathGateSliceTest`** — the
  lightweight slice (no context). Path-gate rules + multi-issuer decoder + fail-closed.
- **`ModerationDecideEscalationTest`** — a `@SpringBootTest` (mirrors the existing
  `DomainAuthzEndpointTest`) for the `POST /{id}/decide` **escalation boundary**: a MOD
  passes the coarse `/api/federation/moderation/**` path gate (`hasAnyRole MOD/ADMIN/
  SUPERADMIN`) but `@PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")` then **DENIES**
  it (403), while ADMIN / SUPERADMIN reach the controller (200). That MOD-vs-decide gap
  is method security, not a path rule, so it can only be proven with the context up.

---

## Why fail-closed is the load-bearing assertion

The per-issuer resolver's allowlist is exactly `DomainRegistry.trustedIssuers()`. An
`iss` outside that set yields **no** authentication manager, so the
`JwtIssuerReactiveAuthenticationManagerResolver` surfaces a 401 **before any authority
is emitted** — there is no fallback "default" manager that could accept an unlisted
brand. Scenario (b) is the regression guard that keeps it that way, and it is the
end-to-end proof that `PrincipalDomain.resolve(...)` is **never reached** for an
untrusted issuer (the request dies at the decoder).
