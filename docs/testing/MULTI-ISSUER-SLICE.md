# Multi-issuer security-slice — the reusable test pattern (federation-api)

This is the **reference pattern** (taken from `hugmesh-gateway`) for proving that a
Spring WebFlux OAuth2 resource server handles **per-brand (multi-issuer)
Casdoor tokens** correctly. The property that matters most: an **unknown issuer
fails CLOSED (401)**, and a token from one brand can **never authenticate as another**.

The slice is **deterministic, with no network and no live Casdoor**. A tiny in-process HTTP server
bound to `127.0.0.1` serves each brand's JWKS + OIDC discovery doc, so
`ReactiveJwtDecoders.fromIssuerLocation(...)` validates real
RSA-signed tokens offline.

---

## What the slice asserts (the three keystones)

| # | Scenario | Expectation | Category |
|---|----------|-------------|----------|
| (a) | A brand-X-issuer JWT | resolves to brand-X's manager → **authenticated**, and `DOMAIN_brandx` is emitted | USER-SITUATIONAL |
| (b) | A token from an issuer **not** in `app.tenancy.issuers` (well-formed, correctly signed, just unlisted) | the per-issuer resolver returns `Mono.empty()` → **401 fail-closed**, never a default-accept | CROSS-USER DENY |
| (c) | A brand-Y JWT presented to the resource server | scoped to brand-Y; can **never** become brand-X (no `DOMAIN_brandx`) | CROSS-USER DENY |

It also covers the cheap fail-closed neighbours: a **tampered signature** and a **garbage
bearer** both 401. And it covers the federation-api-specific **authority-injection** guard:
a brand-X token carrying `permissions:["DOMAIN_brandy","ROLE_SUPERADMIN"]` gains
neither the forged tenant scope nor the super-role (`CasdoorAuthorities` strips
reserved-prefix permissions).

---

## The two reusable seams

### 1. `TestIssuer` — mint issuer-specific JWTs against test JWKs (no network)

`src/test/java/.../testsupport/TestIssuer.java`, copied from the gateway (package
changed) and since extended. Each instance generates a fresh RSA keypair and starts a JDK
`HttpServer` on `127.0.0.1:<random-port>` that serves the OIDC discovery doc and the public
JWK set. It exposes `issuerUri()`, `mint(subject, roleNames)` and
`mintWithClaims(subject, claims)`, plus the negative-test minters
`mintWithExpiry(subject, claims, expirySeconds)`, `mintExpired(subject, roleNames)` and
`mintRevoked(subject, roleNames)`. A token minted by issuer A is cryptographically
valid **only** against issuer A's manager, which is exactly the cross-brand isolation of (c).
It is `AutoCloseable`; stop it in `@AfterEach`.

Its only dependency is `nimbus-jose-jwt`, already transitive via
`spring-boot-starter-oauth2-resource-server`.

### 2. `SecuritySliceSupport` — build the REAL `SecurityWebFilterChain` into a `WebTestClient`

`src/test/java/.../config/SecuritySliceSupport.java`. It constructs this repo's real
`SecurityConfig(domainRegistry, tenantAuthManagerResolver, false, 600_000L)` (the last
two arguments are the MFA flag, off, and its freshness window in ms) and calls its **prod**
`filterChain(ServerHttpSecurity.http())`. It wraps the chain in a `WebFilterChainProxy` and
installs it as a `webFilter` on `WebTestClient.bindToController(...)`. There is **no full Spring
Boot context**: the production `authorizeExchange` policy and OAuth2 resource-server
wiring run as deployed, in a fast slice.

Helpers: `sliceClient(registry, resolverProvider, controllers...)` (builds the client),
`provider(resolver)` (the multi-issuer swap) and `absent()` (single-issuer
`o.jwt(...)` path).

> **federation-api note.** This repo's `SecurityConfig` splits the chain into a
> `@Profile("dev","test") devFilterChain` (spec paths permitAll) and a
> `@Profile("!dev & !test") filterChain` (PROD: spec paths ADMIN/SUPERADMIN). Every
> route the slice exercises is shared, so the slice drives the stricter PROD chain.

---

## Scope of the lightweight slice vs. method security

The slice builds **only** the `SecurityWebFilterChain` (the coarse `authorizeExchange`
path gate + the JWT decoder). It does **not** activate
`@EnableReactiveMethodSecurity`'s `@PreAuthorize` gates, which need the AOP proxy from
a real application context.

So the tests split in two:

- **`MultiIssuerSecuritySliceTest`** + **`SecurityConfigPathGateSliceTest`**: the
  lightweight slice (no context). Path-gate rules, multi-issuer decoder, fail-closed.
- **`AdminModulePathGateSliceTest`**: the same lightweight slice pointed at
  `/api/federation/admin/modules/**`. Its load-bearing assertion is the gate's
  **narrowness**. Unlike the sibling `/api/federation/modules/**` rule
  (`hasAnyRole ADMIN,SUPERADMIN`), this one is `hasRole SUPERADMIN` ONLY, so a
  per-brand ADMIN is 403 on every verb (nothing sits above SUPERADMIN in the
  hierarchy, so ADMIN cannot satisfy it transitively). The `@PreAuthorize` +
  service-guard half is proven with the context up in `AdminModuleEndpointTest`.
- **`ModerationDecideEscalationTest`**: a `@SpringBootTest` (mirrors the existing
  `DomainAuthzEndpointTest`) for the `POST /{id}/decide` **escalation boundary**. A MOD
  passes the coarse `/api/federation/moderation/**` path gate (`hasAnyRole MOD/ADMIN/
  SUPERADMIN`), but `@PreAuthorize("hasAnyRole('ADMIN','SUPERADMIN')")` then **DENIES**
  it (403), while ADMIN / SUPERADMIN reach the controller (200). The MOD-vs-decide gap
  is method security, not a path rule, so only a test with the context up can prove it.

---

## Why fail-closed is the load-bearing assertion

The per-issuer resolver's allowlist is exactly `DomainRegistry.trustedIssuers()`. An
`iss` outside that set yields **no** authentication manager, so the
`JwtIssuerReactiveAuthenticationManagerResolver` surfaces a 401 **before any authority
is emitted**. No fallback "default" manager exists that could accept an unlisted
brand. Scenario (b) is the regression guard that keeps it so. It is also the
end-to-end proof that `PrincipalDomain.resolve(...)` is **never reached** for an
untrusted issuer: the request dies at the decoder.
