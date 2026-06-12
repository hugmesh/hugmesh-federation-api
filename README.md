# snapdragon-federation-api

The platform's **dynamic-federation registry / DB / manifest API** — the
authoritative catalog of federated remote modules and the runtime contract the
Angular host shells bootstrap from. A reactive Spring Boot (WebFlux + R2DBC)
backend service that:

- hosts the `federation_modules` registry (the canonical list of remote shells,
  fragments and optional services that make up a brand's UI);
- serves the **runtime manifest** the Angular host bootstrap feeds into
  native-federation's `initFederation(...)`, so new remotes appear **without
  redeploying** the host shell;
- exposes a **public capabilities projection** a logged-out host reads to
  grey-out optional services that are absent / disabled;
- resolves **vanity subdomains** (`<username>.<domain>`) to a user's public
  profile fragment;
- stores per-user content-hash-versioned module **bundles** for the
  `snapdragon-remote-fragment` pods to *sync-and-serve-static*;
- owns the platform-wide **moderation + kill-switch** surface; and
- gates a **username availability / confusable** check the registration mint
  paths consult.

It is built by reusing two proven references — the snapdragon.games DB-backed
federation engine and the productionised snapdragon-admin-bff-api conventions —
not by inventing new patterns.

## Where it sits in the architecture

| | |
|---|---|
| **Tier** | Backend BFF / platform service (reactive Spring Boot, behind the gateway). |
| **Namespace** | `systems.snapdragon.federation` (artifact `federation`, image built by GitLab CI). |
| **Issuer / auth** | Casdoor JWT OAuth2 **resource server**. Tokens arrive already validated by the gateway; this service re-validates the JWT and maps Casdoor claims → Spring authorities with the **canonical converter copied verbatim from `snapdragon-gateway`** (so authorities are byte-identical across the platform). |
| **Tenancy** | Multi-brand / multi-tenant. The brand a token belongs to is keyed on the **cryptographically-validated issuer** (one Casdoor per brand → distinct `iss`) → a single `DOMAIN_<x>` authority, never a user-settable claim. See *Multi-tenancy (domain scoping)*. |
| **Upstream callers** | the Angular host shells (manifest + capabilities + vanity), the `snapdragon-remote-fragment` sync fleet (bundle fetch), the registration mint paths / actions / user-bff / admin-bff (username check, bundle upload, profile-ban writes), mod-bff / admin-bff (moderation + kill-switch). |
| **Downstream** | PostgreSQL (R2DBC, all runtime reads/writes; JDBC only for Liquibase migrations), an optional best-effort Cassandra manifest cache, and the filesystem/S3 bundle store. |

This service is the **read/write source of truth for "what UI modules exist,
which are serveable, and to whom"** — the rest of the platform (gateway routing,
host bootstrap, the remote-fragment static fleet) is downstream of its manifest.

## Stack

- Spring Boot **3.5.5**, Java **21**, reactive **WebFlux** (no blocking).
- **R2DBC** (r2dbc-postgresql) for ALL runtime reads/writes. JDBC is used **only**
  by Liquibase for schema migrations.
- **Casdoor** JWT OAuth2 resource-server; the authority converter +
  `DomainRegistry` + `Roles` helpers are the canonical gateway code (verbatim).
- **springdoc-openapi-starter-webflux-ui** — spec at `/v3/api-docs`, UI at
  `/swagger-ui.html` (profile-split gating, see *Security*).
- **Resilience4j** circuit breakers on the direct-write profile-ban path.
- **ICU4j** + **commons-text** for the confusable-username skeleton computation.
- **Cassandra-reactive** driver for a best-effort manifest write-through cache
  (disabled by default; degrades gracefully when absent).
- Optional **server-side mTLS** (TLSv1.3, client-cert-required) for API↔API calls.
- GraalVM **native** profile + AOT hints. **GitLab CI** (`.gitlab-ci.yml`); no
  GitHub Actions.

## Endpoints (the public surface)

All paths are under `/api/federation`. Role gates are enforced both in
`SecurityConfig` (path rules, defence-in-depth) and by `@PreAuthorize` on the
controllers. `SUPERADMIN` is the cross-domain infra role and reaches every
privileged surface in every brand.

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/manifest` | GET | authenticated | Runtime manifest: enabled + circuit-closed + visibility-permitted + **domain-scoped** remotes, `{generatedAt, remotes[]}`. Visibility/role/domain filtered **in code**; Cassandra write-through cached (public-safe default view only). |
| `/capabilities` | GET | **public (no JWT)** | **Public install-state projection** — `{slug, installed, mountAt, requiresRole}` per registered module. The list a logged-out / non-admin host reads to grey-out optional services. Narrow + caller-independent (no internal locator/detail). |
| `/vanity/{username}` | GET | **public (no JWT)** | **Vanity-subdomain resolve.** Returns the user's PUBLIC profile-fragment descriptor (`remoteEntryUrl`, `contentHash`, `/_fragments/<slug>/<hash>/` path) iff a `slug=profile-<username>`, `kind=fragment`, `visibility=public`, enabled, circuit-closed, **non-suspended** module exists; else **404**. Never returns internal fragments. |
| `/vanity` (+ `Host:` header) | GET | **public (no JWT)** | Same resolve, but the username is the **first DNS label** of the `Host` header (`alice.<domain>` → `alice`) so the gateway can forward the vanity host verbatim. |
| `/username/{candidate}/availability` | GET | **ROLE_SERVICE / ADMIN (INTERNAL)** | Registration gate: collision / reserved / confusable check. An enumeration oracle (`matchedWith` names the colliding label) — **never public**. |
| `/username/check` | POST | ROLE_SERVICE / ADMIN | Same check by request body. |
| `/username/{candidate}/confusables` | GET | ROLE_ADMIN | Admin debug: the computed skeleton (+ any reserved match), no DB scan. |
| `/modules` | GET/POST | ROLE_ADMIN | Registry CRUD (list / create), domain-scoped. |
| `/modules/{slug}` | GET/PUT/DELETE | ROLE_ADMIN | Registry CRUD (get / update / delete), domain-scoped. |
| `/bundles/{slug}` | PUT | authenticated (owner) | Upload a module bundle (content-hash versioned). |
| `/bundles/{slug}` | DELETE | authenticated (owner) | Delete my bundle. |
| `/bundles/mine` `…/slug/{slug}` `…/{hash}` | GET | authenticated | List bundles by owner / slug / content-hash. |
| `/bundles/slug/{slug}/body` | GET | authenticated (owner) | Read my card body (the entry file) by slug. |
| `/bundles/{hash}/files/{*path}` | GET | authenticated | **FETCH a bundle file by content-hash** — the remote-fragment SYNC read. |
| `/moderation` | GET/POST | ROLE_MOD / ADMIN | Recommend / list moderation requests, domain-scoped. |
| `/moderation/{id}/refer` | POST | ROLE_MOD / ADMIN | Refer a request up to admins. |
| `/moderation/{id}/decide` | POST | ROLE_ADMIN | Approve / deny. |
| `/overrides` | GET/POST | ROLE_ADMIN | Kill-switch: list / apply (`circuit-break` \| `unpublish` \| `remove`), domain-scoped. |
| `/overrides/{slug}/rearm` | POST | ROLE_ADMIN | Recover a circuit-broken module (per-slug). |
| `/overrides/clear` | POST | ROLE_ADMIN | Rearm an active scope override (`{scope,target}`; stamps `cleared_at`). |

## The manifest read path (the keystone)

`ManifestService.render(authorities, scope)` is lifted from the games
`FederationController.manifest()` (`findAllByEnabledTrue → DTO → {generatedAt,
remotes}`) and extended with filters applied per request so the **same DB rows
serve every audience**:

1. **enabled** — DB-side; an `unpublish` override flips `enabled=false`.
2. **circuit-state** — only `circuit_state='closed'` rows ship; a `circuit-break`
   override flips it to `open`, dropping the remote from the manifest **without a
   redeploy** (the kill-switch).
3. **visibility / role** — `public` remotes to everyone; `internal` remotes only
   to `ROLE_ADMIN` / `ROLE_INTERNAL` (and `SUPERADMIN`) callers, against the JWT
   authorities.
4. **domain** — the module + active-scope-override finders are **pinned to the
   caller's `DOMAIN_<x>`** so a brand-X principal's manifest lists only brand-X
   remotes; `SUPERADMIN` runs the un-pinned finders (all brands). See
   *Multi-tenancy*.
5. **active scope overrides** — a `scope=all|user|role` `federation_override`
   that has not been rearmed (`cleared_at IS NULL`) is applied across the whole
   (domain-scoped) catalogue at render time. Loaded once per render and applied in
   code (`isSuppressedByScope`):
   - `scope=all` — global kill: every module drops until rearmed.
   - `scope=user` (target = the owner) — drops modules with `owner_user_id =
     target` (system NULL-owner modules untouched).
   - `scope=role` (target = a role name) — drops modules whose **declared**
     `metadata.requiresRole` (case-insensitive) equals the target role. This is a
     *content-declared* cut, not an owner-holds-role or per-caller-audience cut
     (see *Deferred / stubbed* for the honest limitation).

   Rearm with `POST /overrides/clear` `{scope,target}` (stamps `cleared_at`).
   Per-module-slug overrides mutate `circuit_state` / `enabled` at apply time and
   are dropped by the enabled+circuit DB finder, so they are **not** in the active
   scope set (no regression).

The rendered manifest is best-effort write-through cached — but **only the
public-safe default-domain view** (no internal rows, no superadmin cross-domain
superset, not a brand-specific view) so a cache poller without a token never sees
internal remotes nor another brand's remotes. A cache miss / failure always
renders from Postgres.

## Public capabilities (greying-out optional services)

`GET /api/federation/capabilities` is the **public sibling** of the manifest. The
manifest is `authenticated()` + visibility-filtered, so a logged-out host could
never even learn that an internal-visibility optional service (forum / mastodon /
matrix / games) exists — it cannot drive greying. The capabilities projection is
`permitAll`, lists **every** registry row (via `findAll()`, not just the serveable
ones), and returns a deliberately narrow, public-safe `CapabilityDto`
(`slug + installed + mountAt + requiresRole` only — no `remoteEntryUrl`,
`contentHash`, `ownerUserId`, `visibility` or raw `metadata`).

- `installed=true` ⇔ the row exists AND is enabled AND circuit-closed (serveable
  right now). The host greys a registered-but-disabled / circuit-broken service
  out **by state**.
- A never-registered optional service is **absent** from the list. The host greys
  it out **by absence**.

GET-only and caller-independent (the same body for everyone), so it is safe with
no JWT. The manifest / override read paths are untouched — this is purely additive.

## Vanity subdomains (`<username>.<domain>`)

A user can serve their PUBLIC profile at `https://<username>.snapdragon.systems`.
The federation API owns the **resolve** step.

```
wildcard DNS *.<domain>  ─►  backend ingress  ─►  fe-gateway
   (Host: alice.<domain>)                          │
   the fe-gateway Host=*.<domain> route is ORDERED AFTER the apex + the reserved
   service hosts (id. api. matrix. mastodon. scale. headscale.), so the reserved
   subdomains are matched first and never captured by the wildcard
                                                    │
                              GET /api/federation/vanity  (Host: alice.<domain>)
                                                    ▼
   federation-api: first DNS label `alice` ─► VanityService.resolve("alice")
       SELECT … WHERE slug='profile-alice' AND kind='fragment'
                   AND visibility='public' AND enabled AND circuit_state='closed'
   ─► VanityProfileDto { remoteEntryUrl, contentHash, /_fragments/profile-alice/<hash>/ }
                                                    ▼
   the vanity host renders that fragment (remote-fragment serves the bytes)
```

**username ↔ fragment association (the chosen convention).** A user's public
profile is ONE `federation_modules` row:

| column | value | why |
|---|---|---|
| `slug` | `profile-<username>` | deterministic from the username → resolve is a single **unique-slug** lookup, no extra mapping table (`slug` is already UNIQUE + indexed). |
| `kind` | `fragment` | served by the remote-fragment sync-and-serve-static fleet, exactly like every other fragment bundle. |
| `owner_user_id` | `<username>` | the `scope=user` kill-switch / access-suspension ban keys on this field (NOT the Casdoor sub), so it covers a user's vanity profile + manifest modules with **no new wiring**. |
| `visibility` | `public` | **the gate** — only `public` fragments are resolvable at a vanity host. |

**Why it's safe to expose without a JWT.** The vanity endpoint is `permitAll`
because it IS the public profile — anonymous browsers hit it. The finder filters
`visibility='public'` + `enabled` + `circuit_state='closed'` **in the query**, and
`VanityService` re-asserts the public-fragment invariant **in code**. An internal /
disabled / kill-switched / suspended / missing fragment yields an empty `Mono` →
the controller maps it to **404**. There is no path through this endpoint to an
internal row, and it is GET-only so it can never mutate.

**Username extraction.** `GET /vanity/{username}` takes it explicitly; `GET
/vanity` extracts the FIRST DNS LABEL of the `Host` header (`firstLabel`: strips
`:port`, lower-cases, requires ≥3 labels so the apex returns no username). The
controller also refuses reserved first-labels (`id api matrix mastodon scale
headscale www`) defensively — the gateway route order already prevents those.

## Account-states profile-ban (read/write path)

The platform's access-suspension foundation (admin-bff / mod-bff) bans a USER's
public profile through this service — via the **read** path (vanity / manifest)
and a direct **write** path on `OverrideService`:

- **`OverrideService.applyUserScope(ownerUsername, action, setBy, source)`** writes
  a `scope='user'` `federation_override` row **directly via the repository** — no
  module lookup, **no existing-module requirement**. The durable row exists
  regardless of whether the user ever published, drops every owned module from the
  manifest render, and blocks the vanity read. Tagged `reason='access_suspension:<id>'`.
- **`VanityService.resolve()`** also consults
  `findByScopeAndTargetAndClearedAtIsNull('user', owner)` on the resolved
  fragment's `owner_user_id` and returns empty → **404 even for a public + enabled
  + circuit-closed fragment** when the owner is suspended. Identity is pinned on
  **`owner_user_id`**, NOT the Casdoor sub.
- **`ManifestCache.invalidate()`** is called on every `scope=user` mutation so a
  just-banned profile is never served from a stale cached manifest.
- **`OverrideService.clearScopeBySource(source)`** (lifting/expiring a suspension)
  stamps `cleared_at` on **only** the rows whose `reason` equals that source — so
  an expiring suspension never rearms an unrelated manual `scope=user` kill (which
  carries a NULL / different `reason`).
- Both direct-repo writes are wrapped in `@CircuitBreaker(name="federationOverride")`
  (fail-fast): the durable row is the source of truth, so the read path converges
  once it lands.

Scope of the profile ban: **unpublish / vanity-suppress only** — there is no
`ROLE_USER` self-publish endpoint today (`ModuleRegistryController` is ADMIN-only),
so the ban suppresses the existing/future profile rather than gating a create path.
The homeserver (akkoma/tuwunel) and the access-suspension table + reconcile loop
live in their own repos (generator / admin-bff / mod-bff).

## Username availability + confusable check (INTERNAL)

`/api/federation/username/**` is the registry-owned **look-alike gate** the
registration mint paths (Casdoor pre-signup webhook, OAuth handle mint, actions /
user-bff / admin-bff) call before granting a username. Every response is an
**enumeration oracle** (`matchedWith` names the colliding username / reserved
label), so the whole controller is gated to an internal service credential
(`ROLE_SERVICE`, or `ROLE_ADMIN`) — never the SPA / public surface.

- Collision is checked three ways: exact DB match, a reserved label (the
  `017`/`021` reserved-profile-slug CHECK + the reserved-username list), and a
  **confusable** match against the `username_skeleton` cache (an ICU4j-computed
  look-alike skeleton; changeset `020`). The skeleton is a *recomputable*
  NON-unique index, NOT a unique identity — the `slug` UNIQUE + `017` reserved
  CHECK stay the real exact-username backstop.
- `self` excludes the caller's OWN existing username by **exact** username only (a
  different-but-confusable owner stays flagged).
- `override=confusable` (ROLE_ADMIN only) flips an `exact`/`confusable` verdict to
  available and writes an AUDIT line; it NEVER overrides `reserved` or a hard
  reject.

## Multi-tenancy (domain scoping)

> Status: **on `feat/domain-foundation`** (changeset `026` + the `DomainScope`
> service-layer cut). The capability/vanity public projections and the
> owner==JWT-subject bundle paths are untouched by it. Documented here because it
> is the platform's multi-brand contract and the intended shape of `main`.

The platform is multi-brand / multi-tenant: one Casdoor per brand, so the token's
cryptographically-validated **issuer** (`iss`) is the trustworthy tenant
discriminator. Domain scoping is the canonical, adversarially-verified gateway
code copied verbatim (package-adjusted) into this BFF so it derives a token's
brand **the exact same way the gateway does**:

- **`CasdoorAuthorities`** (single converter shared by the single-issuer and the
  multi-issuer decoder paths) emits: `ROLE_USER` floor + `roles → ROLE_<UPPER>` +
  `permissions` verbatim **EXCEPT** any entry starting with a reserved prefix
  (`ROLE_` / `DOMAIN_`) is **dropped** (authority-injection defense — a brand-X
  token carrying `permissions:["DOMAIN_brandy"]` or `permissions:["ROLE_SUPERADMIN"]`
  can never forge a tenant scope / super-role) + legacy `isAdmin → ROLE_ADMIN` +
  **exactly one** `DOMAIN_<x>` derived from the validated issuer via
  `DomainRegistry`.
- **`DomainRegistry`** maps `iss → domain` from
  `spring.security.oauth2.resourceserver.jwt.issuer-uri` (single-issuer →
  `DOMAIN_default`) and the optional `app.tenancy.issuers` CSV (`iss=domain,…`).
  Multi-brand mode is **fail-closed**: an issuer not in the map yields `null` and
  the multi-issuer decoder (`TenancyResourceServerConfig`, config-gated on a real
  `=`-bearing CSV) 401s an unknown `iss` before any authority is emitted.
- **`DomainScope`** is the per-request domain predicate threaded into the
  services. `SUPERADMIN` → no predicate (cross-domain, sees/mutates all). A normal
  principal → pinned to their issuer-derived domain. An unresolvable issuer →
  `NO_DOMAIN` sentinel that **matches no row** (fail-closed, never silently
  cross-domain).
- **`Roles`** helpers (`isSuperadmin` / `isImageBuilder` / `domainOf`,
  fail-closed) drive the least-privilege cascade
  **SUPERADMIN → ADMIN → MOD → USER** plus the orthogonal `ROLE_IMAGE_BUILDER`
  capability (mesh-workload image builds — a separate grant, not an admin default).
- Changeset **`026`** adds a NOT-NULL `domain` column (DEFAULT `'default'`) +
  domain index to the three tenant-owned tables (`federation_modules`,
  `federation_override`, `moderation_requests`). A row's domain is stamped from the
  **principal's domain at write time** (never a body value, never patchable); the
  domain-pinned finders enforce the cut in the QUERY. `user_modules` /
  `username_skeleton` / vanity fragments are owner-scoped (keyed on
  `owner_user_id`, already a per-domain namespace) and unchanged.

**Backward-compatible.** With only a single issuer and no `app.tenancy.issuers`,
every token mints `DOMAIN_default`, every pre-existing/seed row defaults to
`domain='default'`, and behaviour is byte-for-byte unchanged.

## Schema (Liquibase — `src/main/resources/db/changelog`)

- **`010` `federation_modules`** — the registry. Lifted from games
  `db/changelog/018`, extended with `owner_user_id`, `content_hash`, `visibility`,
  `circuit_state`.
- **`011` `user_modules`** — per-user bundle uploads (locator + content_hash +
  manifest_json + visibility + superseded_at). `016` adds `entry_file`.
- **`012` `moderation_requests`** — recommend / refer / decide workflow.
- **`013` `federation_override`** — kill-switch audit; scope triple
  (`all|role|user` + target). `014` adds `cleared_at` (the scope-override active
  lifecycle: ACTIVE while `cleared_at IS NULL`). `019` adds `reason` (the
  access-suspension SOURCE tag so `clearScopeBySource` clears only its own rows).
- **`015`** — vanity profile fragment **seed** (`profile-alice` public +
  `profile-bob` internal), reusing only existing `010` columns.
- **`017` / `021`** — reserved-profile-slug CHECK (a `profile-<reserved>` /
  `profile-forum` fragment is rejected; `021` re-issues `017` as a new changeSet).
- **`018`** — enum/domain CHECK constraints (DB parity for the API-enforced
  kind/visibility/circuit_state/scope/action/status vocabularies).
- **`020` `username_skeleton`** — confusable-skeleton cache (non-unique skeleton
  index + ICU version stamp).
- **`022`–`025`** — register the optional-service modules (phpBB **forum**,
  akkoma **mastodon**, tuwunel **matrix**, **games**) as federation modules
  (`kind='remote-shell'`, idempotent slug-absent seed-guard so install-state can
  appear / grey-out via the manifest + capabilities).
- **`026`** *(feat/domain-foundation)* — multi-tenancy `domain` column + index on
  the three tenant-owned tables (see *Multi-tenancy*).

### A note on the JSON columns (honest constraint)

Spring Data R2DBC ships no JSONB codec, so — exactly as the games engine does —
`metadata` / `manifest_json` are mapped to **String** entity fields. The changelog
uses a `${json.type}` property: **`jsonb` on Postgres**, **`clob` on the H2
slice-test DB** (r2dbc-h2 returns a real `jsonb` column as a `byte[]`, which would
break the String mapping; `clob` reads back as String on both). Likewise
`${str.type}` is `text` on Postgres but `varchar(1024)` on H2 (H2 refuses to
index/UNIQUE a `CLOB`). The same changelog therefore applies on real Postgres and
on the H2 PG-compat test DB. To move `metadata` to true `jsonb` semantics in prod
later, wire a `byte[]`/`Json`→String R2DBC reading converter and
`ALTER COLUMN … TYPE jsonb USING …::jsonb`.

## Security

`SecurityConfig` (`@EnableWebFluxSecurity` + `@EnableReactiveMethodSecurity`):

- Casdoor JWT resource-server; authorities from the **canonical gateway converter**
  (`CasdoorAuthorities` — roles, permissions with the reserved-prefix guard,
  `isAdmin`, the `ROLE_USER` floor, the issuer-keyed `DOMAIN_<x>`), unit-tested.
- Profile split for the springdoc spec/UI: **permitAll** under `dev`/`test` (so
  `gen:fetch` can curl `/v3/api-docs` without a token), **ROLE_ADMIN** in prod.
- Path rules (all declared before the `anyExchange().authenticated()` catch-all):
  vanity + capabilities = **permitAll** (public reads); username = **ROLE_SERVICE
  / ADMIN** (internal oracle); modules + overrides = **ROLE_ADMIN**; moderation =
  **ROLE_MOD / ADMIN** (decide narrowed to ADMIN); manifest + bundles =
  **authenticated** (bundle owner = JWT subject, enforced in the service).
  `SUPERADMIN` is added to the privileged gates.
- **API↔API mTLS (server side).** Disabled by default (`server.ssl.enabled=false`,
  `client-auth=none`) so local/dev/CI run plaintext. In-cluster, the deployment
  mounts the PKCS12 keystore (Vault-PKI identity) + truststore (cluster CA) and
  sets `SSL_ENABLED=true` / `SSL_CLIENT_AUTH=need`, so the TLS handshake **requires
  a client cert chaining to the cluster CA** (TLSv1.3 floor). A caller not
  deployed+signed by the Vault/ESO PKI process cannot reach the API at all.
- **Bean Validation** on all write/path inputs (`ValidationPatterns` +
  `ValidationExceptionHandler`) so API-enforced vocabularies match the DB CHECK
  constraints (the `018` enum parity).

## Bundle storage

Pluggable `BundleStorage` (lifted from games `UploadStorage`):
- **`filesystem`** (default) — fully functional; opaque locator
  `file:/…/<slug>/<content-hash>`, zip-slip-safe reads.
- **`s3`** — a documented **stub** that throws 501 (see *Deferred*). Select with
  `app.bundles.storage=s3`.

## Manifest cache

Best-effort Cassandra write-through (`CassandraManifestCache`, lifted from
admin-bff's `CassandraRouteMirror`): lazy/gated `CqlSession`, blocking calls on
`boundedElastic`, every failure swallowed. **Disabled by default**
(`app.manifest-cache.cassandra.enabled=false`) → the `NoopManifestCache` wins and
the read path always renders from Postgres. Cassandra auto-config is excluded so
startup never depends on a reachable cluster.

## Build & test

```bash
./mvnw test          # R2DBC slices over H2-PG-compat + the REAL Liquibase
                     # changelog; filesystem storage in a temp dir; Cassandra
                     # disabled (noop). No external infra required.
./mvnw package       # builds target/federation-0.1.0.jar
./mvnw -Pnative native:compile   # GraalVM binary (needs a GraalVM host)
```

Representative tests:
- `ManifestServiceTest` / `ManifestDomainCutTest` — the keystone: filtering by
  visibility / enabled / circuit-state / scope-override + the per-domain vs
  superadmin cut + cache write-through.
- `CapabilityServiceTest` / `CapabilityEndpointTest` — the public projection.
- `VanityServiceTest` / `VanityControllerTest` — the public profile resolve + the
  suspension 404.
- `UsernameAvailabilityServiceTest` / `UsernameSkeletonServiceTest` — the
  confusable gate.
- `FederationModuleRepositoryTest`, `UserModuleRepositoryTest`,
  `ModerationAndOverrideRepositoryTest`, `DomainScopedRepositoryTest` — R2DBC
  slices over the real changelog (incl. the `026` domain-pinned finders).
- `SecurityConfigConverterTest` / `DomainAuthzEndpointTest` — the Casdoor authority
  mapping (incl. the authority-injection regressions) + HTTP authz per role.
- `FederationApplicationContextTest` — full-context boot with degraded defaults.

## Configuration (env)

| Env | Default | Purpose |
|---|---|---|
| `CASDOOR_ISSUER_URI` | `https://id.snapdragon.systems` | single-issuer JWT issuer |
| `APP_TENANCY_ISSUERS` | (empty) | multi-brand `iss=domain,…` CSV (gates the multi-issuer decoder) |
| `SPRING_R2DBC_URL` / `_USERNAME` / `_PASSWORD` | …`/federation` | runtime DB |
| `SPRING_LIQUIBASE_URL` / `_USER` / `_PASSWORD` | …`/federation` | migration DB |
| `APP_BUNDLES_STORAGE` | `filesystem` | `filesystem` \| `s3` |
| `APP_BUNDLES_DIR` | `/var/snapdragon/federation/bundles` | filesystem root |
| `MANIFEST_CACHE_ENABLED` | `false` | enable the Cassandra cache |
| `SSL_ENABLED` / `SSL_CLIENT_AUTH` | `false` / `none` | API↔API mTLS (in-cluster: `true` / `need`) |
| `SSL_KEY_STORE` / `SSL_TRUST_STORE` (+ passwords) | `/stores/…p12` | PKCS12 identity + cluster-CA truststore |
| `SPRING_PROFILES_ACTIVE` | (prod) | `dev` / `test` open the spec |

## Deferred / stubbed (honest)

Intentionally NOT implemented in the scaffold:

- **Full upload pipeline.** `BundleService.put` stages + content-hashes + installs
  a **single** entry file. The games-style multi-file **zip** pipeline (zip-slip
  validation, `manifest.json` schema check, `register.sql` execution) is not
  ported. Port from games `GameUploadService` when needed.
- **S3 / MinIO storage** (`S3BundleStorage`) is a stub that throws 501. The
  production-proven reference is games `S3UploadStorage`. The `filesystem`
  strategy is fully functional today.
- **Auto-applying an approved `moderation_request` as a `federation_override`.**
  Kept as two auditable steps (decide, then apply); wire
  `ModerationService.decide(approve)` → `OverrideService.apply` when the policy is
  finalised.
- **`scope=role` is a *content-declared* cut.** It suppresses modules whose
  declared `metadata.requiresRole` equals the target role. There is **no module
  role column** and **no user→role table** in this service (roles live only in the
  Casdoor JWT), so "drop modules **owned by users who hold** role R" is not
  expressible here (add a `federation_modules.owner_role` column or a Casdoor
  user-roles lookup later). An **audience** cut (filter by the *caller's* roles) is
  rejected because the cached manifest stores a single public-safe view that
  per-caller filtering would poison. Consequence: a module with no `requiresRole`
  is unaffected by a `scope=role` kill.
- **Per-brand manifest cache key.** Only the canonical public-safe default-domain
  view is cached; a brand-specific / superadmin cross-domain render always reads
  Postgres. A per-domain cache key is a later enhancement.
- **Cassandra cache schema bootstrap.** The cache assumes
  `<keyspace>.federation_manifest (id text PRIMARY KEY, body text, updated_at timestamp)`
  exists (created by the cluster init CQL); the service does not create it.
- **Vanity PUBLISH path (cross-service).** The vanity *resolve* (this repo) is
  complete and gates on `visibility='public'`. What is **not** wired is the step
  that *creates/marks* a user's `slug=profile-<username>`, `kind=fragment`,
  `visibility=public` module when the user opts in:
  - `snapdragon-user-bff-api` `ProfileService.save` persists
    `user_profile.visibility` + `vanity_subdomain_enabled` but makes **no**
    federation call — flipping those flags does **not** register/publish a fragment.
  - `FederationApiClient` (user-bff-api) can already `PUT /bundles/{slug}` (a
    `user_modules` bundle row), but a `user_modules` bundle row is **not** a
    `federation_modules` registry row; registering one is `ROLE_ADMIN`-gated.

  **The missing link:** on `ProfileService.save` when `visibility='public' &&
  vanitySubdomainEnabled`, (1) publish the fragment bytes, then (2) **upsert the
  `federation_modules` row** (`slug=profile-<username>`, `kind=fragment`,
  `owner_user_id=<username>`, `visibility=public`, `content_hash`). Recommended:
  add an **owner-scoped self-publish-profile** endpoint to federation (e.g. owner-
  gated `PUT /vanity/{username}`) that upserts the module from the caller's own
  bundle — keeps the admin registry CRUD admin-only. Symmetrically flip to
  `visibility='internal'` / `enabled=false` when the user disables vanity.
- **Vanity SERVING.** The resolved `VanityProfileDto.fragmentPath`
  (`/_fragments/profile-<username>/<contentHash>/`) is served by the existing
  `snapdragon-remote-fragment` fleet (its sidecar polls `GET /manifest`, filters
  `kind=='fragment'`, mirrors the bytes; nginx serves them; the fe-gateway routes
  `/_fragments/**`). **Gap:** remote-fragment only syncs fragments that appear in
  the manifest, and the manifest only emits `federation_modules` rows — so a
  profile fragment is synced/served only once the publish path above creates its
  registry row. The vanity HOST page is a `snapdragon.systems` front-end concern,
  out of scope here.
- **Gateway `PUBLIC_PATHS` allowlist (cross-service).** The shared gateway image
  ends every chain with `anyExchange().authenticated()` and opens a hardcoded
  `PUBLIC_PATHS` allowlist. `/api/federation/vanity/**` (and `/capabilities`) must
  be added there so the fe-gateway does not 401 the anonymous public read before it
  reaches federation — a one-line change in the `snapdragon-gateway` repo.

## Conventions mirrored

- **Engine** = `snapdragon.games/backend`: `federation_modules`
  (`db/changelog/018`), `FederationController` (reactive `findAllByEnabledTrue →
  DTO`), `UploadStorage` (pluggable filesystem|S3, opaque locator) +
  `AssetController` reactive serving + content-hash versioning + `game_access`
  scope (`all|role|user`).
- **Conventions** = `snapdragon-admin-bff-api`: reactive WebFlux security
  (profile-split filter chains), R2DBC + JDBC-only-for-Liquibase, `CassandraRouteMirror`
  best-effort mirror, springdoc, native hints, Dockerfile, `.gitlab-ci.yml`,
  H2-PG-compat slice tests over the real changelog.
- **Auth / tenancy** = `snapdragon-gateway`: the `CasdoorAuthorities` converter,
  `DomainRegistry`, `Roles` helpers and `TenancyResourceServerConfig` are the
  canonical gateway code, copied verbatim so authorities + domain derivation are
  byte-identical across the platform.
</content>
</invoke>
