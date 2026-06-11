# snapdragon-federation-api

The platform **dynamic-federation registry / DB / manifest API** — the Phase-4
keystone. A reactive Spring Boot (WebFlux + R2DBC) service that hosts the
authoritative catalog of federated remote modules, serves the runtime manifest
the Angular host bootstrap feeds into native-federation's `initFederation(...)`,
stores per-user content-hash-versioned module bundles for the
`snapdragon-remote-fragment` pods to **sync-and-serve-static**, and owns the
platform-wide moderation + kill-switch surface.

Built by reusing two proven references — the snapdragon.games DB-backed
federation engine and the productionised snapdragon-admin-bff-api conventions — not
by inventing new patterns.

## Stack

- Spring Boot **3.5.5**, Java **21**, reactive **WebFlux** (no blocking).
- **R2DBC** (r2dbc-postgresql) for ALL runtime reads/writes. JDBC is used **only**
  by Liquibase for schema migrations.
- **Casdoor** JWT OAuth2 resource-server with the verbatim authority converter
  from admin-bff / gateway / actions.
- **springdoc-openapi-starter-webflux-ui** — spec at `/v3/api-docs`, UI at
  `/swagger-ui.html` (profile-split gating, see Security).
- **Cassandra-reactive** driver for a best-effort manifest write-through cache
  (degrades gracefully when absent).
- GraalVM **native** profile + AOT hints. **GitLab CI** (`.gitlab-ci.yml`); no
  GitHub Actions.

## What it does

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/federation/manifest` | GET | authenticated | The runtime manifest: enabled + circuit-closed + visibility-permitted remotes, `{generatedAt, remotes[]}`. Visibility/role filtered **in code** per caller; Cassandra write-through cached. |
| `/api/federation/vanity/{username}` | GET | **public (no JWT)** | **Vanity-subdomain resolve.** Returns the user's PUBLIC profile-fragment descriptor (`remoteEntryUrl`, `contentHash`, `/_fragments/<slug>/<hash>/` path) iff a `slug=profile-<username>`, `kind=fragment`, `visibility=public`, enabled, circuit-closed module exists; else **404**. Never returns internal fragments. |
| `/api/federation/vanity` (+ `Host:` header) | GET | **public (no JWT)** | Same resolve, but the username is the **first DNS label** of the `Host` header (`alice.<domain>` → `alice`) — lets the gateway forward the vanity host verbatim. |
| `/api/federation/modules` | GET/POST | ROLE_ADMIN | Registry CRUD (list / create). |
| `/api/federation/modules/{slug}` | GET/PUT/DELETE | ROLE_ADMIN | Registry CRUD (get / update / delete). |
| `/api/federation/bundles/{slug}` | PUT | authenticated (owner) | Upload a module bundle (content-hash versioned). |
| `/api/federation/bundles/mine` `…/slug/{slug}` `…/{hash}` | GET | authenticated | List bundles by owner / slug / content-hash. |
| `/api/federation/bundles/{hash}/files/{*path}` | GET | authenticated | **FETCH a bundle file by content-hash** — the remote-fragment SYNC read. |
| `/api/federation/moderation` | GET/POST | ROLE_MOD/ADMIN | Recommend / list moderation requests. |
| `/api/federation/moderation/{id}/refer` | POST | ROLE_MOD/ADMIN | Refer a request up to admins. |
| `/api/federation/moderation/{id}/decide` | POST | ROLE_ADMIN | Approve / deny. |
| `/api/federation/overrides` | GET/POST | ROLE_ADMIN | Kill-switch: list / apply (`circuit-break` \| `unpublish` \| `remove`). |
| `/api/federation/overrides/{slug}/rearm` | POST | ROLE_ADMIN | Recover a circuit-broken module (per-slug). |
| `/api/federation/overrides/clear` | POST | ROLE_ADMIN | Rearm an active scope override (`{scope,target}`; stamps `cleared_at`). |

### The manifest read path (the keystone)

Lifted from the games `FederationController.manifest()`
(`findAllByEnabledTrue → DTO → {generatedAt, remotes}`) and extended with three
filters applied per request so the same DB rows serve every audience:

1. **enabled** — DB-side; an `unpublish` override flips `enabled=false`.
2. **circuit-state** — only `circuit_state='closed'` rows ship; a `circuit-break`
   override flips it to `open`, dropping the remote from the manifest **without a
   redeploy** (the kill-switch).
3. **visibility / role** — `public` remotes to everyone; `internal` remotes only
   to `ROLE_ADMIN` / `ROLE_INTERNAL` callers (in `ManifestService`, against the
   JWT authorities).
4. **active scope overrides** — a `scope=all|user|role` `federation_override` that
   has not been rearmed (`cleared_at IS NULL`) is applied across the **whole
   catalogue** at render time (these carry no single module slug to mutate). Loaded
   reactively once per render via `findByScopeInAndClearedAtIsNull(...)` and applied
   in code (`isSuppressedByScope`):
   - `scope=all` — global kill: **every** module drops until rearmed.
   - `scope=user` (target = a Casdoor subject) — drops modules with
     `owner_user_id = target` (system NULL-owner modules untouched).
   - `scope=role` (target = a role name) — drops modules whose **declared**
     `metadata.requiresRole` (case-insensitive) equals the target role. See the
     honest limitation under *Deferred / stubbed* — this is a content-declared cut,
     not an owner-holds-role or per-caller-audience cut.

   Rearm with `POST /api/federation/overrides/clear` `{scope,target}` (stamps
   `cleared_at`; the suppressed modules return on the next render). Per-module-slug
   overrides are unchanged: they mutate `circuit_state` / `enabled` at apply time
   and are dropped by the enabled+circuit DB finder, so they are **not** in the
   active scope set (no regression).

### Vanity subdomains (`<username>.<domain>`)

A user can serve their PUBLIC profile at `https://<username>.snapdragon.systems`.
The federation API owns the **resolve** step.

**The flow (end to end):**

```
wildcard DNS *.<domain>  ─►  backend ingress  ─►  fe-gateway
   (Host: alice.<domain>)                          │
   the fe-gateway has a Host=*.<domain> route, ORDERED AFTER the apex + the
   reserved service hosts (id. api. matrix. mastodon. scale. headscale.), so the
   reserved subdomains are matched first and never captured by the wildcard
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
| `slug` | `profile-<username>` | deterministic from the username → the resolve is a single **unique-slug** lookup, no extra mapping table (the `slug` column is already UNIQUE + indexed). |
| `kind` | `fragment` | served by the remote-fragment sync-and-serve-static fleet, exactly like every other fragment bundle. |
| `owner_user_id` | `<username>` | the `scope=user` kill-switch / access-suspension ban keys on this field (NOT the Casdoor sub), so it covers a user's vanity profile + manifest modules with **no new wiring**. |
| `visibility` | `public` | **the gate** — only `public` fragments are resolvable at a vanity host. |

The resolve keys on the **slug** (single indexed equality, no scan);
`owner_user_id` is set for ownership/kill-switch.

**Why it's safe to expose without a JWT.** The vanity endpoint is `permitAll`
(`GET /api/federation/vanity/**`) because it IS the public profile — anonymous
browsers hit it. The finder
(`findBySlugAndKindAndVisibilityAndEnabledTrueAndCircuitState`) filters
`visibility='public'` + `enabled` + `circuit_state='closed'` **in the query**, and
`VanityService` re-asserts the public-fragment invariant **in code**
(`.filter(isPublicProfileFragment)`). An internal / disabled / kill-switched /
missing fragment therefore yields an empty `Mono` → the controller maps it to
**404**. There is no code path through this endpoint to an internal row, and it is
GET-only so it can never mutate. Fully reactive (`Mono` throughout — no blocking).

**Username extraction.** `GET /api/federation/vanity/{username}` takes it
explicitly; `GET /api/federation/vanity` extracts it from the FIRST DNS LABEL of
the `Host` header (`VanityController.firstLabel`: strips `:port`, lower-cases,
requires ≥3 labels so the apex returns no username). The controller also refuses
reserved first-labels (`id api matrix mastodon scale headscale www`) defensively —
the gateway route order already prevents those from arriving.

### Account-states profile-ban foundation (read/write path)

The platform's access-suspension foundation (admin-bff / mod-bff) bans a USER's
public profile through this service — the **read** path (vanity / manifest) and a
direct **write** path on `OverrideService`:

- **`OverrideService.applyUserScope(ownerUsername, action, setBy, source)`** writes
  a `scope='user'` `federation_override` row **directly via the repository** — no
  module lookup, **no existing-module requirement**. This is the fix for the prior
  404 when a banned user has never published a module: the durable row exists
  regardless, drops every owned module from the manifest render, and blocks the
  vanity read. The row is tagged `reason='access_suspension:<id>'` (the *source*).
- **`VanityService.resolve()`** now also consults
  `FederationOverrideRepository.findByScopeAndTargetAndClearedAtIsNull('user', owner)`
  on the resolved fragment's `owner_user_id` and returns empty → **404 even for a
  public + enabled + circuit-closed fragment** when the owner is suspended.
  Identity is pinned on **`owner_user_id`** (the value the ban writer targets and
  the publisher stores), NOT the Casdoor sub.
- **`ManifestCache.invalidate()`** is called on every `scope=user` mutation so a
  just-banned profile is never served from a stale cached manifest (the durable row
  already removes it from the authoritative Postgres render).
- **`OverrideService.clearScopeBySource(source)`** (the suspension lifting/expiring)
  stamps `cleared_at` on **only** the rows whose `reason` equals that source — so an
  expiring suspension never rearms an unrelated manual `scope=user` kill an admin
  applied separately (which carries a NULL / different `reason`).
- Both direct-repo writes are wrapped in `@CircuitBreaker(name="federationOverride")`
  (fail-fast): the durable row is the source of truth, so the read path converges
  once it lands; the breaker sheds load against a wedged store rather than stalling
  the ban caller.

Scope of the profile ban: **unpublish / vanity-suppress only** — there is no
`ROLE_USER` self-publish endpoint today (`ModuleRegistryController` is ADMIN-only),
so the ban suppresses the existing/future profile rather than gating a create path.
The homeserver (akkoma/tuwunel) and the access-suspension table + reconcile loop
live in their own repos (generator / admin-bff / mod-bff) — this service owns only
the federation profile read/write leg.

**Seed (changeset 015).** `profile-alice` (public) + `profile-bob` (internal) are
seeded so the H2 PG-compat slice test resolves a public profile fragment AND
confirms an internal one 404s, against the REAL applied changelog. They reuse only
existing `010` columns (no schema change). A NULL `content_hash` means "module
registered, bundle not yet synced" — the resolve still returns the descriptor (with
a null `fragmentPath`) so the host can tell that case apart from "served".

## Schema (Liquibase — `src/main/resources/db/changelog`)

- **`federation_modules`** — the registry. Lifted from games `db/changelog/018`,
  extended with `owner_user_id`, `content_hash`, `visibility`, `circuit_state`.
- **`user_modules`** — per-user bundle uploads. Mirror of games `game_uploads`
  (locator + content_hash + manifest_json + visibility + superseded_at).
- **`moderation_requests`** — recommend / refer / decide workflow.
- **`federation_override`** — kill-switch audit; scope triple (`all|role|user` +
  target) mirrors the games `game_access` pattern. `cleared_at` (changeset 014) is
  the scope-override **active lifecycle**: a `scope=all|user|role` row is ACTIVE
  (applied at every manifest render) while `cleared_at IS NULL`, and is rearmed
  when `clearScope` stamps it. Per-module-slug rows keep `cleared_at` NULL but are
  applied via direct module mutation, not the active-set finder.

### A note on the JSON columns (honest constraint)

Spring Data R2DBC ships no JSONB codec, so — exactly as the games engine does —
`metadata` / `manifest_json` are mapped to **String** entity fields. The
changelog uses a `${json.type}` property: **`jsonb` on Postgres**, **`clob` on
the H2 slice-test DB** (r2dbc-h2 returns a real `jsonb` column as a `byte[]`,
which would break the String mapping; `clob` reads back as String on both).
Likewise `${str.type}` is `text` on Postgres but `varchar(1024)` on H2 (H2
refuses to index/UNIQUE a `CLOB`). The same changelog therefore applies on real
Postgres and on the H2 PG-compat test DB. To move `metadata` to true `jsonb`
semantics in prod later, wire a `byte[]`/`Json`→String R2DBC reading converter
and `ALTER COLUMN … TYPE jsonb USING …::jsonb`.

## Security

`SecurityConfig` (`@EnableWebFluxSecurity` + `@EnableReactiveMethodSecurity`)
mirrors admin-bff exactly:

- Casdoor JWT resource-server; `casdoorAuthoritiesConverter` (roles claim as
  string or `{name}`, permissions, `isAdmin`, plus a `ROLE_USER` floor) is
  **copied verbatim** and unit-tested.
- Profile split for the springdoc spec/UI: **permitAll** under `dev`/`test` (so
  `gen:fetch` can curl `/v3/api-docs` without a token), **ROLE_ADMIN** in prod.
- Path rules: manifest read = authenticated; modules + overrides = ROLE_ADMIN;
  moderation = ROLE_MOD/ADMIN (decide narrowed to ROLE_ADMIN by `@PreAuthorize`);
  bundles = authenticated (owner = JWT subject, enforced in the service).

## Bundle storage

Pluggable `BundleStorage` (lifted from games `UploadStorage`):
- **`filesystem`** (default) — fully functional; opaque locator
  `file:/…/<slug>/<content-hash>`, zip-slip-safe reads.
- **`s3`** — a documented **stub** that throws 501 (see Deferred). Select with
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
./mvnw test          # 18 tests; R2DBC slices over H2-PG-compat + the REAL
                     # Liquibase changelog; filesystem storage in a temp dir;
                     # Cassandra disabled (noop). No external infra required.
./mvnw package       # builds target/federation-0.1.0.jar
./mvnw -Pnative native:compile   # GraalVM binary (needs a GraalVM host)
```

Tests:
- `ManifestServiceTest` — the keystone: manifest filtering by
  visibility / enabled / circuit-state + cache write-through.
- `FederationModuleRepositoryTest`, `UserModuleRepositoryTest`,
  `ModerationAndOverrideRepositoryTest` — R2DBC slices over the real changelog.
- `SecurityConfigConverterTest` — the Casdoor authority mapping.
- `FederationApplicationContextTest` — full-context boot with degraded defaults.

## Configuration (env)

| Env | Default | Purpose |
|---|---|---|
| `CASDOOR_ISSUER_URI` | `https://id.snapdragon.systems` | JWT issuer |
| `SPRING_R2DBC_URL` / `_USERNAME` / `_PASSWORD` | …`/federation` | runtime DB |
| `SPRING_LIQUIBASE_URL` / `_USER` / `_PASSWORD` | …`/federation` | migration DB |
| `APP_BUNDLES_STORAGE` | `filesystem` | `filesystem` \| `s3` |
| `APP_BUNDLES_DIR` | `/var/snapdragon/federation/bundles` | filesystem root |
| `MANIFEST_CACHE_ENABLED` | `false` | enable the Cassandra cache |
| `SPRING_PROFILES_ACTIVE` | (prod) | `dev` / `test` open the spec |

## Deferred / stubbed (honest)

These are intentionally NOT implemented in the scaffold and are documented here:

- **Full upload pipeline.** `BundleService.put` stages + content-hashes + installs
  a **single** entry file. The games-style multi-file **zip** pipeline (zip-slip
  validation, `manifest.json` schema check, `register.sql` execution) is not
  ported. Port from games `GameUploadService` when needed.
- **S3 / MinIO storage** (`S3BundleStorage`) is a stub that throws 501. The
  production-proven reference is games `S3UploadStorage` (decision 020) — it needs
  the `software.amazon.awssdk:s3` dependency + presigner + Resilience4j circuit
  breaker. The `filesystem` strategy is fully functional today.
- **Auto-applying an approved `moderation_request` as a `federation_override`.**
  Kept as two auditable steps (decide, then apply) for now; wire
  `ModerationService.decide(approve)` → `OverrideService.apply` when the policy is
  finalised.
- **`scope=role` semantics (honest limitation — now IMPLEMENTED, with a caveat).**
  The active scope read-path (`scope=all|user|role`) is implemented (see *The
  manifest read path*). `scope=role` suppresses modules whose **declared**
  `metadata.requiresRole` (case-insensitive) equals the target role. This is
  deliberately a *content-declared* cut for two reasons:
  - There is **no module role column** and **no user→role table** in this service
    (roles live only in the Casdoor JWT), so "drop modules **owned by users who
    hold** role R" is not expressible here. To get that semantic later, add a
    `federation_modules.owner_role` column or wire a Casdoor user-roles lookup.
  - An **audience cut** (filter the manifest by the *caller's* roles) is rejected
    because the manifest cache stores a single **public-safe view**; per-caller
    filtering would poison the shared cached body (the first caller's roles would
    decide everyone's cached manifest). The scope cut therefore runs on the same
    public-safe stream and stays cache-safe.

  Consequence to be aware of: a module with **no** `requiresRole` in its metadata
  is **unaffected** by a `scope=role` kill.
- **Cassandra cache schema bootstrap.** The cache assumes a
  `<keyspace>.federation_manifest (id text PRIMARY KEY, body text, updated_at timestamp)`
  table exists (created by the cluster init CQL, as the games stack does); the
  service does not create it.
- **Vanity PUBLISH path (cross-service — NOT wired this pass).** The vanity
  *resolve* (this repo) is complete and gates on `visibility='public'`. What is
  **not** implemented is the step that *creates/marks* a user's
  `slug=profile-<username>`, `kind=fragment`, `visibility=public` module when the
  user opts in. Today:
  - `snapdragon-user-bff-api` `ProfileService.save` persists
    `user_profile.visibility` (`public|internal`) and `vanity_subdomain_enabled`,
    but has **no** federation call — flipping those flags does **not** register or
    publish a profile fragment.
  - `FederationApiClient` (in user-bff-api) can already `PUT
    /api/federation/bundles/{slug}` (writes a `user_modules` bundle row) and the
    `CardsController` exposes it — but a `user_modules` bundle row is **not** a
    `federation_modules` row. `BundleService.put` records the bundle bytes only; it
    does **not** create the `federation_modules` registry row the manifest +
    vanity-resolve read from. Registering a `federation_modules` row is
    `ROLE_ADMIN`-gated (`ModuleRegistryController`).

  **What must be wired (follow-up), source of truth + gate.** The
  **`user_profile.vanity_subdomain_enabled` + `visibility` flags in user-bff-api
  are the source of truth** for whether a profile is published public; **federation
  gates the serve on `federation_modules.visibility='public'`.** To connect them,
  on `ProfileService.save` when `visibility='public' && vanitySubdomainEnabled`:
  1. publish the profile fragment bytes (`PUT
     /api/federation/bundles/profile-<username>?visibility=public` — already
     possible via `FederationApiClient`); then
  2. **upsert the `federation_modules` row** (`slug=profile-<username>`,
     `kind=fragment`, `owner_user_id=<username>`, `visibility=public`,
     `content_hash` = the published bundle hash). This is the missing link. Two
     clean options: (a) add an **owner-scoped, self-publish-profile** endpoint to
     federation (e.g. `PUT /api/federation/vanity/{username}` owner-gated to the JWT
     subject) that upserts the module from the caller's own bundle — keeps the
     admin registry CRUD admin-only; or (b) have `BundleService.put` optionally
     upsert a `federation_modules` row for `kind=fragment` self-publish bundles.
     Option (a) is recommended (explicit, owner-enforced, no widening of the admin
     registry). When the user sets `visibility=internal` or disables vanity,
     symmetrically flip the module to `visibility='internal'` (or `enabled=false`)
     so the resolve 404s again.
- **Vanity SERVING (how the resolved fragment is rendered at the host).** The
  resolved `VanityProfileDto.fragmentPath`
  (`/_fragments/profile-<username>/<contentHash>/`) is served by the EXISTING
  `snapdragon-remote-fragment` sync-and-serve-static fleet: its sidecar polls
  `GET /api/federation/manifest`, filters `kind=='fragment'`, and mirrors each
  bundle's bytes to `/_fragments/<slug>/<contentHash>/…` where nginx serves them
  statically (no per-request proxy). The fe-gateway already routes `/_fragments/**`
  to that fleet. **Gap:** remote-fragment only syncs fragments that appear in the
  manifest, and the manifest only emits `federation_modules` rows — so a profile
  fragment is synced/served **only once the publish path above creates its
  `federation_modules` row**. The vanity HOST page (the shell that the wildcard
  host serves and that calls `loadRemoteModule(fragmentPath + 'remoteEntry.json')`
  to render the profile) is a `snapdragon.systems` host concern and is **not** built
  in this pass — documented as the front-end follow-up.
- **Gateway PUBLIC_PATHS allowlist (cross-service — THIRD repo, deferred).** The
  generator adds the `Host=*.snapdragon.systems` fe-gateway route pointing directly
  at federation (the public vanity read needs no JWT, and federation already
  `permitAll`s `GET /api/federation/vanity/**`). BUT the **shared gateway image**
  (`snapdragon-gateway` repo) ends every Spring Security chain with
  `anyExchange().authenticated()` and only opens a hardcoded `PUBLIC_PATHS`
  allowlist (`/api/auth`, `/api/registration`, `/api/login`, the login/registration
  remotes). `/api/federation/vanity/**` is **not** in that allowlist, so the
  fe-gateway pod would itself **401** the anonymous vanity request before it
  reaches federation. To make the public vanity host actually reachable end-to-end,
  add `/api/federation/vanity/**` (or a `Host=*.<domain>` public rule) to the
  gateway `PUBLIC_PATHS`. That is a one-line change in the `snapdragon-gateway`
  repo, out of scope for this two-repo (federation + generator) pass.

## Conventions mirrored

- **Engine** = `snapdragon.games/backend`: `federation_modules` (`db/changelog/018`),
  `FederationController` (reactive `findAllByEnabledTrue → DTO`), `UploadStorage`
  (pluggable filesystem|S3, opaque locator) + `AssetController` reactive serving +
  content-hash versioning + `game_access` scope (`all|role|user`).
- **Conventions** = `snapdragon-admin-bff-api`: reactive WebFlux security
  (`@EnableWebFluxSecurity` + profile-split filter chains), R2DBC +
  JDBC-only-for-Liquibase, Casdoor authority converter, `CassandraRouteMirror`
  best-effort mirror, springdoc, native hints, Dockerfile, `.gitlab-ci.yml`,
  H2-PG-compat slice tests over the real changelog.
