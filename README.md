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
