# Security — hugmesh-federation-api

## Authentication layers

This API is defended in depth by two independent layers:

1. **OAuth2 resource server (application layer).** Every request must carry a
   valid Casdoor-issued JWT (`spring.security.oauth2.resourceserver`), except four
   public reads: `GET /api/federation/vanity` (and `/vanity/**`),
   `GET /api/federation/capabilities`, and the probes `/actuator/health`,
   `/actuator/health/**` and `/actuator/info`. Fine-grained
   authz (modules/overrides = `ROLE_ADMIN`, moderation = `ROLE_MOD`/`ROLE_ADMIN`,
   manifest GET + bundles = authenticated, plus `ROLE_SUPERADMIN` on every
   privileged gate) is enforced in `SecurityConfig`. The README's *Security*
   section lists every path rule.

2. **Mutual TLS — the API-to-API trust boundary (transport layer).** In-cluster,
   the TLS handshake **requires a client certificate that chains to the cluster CA
   truststore**. Only services that were deployed and signed by our Vault/ESO PKI
   process hold such a certificate. A random pod, an external client, or
   anything not issued by our PKI presents no chaining cert, so its handshake is
   rejected before any byte of HTTP is read — it cannot read or call this API at all.

## How the mTLS layer is wired

The cluster CA is the offline root from `hugmesh-generator/scripts/gen-keystores.sh`.
In-cluster, Vault's `pki_int` role (which chains to that root) issues a leaf cert per
app with `ttl: 720h`; External Secrets Operator (ESO) refreshes it every 168h into the
`hugmesh-federation-api-mtls` `kubernetes.io/tls` Secret (`tls.crt` / `tls.key` /
`ca.crt`, where `ca.crt` is the issuing CA Vault returns). A keystore
initContainer (the equivalent of the gateway chart's `build-keystore`) assembles:

- `keystore.p12` — this service's own mTLS **identity** (key + cert chain),
- `truststore.p12` — the **cluster CA** trust anchor,

into an in-pod tmpfs and generates the store password there (it never enters git,
a Secret, or Vault). The deployment then sets the env below so the running pod
enforces client-cert verification. Because every in-cluster leaf chains to the same
cluster CA, the truststore validates them. The initContainer runs once per pod start,
so a refreshed Secret reaches the pod only when the pod restarts.

The gateways are the legitimate callers. `hugmesh-be-gateway` presents its own
ESO-issued client cert (`hugmesh-be-gateway-mtls`) on the `federation-api` route
(`/api/federation/**`), and `hugmesh-fe-gateway` presents its client cert on the direct
`vanity-subdomain` route. Their handshakes succeed; a caller without a cert chaining to the cluster CA fails.

## Configuration (parameterized — safe by default)

`server.ssl.*` in `application.yml` is parameterized so local/dev/CI keep working:

| Property | Env var | Local/CI default | In-cluster value |
| --- | --- | --- | --- |
| `server.ssl.enabled` | `SSL_ENABLED` | `false` (plaintext) | `true` |
| `server.ssl.client-auth` | `SSL_CLIENT_AUTH` | `none` | `need` |
| `server.ssl.key-store` | `SSL_KEY_STORE` | `/stores/keystore.p12` | mounted PKCS12 keystore |
| `server.ssl.key-store-type` | `SSL_KEY_STORE_TYPE` | `PKCS12` | `PKCS12` |
| `server.ssl.key-store-password` | `SSL_KEY_STORE_PASSWORD` | _(empty)_ | in-pod-generated |
| `server.ssl.trust-store` | `SSL_TRUST_STORE` | `/stores/truststore.p12` | mounted PKCS12 truststore (cluster CA) |
| `server.ssl.trust-store-type` | `SSL_TRUST_STORE_TYPE` | `PKCS12` | `PKCS12` |
| `server.ssl.trust-store-password` | `SSL_TRUST_STORE_PASSWORD` | _(empty)_ | in-pod-generated |
| `server.ssl.enabled-protocols` | `SSL_ENABLED_PROTOCOLS` | `TLSv1.3` | `TLSv1.3` |

With the defaults, `server.ssl.enabled=false`, so the stores are never opened and
existing tests run unchanged. `client-auth` maps to Netty's `ClientAuth`:
`none → NONE`, `want → OPTIONAL`, `need → REQUIRE`. WebFlux/Netty reads these
properties directly; no custom `SslContext`/`HttpServer` bean is needed.

## Deployment requirement ✅ wired

The **authoritative** deployment manifest for this API lives in
`hugmesh-generator` (`specs/cluster/manifests/federation-api/deployment.yaml`);
this repo's own [`deploy/deployment.yaml`](deploy/deployment.yaml) is a mirror of it,
staged for the (not-yet-active) Forgejo/ArgoCD
`hugmesh-deploy.yaml` catalog cutover — see that file's own header comment for
the dual-home rationale. The mirror has drifted: the generator copy sets the Cassandra
manifest-cache block differently (CQL auth on with user `federation_cass`, local
datacenter `datacenter1`, a `hugmesh.net/cassandra-access: dml` pod annotation), while
this repo's copy keeps CQL auth off and `dc1`. The mTLS wiring is identical in both. Both copies carry the enforcement wiring: a
`build-keystore` initContainer assembles `keystore.p12` (this pod's Vault-PKI
identity, from the ESO-synced `hugmesh-federation-api-mtls` Secret) +
`truststore.p12` (the cluster CA) into a `Memory`-backed `stores` `emptyDir`
(store password generated in-pod, never in git/a Secret/the pod spec), and the
container env sets:

```
SSL_ENABLED=true
SSL_CLIENT_AUTH=need
SSL_KEY_STORE=/stores/keystore.p12
SSL_KEY_STORE_TYPE=PKCS12
SSL_TRUST_STORE=/stores/truststore.p12
SSL_TRUST_STORE_TYPE=PKCS12
```

(`SSL_KEY_STORE_PASSWORD` / `SSL_TRUST_STORE_PASSWORD` come from the in-pod
generated `/stores/application.properties`, loaded via
`SPRING_CONFIG_ADDITIONAL_LOCATION` — never set directly in the env block.) The
readiness/liveness probes are already HTTPS `exec` `curl` calls presenting this
pod's own client cert, matching `SSL_CLIENT_AUTH=need`.

## Continuous security testing (CI) ✅ shipped

In addition to the two runtime auth layers above, this repo participates in the
platform **continuous-OWASP pen-test standard** as a **CI-pipeline control** (a
dev/CI stage — NOT a deployed CronJob and NOT a runtime/UI trigger).

`.gitlab-ci.yml` runs `stages: [security, dast, pentest, test, build]` (the `test`
stage runs the real JUnit suite, incl. the full-context `@SpringBootTest`s against
a Testcontainers-provisioned Postgres, and — unlike the advisory pen-test stage
below — actually gates `build:image`). The `pentest:*` jobs `extends:` the
canonical, org-wide template `include`d from `hugmesh-generator`
(`/tests/pentest/ci/pentest-stage.gitlab-ci.yml`), the single source of truth, so
the full harness runs:

- **OWASP Dependency-Check (SCA)** — flags known-vulnerable dependencies;
- **ZAP API DAST** — the authenticated baseline scan with the custom
  escalation / DoS probes;
- **nuclei** — the org's grounded templates.

The stage is **advisory** (`allow_failure: true`): it reports findings but never
gates the `build:image` job, and runs on the default branch + merge requests.
These jobs **replace** the earlier inline `dependency-check` / `zap-api-scan`
jobs (migrated into the shared template — no duplicate scan path).
