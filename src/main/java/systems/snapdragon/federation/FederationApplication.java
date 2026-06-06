package systems.snapdragon.federation;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * snapdragon-federation-api — the platform dynamic-federation registry/DB/manifest
 * API (the Phase-4 keystone).
 *
 * <p>Hosts the authoritative {@code federation_modules} catalog, serves the
 * runtime manifest the Angular host bootstrap feeds into native-federation's
 * {@code initFederation(...)}, stores per-user federated module bundles
 * (content-hash versioned, served back so snapdragon-remote-fragment pods can
 * SYNC them), and owns the platform-wide moderation / kill-switch surface
 * (federation_override + moderation_requests).
 *
 * <p>Reactive end-to-end (WebFlux + R2DBC); JDBC is used ONLY by Liquibase for
 * schema migrations. Conventions mirror snapdragon-admin-bff-api; the federation
 * engine itself is lifted from the snapdragon.games DB-backed
 * {@code FederationController} + {@code UploadStorage} + {@code game_access}
 * patterns.
 */
@SpringBootApplication
public class FederationApplication {
    public static void main(String[] args) {
        SpringApplication.run(FederationApplication.class, args);
    }
}
