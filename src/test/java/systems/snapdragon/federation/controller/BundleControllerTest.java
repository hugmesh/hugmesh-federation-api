package systems.snapdragon.federation.controller;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.snapdragon.federation.model.UserModule;
import systems.snapdragon.federation.service.BundleService;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Bundle controller unit coverage for the owner-scoped read-body + delete: proves
 * the controller forwards the JWT subject as the owner, resolves the ADMIN flag
 * from the reactive security context, and surfaces the service's reactive result.
 * The service is mocked; assertions are reactive (StepVerifier) — mirrors
 * VanityControllerTest's direct-call style (no running server).
 */
class BundleControllerTest {

    private static final String SLUG = "my-card";

    private static Jwt jwtFor(String subject) {
        return Jwt.withTokenValue("t")
                .header("alg", "none")
                .subject(subject)
                .claim("sub", subject)
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }

    /** A security context whose authentication carries the given authorities. */
    private static SecurityContext ctx(String subject, String... roles) {
        var authorities = java.util.Arrays.stream(roles).map(SimpleGrantedAuthority::new).toList();
        var auth = new UsernamePasswordAuthenticationToken(subject, "n/a", authorities);
        var ctx = new org.springframework.security.core.context.SecurityContextImpl();
        ctx.setAuthentication(auth);
        return ctx;
    }

    // ---------- read-body ----------

    @Test
    void readBody_forwardsSubjectAsOwner_nonAdmin_returnsBytes() {
        BundleService svc = mock(BundleService.class);
        Resource bytes = new ByteArrayResource("<h1>hi</h1>".getBytes(StandardCharsets.UTF_8));
        when(svc.readOwnBody(eq("alice"), eq(SLUG), eq(false))).thenReturn(Mono.just(bytes));
        BundleController c = new BundleController(svc);

        StepVerifier.create(c.readBody(jwtFor("alice"), SLUG)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("alice", "ROLE_USER")))))
                .assertNext(resp -> {
                    assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
                    assertThat(resp.getBody()).isSameAs(bytes);
                })
                .verifyComplete();

        verify(svc).readOwnBody("alice", SLUG, false);
    }

    @Test
    void readBody_adminFlag_isResolvedFromSecurityContext() {
        BundleService svc = mock(BundleService.class);
        Resource bytes = new ByteArrayResource("x".getBytes(StandardCharsets.UTF_8));
        when(svc.readOwnBody(eq("root"), eq(SLUG), eq(true))).thenReturn(Mono.just(bytes));
        BundleController c = new BundleController(svc);

        StepVerifier.create(c.readBody(jwtFor("root"), SLUG)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("root", "ROLE_USER", "ROLE_ADMIN")))))
                .assertNext(resp -> assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK))
                .verifyComplete();

        verify(svc).readOwnBody("root", SLUG, true);
    }

    @Test
    void readBody_propagatesServiceNotFound() {
        BundleService svc = mock(BundleService.class);
        when(svc.readOwnBody(eq("alice"), eq(SLUG), eq(false)))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "no body")));
        BundleController c = new BundleController(svc);

        StepVerifier.create(c.readBody(jwtFor("alice"), SLUG)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("alice", "ROLE_USER")))))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.NOT_FOUND))
                .verify();
    }

    // ---------- delete ----------

    @Test
    void delete_forwardsSubjectAsOwner_nonAdmin() {
        BundleService svc = mock(BundleService.class);
        when(svc.deleteForOwner(eq("alice"), eq(SLUG), eq(false))).thenReturn(Mono.empty());
        BundleController c = new BundleController(svc);

        StepVerifier.create(c.delete(jwtFor("alice"), SLUG)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("alice", "ROLE_USER")))))
                .verifyComplete();

        verify(svc).deleteForOwner("alice", SLUG, false);
    }

    @Test
    void delete_adminFlag_isResolvedFromSecurityContext() {
        BundleService svc = mock(BundleService.class);
        when(svc.deleteForOwner(eq("root"), eq(SLUG), eq(true))).thenReturn(Mono.empty());
        BundleController c = new BundleController(svc);

        StepVerifier.create(c.delete(jwtFor("root"), SLUG)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("root", "ROLE_USER", "ROLE_ADMIN")))))
                .verifyComplete();

        verify(svc).deleteForOwner("root", SLUG, true);
    }

    @Test
    void delete_propagatesServiceForbiddenAsNotFound() {
        BundleService svc = mock(BundleService.class);
        when(svc.deleteForOwner(eq("bob"), eq(SLUG), eq(false)))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND, "no bundle for slug")));
        BundleController c = new BundleController(svc);

        StepVerifier.create(c.delete(jwtFor("bob"), SLUG)
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("bob", "ROLE_USER")))))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.NOT_FOUND))
                .verify();
    }

    // ---------- put ----------

    @Test
    void put_forwardsSubjectAsOwner_nonAdminFlag() {
        BundleService svc = mock(BundleService.class);
        UserModule saved = new UserModule();
        saved.setOwnerUserId("alice");
        // non-admin caller -> admin=false forwarded; subject forwarded as owner.
        when(svc.put(eq("alice"), eq(SLUG), eq("card.html"), eq("internal"), eq("{}"),
                eq(false), org.mockito.ArgumentMatchers.<reactor.core.publisher.Flux<org.springframework.core.io.buffer.DataBuffer>>any()))
                .thenReturn(Mono.just(saved));
        BundleController c = new BundleController(svc);

        StepVerifier.create(c.put(jwtFor("alice"), SLUG, "card.html", "internal", "{}",
                        reactor.core.publisher.Flux.empty())
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("alice", "ROLE_USER")))))
                .assertNext(m -> assertThat(m.getOwnerUserId()).isEqualTo("alice"))
                .verifyComplete();

        verify(svc).put(eq("alice"), eq(SLUG), eq("card.html"), eq("internal"), eq("{}"),
                eq(false), org.mockito.ArgumentMatchers.<reactor.core.publisher.Flux<org.springframework.core.io.buffer.DataBuffer>>any());
    }

    @Test
    void put_adminFlag_isResolvedFromSecurityContext() {
        BundleService svc = mock(BundleService.class);
        UserModule saved = new UserModule();
        saved.setOwnerUserId("root");
        when(svc.put(eq("root"), eq(SLUG), org.mockito.ArgumentMatchers.isNull(),
                org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.isNull(),
                eq(true), org.mockito.ArgumentMatchers.<reactor.core.publisher.Flux<org.springframework.core.io.buffer.DataBuffer>>any()))
                .thenReturn(Mono.just(saved));
        BundleController c = new BundleController(svc);

        StepVerifier.create(c.put(jwtFor("root"), SLUG, null, null, null,
                        reactor.core.publisher.Flux.empty())
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("root", "ROLE_USER", "ROLE_ADMIN")))))
                .assertNext(m -> assertThat(m.getOwnerUserId()).isEqualTo("root"))
                .verifyComplete();

        verify(svc).put(eq("root"), eq(SLUG), org.mockito.ArgumentMatchers.isNull(),
                org.mockito.ArgumentMatchers.isNull(), org.mockito.ArgumentMatchers.isNull(),
                eq(true), org.mockito.ArgumentMatchers.<reactor.core.publisher.Flux<org.springframework.core.io.buffer.DataBuffer>>any());
    }

    @Test
    void put_propagatesServiceConflict_forCrossOwnerWrite() {
        BundleService svc = mock(BundleService.class);
        when(svc.put(eq("bob"), eq(SLUG), org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any(),
                eq(false), org.mockito.ArgumentMatchers.<reactor.core.publisher.Flux<org.springframework.core.io.buffer.DataBuffer>>any()))
                .thenReturn(Mono.error(new ResponseStatusException(HttpStatus.CONFLICT, "another owner")));
        BundleController c = new BundleController(svc);

        StepVerifier.create(c.put(jwtFor("bob"), SLUG, "card.html", "internal", "{}",
                        reactor.core.publisher.Flux.empty())
                        .contextWrite(ReactiveSecurityContextHolder.withSecurityContext(
                                Mono.just(ctx("bob", "ROLE_USER")))))
                .expectErrorSatisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode())
                        .isEqualTo(HttpStatus.CONFLICT))
                .verify();
    }
}
