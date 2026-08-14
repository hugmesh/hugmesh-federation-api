package net.hugmesh.federation.config;

import io.r2dbc.spi.ConnectionFactory;
import org.springframework.boot.data.r2dbc.autoconfigure.DataR2dbcAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.convert.ReadingConverter;
import org.springframework.data.r2dbc.convert.R2dbcCustomConversions;
import org.springframework.data.r2dbc.dialect.DialectResolver;
import org.springframework.data.r2dbc.dialect.R2dbcDialect;

import org.springframework.data.convert.WritingConverter;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;

/**
 * R2DBC type-conversion shims. Copied from the games {@code R2dbcConvertersConfig}:
 * the Postgres driver returns {@code OffsetDateTime} / {@code LocalDateTime} for
 * {@code timestamptz} / {@code timestamp} columns while the entities expect
 * {@code Instant}. Spring Data's reflective JSR-310 fallbacks are skipped under
 * GraalVM native-image, so registering the two reading converters explicitly
 * makes the conversion deterministic in both JVM and native modes (and on the H2
 * slice-test DB, which also hands back {@code LocalDateTime} for {@code timestamp}).
 *
 * <p><b>Why the WRITING converter exists (zone symmetry).</b> The reading side
 * pins UTC ({@code LocalDateTime.toInstant(UTC)}), but without a writing
 * converter the DRIVER encodes an {@code Instant} into a {@code timestamp}
 * column via the JVM's <i>system default zone</i> (both r2dbc-postgresql and
 * io.r2dbc.h2). On any non-UTC host that asymmetry silently shifts EVERY
 * timestamp by the local offset on EVERY save+read round-trip — e.g. a
 * read-modify-save patch ({@code ModuleRegistryService.applyPatch}, the admin
 * upsert refresh) would move a row's {@code created_at} hours backwards per
 * write. Latent in UTC-pinned prod containers, live everywhere else.
 * {@link InstantToLocalDateTimeConverter} mirrors the read assumption
 * (UTC wall time on the wire) so the round-trip is the identity in every zone.
 */
@Configuration(proxyBeanMethods = false)
public class R2dbcConvertersConfig {

    /** Replaces the auto-configured {@link R2dbcCustomConversions} bean
     *  (see {@link DataR2dbcAutoConfiguration}) with the two timestamp converters
     *  added on top of the dialect defaults. */
    @Bean
    public R2dbcCustomConversions r2dbcCustomConversions(ConnectionFactory connectionFactory) {
        R2dbcDialect dialect = DialectResolver.getDialect(connectionFactory);
        var converters = new ArrayList<>(dialect.getConverters());
        converters.add(new OffsetDateTimeToInstantConverter());
        converters.add(new LocalDateTimeToInstantConverter());
        converters.add(new InstantToLocalDateTimeConverter());
        return R2dbcCustomConversions.of(dialect, converters);
    }

    @ReadingConverter
    static class OffsetDateTimeToInstantConverter implements Converter<OffsetDateTime, Instant> {
        @Override public Instant convert(OffsetDateTime source) { return source.toInstant(); }
    }

    @ReadingConverter
    static class LocalDateTimeToInstantConverter implements Converter<LocalDateTime, Instant> {
        @Override public Instant convert(LocalDateTime source) { return source.toInstant(ZoneOffset.UTC); }
    }

    /** The write-side mirror of {@link LocalDateTimeToInstantConverter}: an
     *  {@code Instant} goes to the {@code timestamp} column as UTC wall time, so
     *  write+read is the identity regardless of the host's default zone (without
     *  this the driver encodes via the system zone — see the class javadoc). */
    @WritingConverter
    static class InstantToLocalDateTimeConverter implements Converter<Instant, LocalDateTime> {
        @Override public LocalDateTime convert(Instant source) {
            return LocalDateTime.ofInstant(source, ZoneOffset.UTC);
        }
    }
}
