package io.cdpi.trustregistry;

import static org.junit.jupiter.api.Assertions.*;

import io.cdpi.trustregistry.api.FallbackExceptionHandler;
import io.cdpi.trustregistry.api.GlobalExceptionHandler;
import io.cdpi.trustregistry.config.NoStoreCacheControlFilter;
import java.time.Clock;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.ControllerAdvice;

/** Reaching this class means the full context started: Hibernate validated the entities against db/init/01-schema.sql. */
class ApplicationContextStartupTest extends AbstractPostgresTest {

    @Autowired ApplicationContext ctx;

    @Test
    void contextStarts_withExpectedInfrastructure() {
        assertEquals("validate", ctx.getEnvironment().getProperty("spring.jpa.hibernate.ddl-auto"));
        assertEquals(1, ctx.getBeansOfType(GlobalExceptionHandler.class).size());
        assertEquals(1, ctx.getBeansOfType(FallbackExceptionHandler.class).size());
        assertTrue(ctx.getBeansWithAnnotation(ControllerAdvice.class).size() >= 2);
        assertEquals(1, ctx.getBeansOfType(NoStoreCacheControlFilter.class).size());
        assertFalse(ctx.getBeansOfType(SecurityFilterChain.class).isEmpty());
    }

    @Test
    void clockBeanIsUtc() {
        assertEquals(ZoneOffset.UTC, ctx.getBean(Clock.class).getZone());
    }
}
