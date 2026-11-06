package io.cdpi.trustregistry.api;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.method.annotation.ExceptionHandlerMethodResolver;

/** ExceptionHandlerMethodResolver throws on ambiguous mappings: constructing it is the ambiguity check. */
class ExceptionHandlerMappingTest {

    @Test
    void globalHandlerHasNoAmbiguousMapping_andNoCatchAll() {
        ExceptionHandlerMethodResolver resolver =
            assertDoesNotThrow(() -> new ExceptionHandlerMethodResolver(GlobalExceptionHandler.class));
        assertNull(resolver.resolveMethodByThrowable(new RuntimeException("anything")),
            "no catch-all expected in the ResponseEntityExceptionHandler subclass");
        // standard MVC exceptions are still handled by the base class
        assertNotNull(resolver.resolveMethodByThrowable(new MissingServletRequestParameterException("p", "String")));
        // custom mappings are all present
        assertNotNull(resolver.resolveMethodByThrowable(new io.cdpi.trustregistry.error.Errors.Conflict("x")));
        assertNotNull(resolver.resolveMethodByThrowable(new org.springframework.dao.DataIntegrityViolationException("x")));
        assertNotNull(resolver.resolveMethodByThrowable(new org.springframework.dao.QueryTimeoutException("x")));
    }

    @Test
    void fallbackHandlerHasNoAmbiguousMapping_andCatchesTheRest() {
        ExceptionHandlerMethodResolver resolver =
            assertDoesNotThrow(() -> new ExceptionHandlerMethodResolver(FallbackExceptionHandler.class));
        assertNotNull(resolver.resolveMethodByThrowable(new IllegalStateException("x")));
    }
}
