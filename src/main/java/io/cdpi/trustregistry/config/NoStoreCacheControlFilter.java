package io.cdpi.trustregistry.config;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authorisation decisions must never be served from a cache. Runs before Spring Security and MVC, so
 * "Cache-Control: no-store" is on 200s, validation errors (400), technical errors (5xx) and security
 * rejections for this endpoint alike. The response wrapper makes the header immutable for downstream code:
 * set/add of Cache-Control are ignored and the header is re-applied after reset(). The filter also runs on
 * container ERROR dispatches, and the path is evaluated relative to any configured context path.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class NoStoreCacheControlFilter extends OncePerRequestFilter {

    static final String PATH = "/v1/authorizations/check";
    private static final String CACHE_CONTROL = "Cache-Control";
    private static final String NO_STORE = "no-store";

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !PATH.equals(applicationPath(request));
    }

    @Override
    protected boolean shouldNotFilterErrorDispatch() {
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        chain.doFilter(request, new NoStoreResponse(response));
    }

    /** Request path relative to the application's context path; on an ERROR dispatch, the originally requested path. */
    static String applicationPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (request.getDispatcherType() == DispatcherType.ERROR
                && request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI) instanceof String original) {
            uri = original;
        }
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)) {
            uri = uri.substring(contextPath.length());
        }
        int semicolon = uri.indexOf(';');
        if (semicolon >= 0) {
            uri = uri.substring(0, semicolon);
        }
        while (uri.length() > 1 && uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        return uri;
    }

    private static final class NoStoreResponse extends HttpServletResponseWrapper {

        NoStoreResponse(HttpServletResponse response) {
            super(response);
            applyNoStore();
        }

        private void applyNoStore() {
            super.setHeader(CACHE_CONTROL, NO_STORE);
        }

        private static boolean isCacheControl(String name) {
            return CACHE_CONTROL.equalsIgnoreCase(name);
        }

        @Override
        public void setHeader(String name, String value) {
            if (!isCacheControl(name)) {
                super.setHeader(name, value);
            }
        }

        @Override
        public void addHeader(String name, String value) {
            if (!isCacheControl(name)) {
                super.addHeader(name, value);
            }
        }

        @Override
        public void setDateHeader(String name, long date) {
            if (!isCacheControl(name)) {
                super.setDateHeader(name, date);
            }
        }

        @Override
        public void addDateHeader(String name, long date) {
            if (!isCacheControl(name)) {
                super.addDateHeader(name, date);
            }
        }

        @Override
        public void setIntHeader(String name, int value) {
            if (!isCacheControl(name)) {
                super.setIntHeader(name, value);
            }
        }

        @Override
        public void addIntHeader(String name, int value) {
            if (!isCacheControl(name)) {
                super.addIntHeader(name, value);
            }
        }

        @Override
        public void reset() {
            super.reset();
            applyNoStore();
        }
    }
}
