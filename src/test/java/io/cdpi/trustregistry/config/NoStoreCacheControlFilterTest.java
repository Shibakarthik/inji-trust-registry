package io.cdpi.trustregistry.config;

import static org.junit.jupiter.api.Assertions.*;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class NoStoreCacheControlFilterTest {

    private final NoStoreCacheControlFilter filter = new NoStoreCacheControlFilter();

    private MockHttpServletResponse run(MockHttpServletRequest request, FilterChain chain) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        return response;
    }

    private static MockHttpServletRequest request(String contextPath, String uri) {
        MockHttpServletRequest r = new MockHttpServletRequest("GET", uri);
        r.setContextPath(contextPath);
        r.setRequestURI(uri);
        return r;
    }

    @Test
    void downstreamCodeCannotReplaceOrAddCacheControl() throws Exception {
        MockHttpServletResponse response = run(request("", "/v1/authorizations/check"), (req, res) -> {
            HttpServletResponse r = (HttpServletResponse) res;
            r.setHeader("Cache-Control", "max-age=3600");
            r.addHeader("cache-control", "public");
            r.setHeader("CACHE-CONTROL", "no-cache");
            r.setDateHeader("Cache-Control", 1L);
            r.addIntHeader("Cache-Control", 5);
            r.setStatus(400);
        });
        assertEquals(List.of("no-store"), response.getHeaders("Cache-Control"));
        assertEquals(400, response.getStatus());
    }

    @Test
    void headerSurvivesResponseReset() throws Exception {
        MockHttpServletResponse response = run(request("", "/v1/authorizations/check"), (req, res) -> {
            ((HttpServletResponse) res).reset();
            ((HttpServletResponse) res).setHeader("Cache-Control", "public");
        });
        assertEquals(List.of("no-store"), response.getHeaders("Cache-Control"));
    }

    @Test
    void worksUnderAContextPath_trailingSlash_andPathParameters() throws Exception {
        FilterChain noop = (req, res) -> { };
        assertEquals("no-store", run(request("/registry", "/registry/v1/authorizations/check"), noop).getHeader("Cache-Control"));
        assertEquals("no-store", run(request("/registry", "/registry/v1/authorizations/check/"), noop).getHeader("Cache-Control"));
        assertEquals("no-store", run(request("", "/v1/authorizations/check;jsessionid=1"), noop).getHeader("Cache-Control"));
    }

    @Test
    void appliesOnContainerErrorDispatchOfThePublicPath() throws Exception {
        MockHttpServletRequest request = request("/registry", "/registry/error");
        request.setDispatcherType(DispatcherType.ERROR);
        request.setAttribute(RequestDispatcher.ERROR_REQUEST_URI, "/registry/v1/authorizations/check");
        assertEquals("no-store", run(request, (req, res) -> { }).getHeader("Cache-Control"));
    }

    @Test
    void otherPathsAreUntouched() throws Exception {
        MockHttpServletResponse response = run(request("", "/v1/admin/issuers"), (req, res) ->
            ((HttpServletResponse) res).setHeader("Cache-Control", "max-age=60"));
        assertEquals(List.of("max-age=60"), response.getHeaders("Cache-Control"));
        assertNull(run(request("", "/v1/authorizations/other"), (req, res) -> { }).getHeader("Cache-Control"));
    }
}
