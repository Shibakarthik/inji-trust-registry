package io.cdpi.trustregistry.config;

import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Access matrix (this class is what ENFORCES it; OpenAPI annotations only document it):
 *   GET public check/OpenAPI/Swagger/health -> public
 *   /v1/admin/**                            -> HTTP Basic, ROLE_REGISTRY_ADMIN
 *   unsafe admin methods                    -> additionally require X-Registry-Admin-Request: true
 *   everything else                        -> denied
 *
 * The explicit custom-header requirement is a CSRF defence for this Basic-authenticated, stateless API.
 * A browser form cannot add the header, and a cross-origin fetch needs a preflight which is not allowed
 * for admin routes (CORS is configured only for the public GET check). Non-browser admin clients must
 * send the header on POST/PATCH/PUT/DELETE requests.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    public static final String ADMIN_ROLE = "REGISTRY_ADMIN";
    public static final String ADMIN_REQUEST_HEADER = "X-Registry-Admin-Request";
    public static final String ADMIN_REQUEST_HEADER_VALUE = "true";

    private static final Set<String> UNSAFE_METHODS = Set.of(
        HttpMethod.POST.name(), HttpMethod.PUT.name(), HttpMethod.PATCH.name(), HttpMethod.DELETE.name());

    private static final RequestMatcher MISSING_ADMIN_REQUEST_HEADER = request -> {
        String contextPath = request.getContextPath() == null ? "" : request.getContextPath();
        boolean adminPath = request.getRequestURI().startsWith(contextPath + "/v1/admin/");
        boolean unsafeMethod = UNSAFE_METHODS.contains(request.getMethod());
        return adminPath && unsafeMethod
            && !ADMIN_REQUEST_HEADER_VALUE.equals(request.getHeader(ADMIN_REQUEST_HEADER));
    };

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, ProblemJsonSecurityHandlers problems) throws Exception {
        http
            // Stateless HTTP Basic does not create a synchronizer-token workflow. Instead, unsafe admin
            // requests are required to carry a non-simple custom header; see MISSING_ADMIN_REQUEST_HEADER.
            .csrf(csrf -> csrf.disable())
            .cors(Customizer.withDefaults())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a
                .requestMatchers(HttpMethod.GET, "/v1/authorizations/check").permitAll()
                .requestMatchers(HttpMethod.GET, "/v1/openapi.json", "/v1/openapi.json/**",
                        "/v3/api-docs", "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers(MISSING_ADMIN_REQUEST_HEADER).denyAll()
                .requestMatchers("/v1/admin/**").hasRole(ADMIN_ROLE)
                .anyRequest().denyAll())
            .exceptionHandling(e -> e.authenticationEntryPoint(problems).accessDeniedHandler(problems))
            .httpBasic(b -> b.authenticationEntryPoint(problems));
        return http.build();
    }

    /** Only the public check endpoint is CORS-enabled (GET, any origin, NO credentials). */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(List.of("*"));
        cfg.setAllowedMethods(List.of("GET"));
        cfg.setAllowCredentials(false);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/v1/authorizations/check", cfg);
        return source;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /** Credentials come from the environment; the password is BCrypt-hashed at startup and never compared in clear text. */
    @Bean
    UserDetailsService userDetailsService(
            @Value("${registry.admin.username}") String username,
            @Value("${registry.admin.password}") String password,
            PasswordEncoder encoder) {
        AdminCredentials.validate(username, password);
        return new InMemoryUserDetailsManager(
            User.withUsername(username).password(encoder.encode(password)).roles(ADMIN_ROLE).build());
    }
}
