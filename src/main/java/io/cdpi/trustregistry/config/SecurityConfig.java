package io.cdpi.trustregistry.config;

import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Access matrix (this class is what ENFORCES it; OpenAPI annotations only document it):
 *   GET /v1/authorizations/check, /v1/openapi.json, /v3/api-docs/**, /swagger-ui*, GET /actuator/health -> public
 *   /v1/admin/**                                                                                        -> HTTP Basic, ROLE_REGISTRY_ADMIN
 *   everything else                                                                                     -> denied
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    public static final String ADMIN_ROLE = "REGISTRY_ADMIN";

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, ProblemJsonSecurityHandlers problems) throws Exception {
        http
            // CSRF protection defends cookie/session authentication. This API has neither: sessions are
            // STATELESS, no cookies are issued, and every request carries its own Authorization header.
            // Leaving CSRF on would only break legitimate non-browser POST/PATCH clients.
            .csrf(AbstractHttpConfigurer::disable)
            .cors(Customizer.withDefaults())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a
                .requestMatchers(HttpMethod.GET, "/v1/authorizations/check").permitAll()
                .requestMatchers(HttpMethod.GET, "/v1/openapi.json", "/v1/openapi.json/**",
                        "/v3/api-docs", "/v3/api-docs/**", "/swagger-ui.html", "/swagger-ui/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/actuator/health", "/actuator/health/**").permitAll()
                .requestMatchers("/v1/admin/**").hasRole(ADMIN_ROLE)
                .anyRequest().denyAll())
            .exceptionHandling(e -> e.authenticationEntryPoint(problems).accessDeniedHandler(problems))
            .httpBasic(b -> b.authenticationEntryPoint(problems));
        return http.build();
    }

    /**
     * Only the public check endpoint is CORS-enabled (GET, any origin, NO credentials), so browser-based verifiers
     * can call it. No other path has a CORS configuration.
     */
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
