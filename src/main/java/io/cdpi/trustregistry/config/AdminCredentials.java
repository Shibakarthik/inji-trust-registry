package io.cdpi.trustregistry.config;

import java.nio.charset.StandardCharsets;

/**
 * Startup validation of the administrator credentials. Messages name the setting, never its value, so nothing
 * secret can reach logs or error output.
 */
public final class AdminCredentials {
    private AdminCredentials() { }

    public static final int MIN_PASSWORD_CHARS = 12;
    /** BCrypt only uses the first 72 bytes of its input; longer passwords are rejected instead of silently truncated. */
    public static final int BCRYPT_MAX_PASSWORD_BYTES = 72;
    public static final int MAX_USERNAME_CHARS = 128;

    public static void validate(String username, String password) {
        if (username == null || username.isBlank()) {
            throw new IllegalStateException("ADMIN_USERNAME (registry.admin.username) must not be blank");
        }
        if (!username.equals(username.strip())) {
            throw new IllegalStateException("ADMIN_USERNAME (registry.admin.username) must not start or end with whitespace");
        }
        if (username.indexOf(':') >= 0) {
            throw new IllegalStateException("ADMIN_USERNAME (registry.admin.username) must not contain ':' (HTTP Basic restriction)");
        }
        if (username.length() > MAX_USERNAME_CHARS) {
            throw new IllegalStateException("ADMIN_USERNAME (registry.admin.username) must be at most " + MAX_USERNAME_CHARS + " characters");
        }
        if (password == null || password.isBlank() || password.length() < MIN_PASSWORD_CHARS) {
            throw new IllegalStateException(
                "ADMIN_PASSWORD (registry.admin.password) must be set and at least " + MIN_PASSWORD_CHARS + " characters long");
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > BCRYPT_MAX_PASSWORD_BYTES) {
            throw new IllegalStateException(
                "ADMIN_PASSWORD (registry.admin.password) must be at most " + BCRYPT_MAX_PASSWORD_BYTES + " bytes in UTF-8 (BCrypt limit)");
        }
    }
}
