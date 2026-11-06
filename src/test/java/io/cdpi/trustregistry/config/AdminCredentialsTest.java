package io.cdpi.trustregistry.config;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class AdminCredentialsTest {

    private static void rejected(String user, String password) {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> AdminCredentials.validate(user, password));
        if (password != null && !password.isBlank()) {
            assertFalse(e.getMessage().contains(password), "message must never contain the password");
        }
    }

    @Test
    void acceptsValidCredentials() {
        assertDoesNotThrow(() -> AdminCredentials.validate("admin", "a-long-enough-password"));
        assertDoesNotThrow(() -> AdminCredentials.validate("registry.admin", "x".repeat(72)));
        assertDoesNotThrow(() -> AdminCredentials.validate("admin", "é".repeat(36))); // 72 bytes in UTF-8
    }

    @Test
    void rejectsBadUsernames() {
        rejected(null, "a-long-enough-password");
        rejected("", "a-long-enough-password");
        rejected("   ", "a-long-enough-password");
        rejected(" admin", "a-long-enough-password");
        rejected("ad:min", "a-long-enough-password");
        rejected("a".repeat(129), "a-long-enough-password");
    }

    @Test
    void rejectsBadPasswords() {
        rejected("admin", null);
        rejected("admin", "");
        rejected("admin", " ".repeat(20));
        rejected("admin", "short-pw-1");           // 10 chars
        rejected("admin", "x".repeat(73));          // 73 bytes
        rejected("admin", "é".repeat(37));          // 37 chars but 74 bytes: BCrypt would silently truncate
    }
}
