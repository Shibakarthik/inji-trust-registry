package io.cdpi.trustregistry.dto;

import io.cdpi.trustregistry.error.Errors;
import java.util.regex.Pattern;

/**
 * Single source of truth for input validation (Bean Validation annotations and manual service/controller checks).
 * Values are validated, never normalised: matching stays exact and case-sensitive.
 */
public final class Patterns {
    private Patterns() { }

    public static final int DID_MAX = 512;              // issuer.did VARCHAR(512)
    public static final int CREDENTIAL_TYPE_MAX = 128;  // issuer_credential_authorization.credential_type VARCHAR(128)
    public static final int DISPLAY_NAME_MAX = 255;     // issuer.display_name VARCHAR(255)

    private static final String IDCHAR = "(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})";

    /**
     * W3C DID syntax: did:method-name:method-specific-id where
     * method-specific-id = *( *idchar ":" ) 1*idchar. Mixed case in the identifier is legitimate
     * (e.g. did:web:Shibakarthik.github.io:collab:farmer). DID URLs (path, query, fragment) are not DIDs.
     */
    public static final String DID_REGEX = "^did:[a-z0-9]+:(?:" + IDCHAR + "*:)*" + IDCHAR + "+$";

    /** Starts alphanumeric; letters, digits and _ . : - after that; 1..128 chars. No whitespace, slashes or quotes. */
    public static final String CREDENTIAL_TYPE_REGEX = "^[A-Za-z0-9][A-Za-z0-9_.:\\-]{0,127}$";

    private static final Pattern DID = Pattern.compile(DID_REGEX);
    private static final Pattern CREDENTIAL_TYPE = Pattern.compile(CREDENTIAL_TYPE_REGEX);

    public static String requireIssuerId(String value) {
        if (value == null || value.length() > DID_MAX || !DID.matcher(value).matches()) {
            throw new Errors.InvalidRequest(
                "issuerId must be a valid DID (did:<method>:<identifier>, max " + DID_MAX + " characters)");
        }
        return value;
    }

    public static String requireCredentialType(String value) {
        if (value == null || value.length() > CREDENTIAL_TYPE_MAX || !CREDENTIAL_TYPE.matcher(value).matches()) {
            throw new Errors.InvalidRequest(
                "credentialType must be 1-" + CREDENTIAL_TYPE_MAX + " characters, start with a letter or digit and "
                + "contain only letters, digits, '_', '.', ':' or '-'");
        }
        return value;
    }

    public static String requireDisplayName(String value) {
        if (value == null || value.isBlank() || value.length() > DISPLAY_NAME_MAX) {
            throw new Errors.InvalidRequest("displayName must be non-blank and at most " + DISPLAY_NAME_MAX + " characters");
        }
        return value;
    }
}
