package io.cdpi.trustregistry.error;

public final class Errors {
    private Errors() { }

    public static class InvalidRequest extends RuntimeException {
        public InvalidRequest(String message) { super(message); }
    }

    public static class NotFound extends RuntimeException {
        public NotFound(String message) { super(message); }
    }

    public static class Conflict extends RuntimeException {
        public Conflict(String message) { super(message); }
    }
}
