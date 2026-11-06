package io.cdpi.trustregistry;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/** Test classpath only. Lets tests drive the real exception-handling chain with unexpected failures. */
@Hidden
@RestController
class FailureInjectionController {

    @GetMapping("/v1/admin/test-failure/{kind}")
    String fail(@PathVariable String kind) {
        if (kind.equals("runtime")) {
            throw new IllegalStateException("secret-internal-detail password=hunter2");
        }
        if (kind.equals("integrity-other")) {
            throw new DataIntegrityViolationException("insert failed",
                new RuntimeException("violates check constraint \"ck_issuer_status\" secret-table-detail"));
        }
        if (kind.equals("unavailable")) {
            throw new QueryTimeoutException("jdbc:postgresql://secret-host/db timed out");
        }
        return "ok";
    }
}
