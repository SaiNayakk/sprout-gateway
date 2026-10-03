package app.sprout.gateway;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/** Anything outside the routed API gets a problem response, never a server error page. */
@RestControllerAdvice
public class ErrorAdvice {

    @ExceptionHandler(NoResourceFoundException.class)
    void notFound(HttpServletResponse res) throws IOException {
        Problems.write(res, 404, "NOT_FOUND", "Not found", "There's nothing at this address.", null);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    void method(HttpServletResponse res) throws IOException {
        Problems.write(res, 405, "VALIDATION_FAILED", "Method not allowed", "This address doesn't accept that method.", null);
    }
}
