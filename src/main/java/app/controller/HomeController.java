package app.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/") // Base path for the controller
public class HomeController {

    private static final Logger LOGGER = LoggerFactory.getLogger(HomeController.class);

    /**
     * Handles requests to "/".
     * Returns a welcome message with the authenticated user's username.
     */
    @GetMapping
    public Map<String, String> home(Principal principal) {
        LOGGER.info("✅ Accessing home endpoint. Authenticated user: {}", principal.getName());
        return Map.of("message", "Welcome to the API", "username", principal.getName());
    }

    /**
     * Handles requests to "/profile".
     * Extracts and returns all claims stored in the JWT token.
     */
    @GetMapping("/profile")
    public Map<String, Object> profile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof JwtAuthenticationToken jwtAuthToken) {
            LOGGER.info("✅ Profile access granted for user: {}", jwtAuthToken.getName());
            LOGGER.debug("🔹 JWT Claims: {}", jwtAuthToken.getTokenAttributes());
            return jwtAuthToken.getTokenAttributes(); // Extracts all claims from the JWT
        }

        LOGGER.warn("❌ Profile access denied: No JWT token found.");
        return Map.of("error", "No JWT token found");
    }
}
