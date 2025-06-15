package app.security;

import app.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtRevocationFilter extends OncePerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtRevocationFilter.class);
    private final TokenService tokenService;
    private final Set<String> ignoredEndpoints;

    public JwtRevocationFilter(TokenService tokenService, Set<String> ignoredEndpoints) {
        this.tokenService = tokenService;
        this.ignoredEndpoints = ignoredEndpoints.stream()
                .map(String::toLowerCase)
                .collect(Collectors.toSet()); // Case-insensitive matching
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String requestPath = request.getRequestURI().toLowerCase();
        LOGGER.info("🔹 Incoming request: {}", requestPath);

        var authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!(authentication instanceof JwtAuthenticationToken jwtToken)) {
            LOGGER.debug("⚠️ No JWT token found, allowing request to proceed.");
            chain.doFilter(request, response);
            return;
        }

        String tokenValue = jwtToken.getToken().getTokenValue();
        LOGGER.info("🔹 Checking revocation status for token: {}", tokenValue);

        boolean revoked = tokenService.isTokenRevoked(tokenValue);
        LOGGER.debug("🔹 Revocation check result -> Token: {}, Revoked: {}", tokenValue, revoked);

        if (revoked) {
            LOGGER.warn("❌ Token revoked: Blocking request - {}", tokenValue);
            LOGGER.error("🚨 SECURITY ALERT: Revoked token {} attempted access!", tokenValue);

            SecurityContextHolder.clearContext(); // ✅ Ensure authentication is removed BEFORE responding

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Token has been revoked\"}");
            response.getWriter().flush();

            return; // ✅ Stops further request processing BEFORE Spring Security runs authentication
        }

        LOGGER.debug("✅ Token is valid, allowing request to proceed.");
        chain.doFilter(request, response);
    }
}
