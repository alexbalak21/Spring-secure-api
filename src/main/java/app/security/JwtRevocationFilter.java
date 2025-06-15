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
        // Ensure ignored endpoints are treated in a case-insensitive manner
        this.ignoredEndpoints = ignoredEndpoints.stream()
                .map(String::toLowerCase)
                .collect(Collectors.toSet());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String requestPath = request.getRequestURI().toLowerCase();
        LOGGER.debug("Request received at path: {}", requestPath);

        // Skip token revocation checks for ignored endpoints (e.g., "/login", "/register")
        if (ignoredEndpoints.contains(requestPath)) {
            LOGGER.debug("Skipping token revocation check for ignored endpoint: {}", requestPath);
            chain.doFilter(request, response);
            return;
        }

        var authentication = SecurityContextHolder.getContext().getAuthentication();

        // If no authentication token is found, proceed without blocking
        if (!(authentication instanceof JwtAuthenticationToken jwtToken)) {
            LOGGER.debug("No JWT token found, allowing request to proceed");
            chain.doFilter(request, response);
            return;
        }

        String tokenValue = jwtToken.getToken().getTokenValue();
        LOGGER.debug("Checking revocation status for token: {}", tokenValue);

        // Block requests if the token has been revoked
        if (tokenService.isTokenRevoked(tokenValue)) {
            LOGGER.warn("Blocked request: Token has been revoked - {}", tokenValue);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Token has been revoked\"}");
            return;
        }

        LOGGER.debug("Token is valid, proceeding with request");
        chain.doFilter(request, response);
    }
}
