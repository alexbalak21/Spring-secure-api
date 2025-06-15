package app.security;

import app.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtRevocationFilter extends OncePerRequestFilter {

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

        // Skip token revocation checks for ignored endpoints (e.g., "/login", "/register")
        if (ignoredEndpoints.contains(requestPath)) {
            chain.doFilter(request, response);
            return;
        }

        var authentication = SecurityContextHolder.getContext().getAuthentication();

        // If no authentication token is found, proceed without blocking
        if (!(authentication instanceof JwtAuthenticationToken jwtToken)) {
            chain.doFilter(request, response);
            return;
        }

        String tokenValue = jwtToken.getToken().getTokenValue();

        // Block requests if the token has been revoked
        if (tokenService.isTokenRevoked(tokenValue)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Token has been revoked\"}");
            return;
        }

        chain.doFilter(request, response);
    }
}
