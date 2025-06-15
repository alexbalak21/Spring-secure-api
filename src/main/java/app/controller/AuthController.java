package app.controller;

import app.dto.LoginRequest;
import app.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final JwtDecoder jwtDecoder;

    public AuthController(TokenService tokenService, AuthenticationManager authenticationManager, JwtDecoder jwtDecoder) {
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
        this.jwtDecoder = jwtDecoder;
    }

    /**
     * Handles user login and returns a JWT token.
     */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest loginRequest) {
        try {
            if (loginRequest.getUsername() == null || loginRequest.getPassword() == null) {
                LOGGER.warn("⚠️ Login request missing username or password");
                return Map.of("status", "error", "message", "Username and password are required");
            }

            LOGGER.info("🔹 Login attempt for user: {}", loginRequest.getUsername());

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            String token = tokenService.generateAccessToken(authentication);
            LOGGER.info("✅ Token successfully generated for user: {}", loginRequest.getUsername());

            return Map.of("status", "success", "token", token);
        } catch (BadCredentialsException e) {
            LOGGER.warn("❌ Authentication failed for user: {} - Invalid credentials", loginRequest.getUsername());
            return Map.of("status", "error", "message", "Invalid username or password");
        } catch (Exception e) {
            LOGGER.error("❌ Unexpected error during login for user: {}", loginRequest.getUsername(), e);
            return Map.of("status", "error", "message", "Authentication error. Please try again.");
        }
    }

    /**
     * Handles user logout and revokes the JWT token.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            LOGGER.warn("❌ Logout request missing or invalid Authorization header");
            return ResponseEntity.badRequest().body(Map.of("status", "error", "message", "Invalid logout request"));
        }

        String token = authHeader.substring(7);
        LOGGER.info("🔹 Logout request received. Extracted token: {}", token);

        if (tokenService.isTokenRevoked(token)) {
            LOGGER.warn("❌ Token is already revoked. Rejecting logout request.");
            return ResponseEntity.status(401).body(Map.of("status", "error", "message", "Token already revoked"));
        }

        try {
            Jwt decodedJwt = jwtDecoder.decode(token);
            Authentication authentication = new JwtAuthenticationToken(decodedJwt);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            LOGGER.info("✅ Authentication manually set for logout: {}", authentication.getName());

            LOGGER.info("🔹 Revoking token: {}", token);
            tokenService.revokeToken(token); // ✅ Blacklist the token immediately

            SecurityContextHolder.clearContext(); // ✅ Ensure full logout
            LOGGER.info("✅ User {} logged out successfully", authentication.getName());

            return ResponseEntity.ok(Map.of("status", "success", "message", "Logged out successfully"));
        } catch (Exception e) {
            LOGGER.error("❌ Failed to decode token during logout: {}", e.getMessage());
            return ResponseEntity.status(401).body(Map.of("status", "error", "message", "Invalid token"));
        }
    }
}
