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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth") // Ensures correct URL mapping
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtDecoder jwtDecoder;

    public AuthController(TokenService tokenService, AuthenticationManager authenticationManager,
                          UserDetailsService userDetailsService, JwtDecoder jwtDecoder) {
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.jwtDecoder = jwtDecoder;
    }

    /**
     * Handles user login and returns a JWT token.
     */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest loginRequest) {
        try {
            if (loginRequest.getUsername() == null || loginRequest.getPassword() == null) {
                LOGGER.warn("Login request missing username or password");
                return Map.of("error", "Username and password are required");
            }

            LOGGER.info("Login request for user: {}", loginRequest.getUsername());

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            String token = tokenService.generateAccessToken(authentication);

            LOGGER.info("✅ Token generated successfully for user: {}", loginRequest.getUsername());

            return Map.of("status", "success", "token", token);
        } catch (BadCredentialsException e) {
            LOGGER.warn("❌ Invalid credentials for user: {}", loginRequest.getUsername());
            return Map.of("status", "error", "message", "Invalid username or password");
        } catch (Exception e) {
            LOGGER.error("❌ Login failed for user: {}", loginRequest.getUsername(), e);
            return Map.of("status", "error", "message", "Authentication error");
        }
    }

    /**
     * Handles user logout and revokes the JWT token.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            LOGGER.warn("❌ Logout request missing a valid Authorization header");
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid logout request"));
        }

        String token = authHeader.substring(7); // Extract token

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // ✅ Ensure authentication exists before processing logout
        if (authentication == null || !authentication.isAuthenticated()) {
            LOGGER.warn("⚠️ Logout request received, but no authentication found - manually extracting");

            try {
                Jwt decodedJwt = jwtDecoder.decode(token);
                authentication = new JwtAuthenticationToken(decodedJwt);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                LOGGER.info("✅ Authentication set for logout: {}", authentication.getName());
            } catch (Exception e) {
                LOGGER.warn("❌ Failed to decode token: {}", e.getMessage());
                return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
            }
        }

        LOGGER.info("🔹 Logging out user: {}", authentication.getName());
        LOGGER.info("🔹 Revoking token: {}", token);
        tokenService.revokeToken(token); // Blacklist token

        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

}
