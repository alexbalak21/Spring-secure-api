package app.controller;

import app.dto.LoginRequest;
import app.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth") // Ensures correct URL mapping
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    public AuthController(TokenService tokenService, AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    /**
     * Handles user login and returns a JWT token.
     */
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Validate input
            if (loginRequest.getUsername() == null || loginRequest.getPassword() == null) {
                LOGGER.warn("Login request missing username or password");
                return Map.of("error", "Username and password are required");
            }

            LOGGER.info("Login request for user: {}", loginRequest.getUsername());

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());
            String token = tokenService.generateAccessToken(authentication);

            LOGGER.info("Token generated successfully for user: {}", loginRequest.getUsername());

            return Map.of("status", "success", "token", token);
        } catch (BadCredentialsException e) {
            LOGGER.warn("Invalid credentials for user: {}", loginRequest.getUsername());
            return Map.of("status", "error", "message", "Invalid username or password");
        } catch (Exception e) {
            LOGGER.error("Login failed for user: {}", loginRequest.getUsername(), e);
            return Map.of("status", "error", "message", "Authentication error");
        }
    }

    /**
     * Handles user logout and revokes the JWT token.
     */
    @PostMapping("/auth/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, @RequestHeader("Authorization") String authHeader) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            LOGGER.warn("Logout request received, but no authentication found");
        } else {
            LOGGER.info("Logging out user: {}", authentication.getName());
        }

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            LOGGER.warn("Logout request missing a valid Authorization header");
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid logout request"));
        }

        String token = authHeader.substring(7); // Extract token
        LOGGER.info("Revoking token: {}", token);
        tokenService.revokeToken(token); // Blacklist token

        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }


}
