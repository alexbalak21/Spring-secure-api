package app.controller;

import app.dto.LoginRequest;
import app.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;

    public AuthController(TokenService tokenService, AuthenticationManager authenticationManager) {
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getName(), loginRequest.getPassword())
        );

        LOGGER.debug("Login request for {}", loginRequest.getName());
        String token = tokenService.generateAccessToken(authentication);
        LOGGER.debug("Token granted: {}", token);

        return token;
    }

    @PostMapping("/logout")
    public Map<String, String> logout(@RequestHeader("Authorization") String token) {
        if (token.startsWith("Bearer ")) {
            token = token.substring(7); // Remove "Bearer " prefix
        }

        tokenService.revokeToken(token); // Add token to blacklist
        return Map.of("message", "Logged out successfully");
    }

    //AUTHER VIDEO
    //https://youtu.be/0GGFZdYe-FY?si=mUbBmaPqdtmXNvIr
}

