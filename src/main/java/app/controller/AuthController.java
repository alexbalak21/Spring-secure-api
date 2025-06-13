package app.controller;

import app.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;


//Need to finish and test

@RestController
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    private final TokenService tokenService;


    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    public String token(Authentication authentication) {
        LOGGER.debug("Token request for {}", authentication.getName());
        String token = tokenService.generateToken(authentication);
        LOGGER.debug("Token granted: {}", token);
        return token;

    }
}
