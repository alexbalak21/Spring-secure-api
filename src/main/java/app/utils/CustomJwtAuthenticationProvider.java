package app.utils;

import app.service.TokenService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;

@Component
public class CustomJwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtAuthenticationProvider jwtAuthProvider;
    private final TokenService tokenService;

    public CustomJwtAuthenticationProvider(JwtDecoder jwtDecoder, TokenService tokenService) {
        this.jwtAuthProvider = new JwtAuthenticationProvider(jwtDecoder);
        this.tokenService = tokenService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        String tokenValue = jwtToken.getToken().getTokenValue();

        // Reject revoked tokens
        if (tokenService.isTokenRevoked(tokenValue)) {
            throw new SecurityException("Token has been revoked");
        }

        return jwtAuthProvider.authenticate(authentication);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
