package app.utils;

import app.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;

@Component
public class CustomJwtAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomJwtAuthenticationProvider.class);
    private final JwtAuthenticationProvider jwtAuthProvider;
    private final TokenService tokenService;

    public CustomJwtAuthenticationProvider(JwtDecoder jwtDecoder, TokenService tokenService) {
        this.jwtAuthProvider = new JwtAuthenticationProvider(jwtDecoder);
        this.tokenService = tokenService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken jwtToken)) {
            LOGGER.warn("⚠️ Unsupported authentication type: {}", authentication.getClass().getName());
            return null;
        }

        String tokenValue = jwtToken.getToken().getTokenValue();
        LOGGER.info("🔹 Authenticating token: {}", tokenValue);

        boolean revoked = tokenService.isTokenRevoked(tokenValue);
        boolean expired = tokenService.isTokenExpired(tokenValue);
        LOGGER.debug("🔹 Revocation/Expiration check -> Token: {}, Revoked: {}, Expired: {}", tokenValue, revoked, expired);

        if (revoked || expired) {
            LOGGER.warn("❌ Authentication blocked: Token is revoked or expired - {}", tokenValue);
            LOGGER.error("🚨 SECURITY ALERT: Revoked/Expired token {} attempted authentication!", tokenValue);

            SecurityContextHolder.clearContext(); // ✅ Ensure authentication removal before rejection
            throw new BadCredentialsException("Token is invalid (revoked or expired)");
        }

        LOGGER.info("✅ Token is valid, proceeding with authentication: {}", tokenValue);
        return jwtAuthProvider.authenticate(jwtToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
