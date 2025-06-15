package app.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class TokenService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenService.class);
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder; // Added JwtDecoder for validation
    private final Set<String> revokedTokens = ConcurrentHashMap.newKeySet(); // Thread-safe blacklist

    private static final int ACCESS_TOKEN_EXPIRATION_MINUTES = 60; // 1 hour
    private static final int REFRESH_TOKEN_EXPIRATION_DAYS = 7; // 7 days

    public TokenService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder) { // Inject JwtDecoder
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
    }

    /**
     * Generates an access token with user details and expiration.
     */
    public String generateAccessToken(Authentication authentication) {
        Instant now = Instant.now();
        String scope = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(ACCESS_TOKEN_EXPIRATION_MINUTES, ChronoUnit.MINUTES))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        LOGGER.info("Access token generated for user: {}", authentication.getName());
        return token;
    }

    /**
     * Generates a refresh token with extended expiration.
     */
    public String generateRefreshToken(Authentication authentication) {
        Instant now = Instant.now();

        JwtClaimsSet refreshClaims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(REFRESH_TOKEN_EXPIRATION_DAYS, ChronoUnit.DAYS))
                .subject(authentication.getName())
                .claim("type", "refresh")
                .build();

        String refreshToken = jwtEncoder.encode(JwtEncoderParameters.from(refreshClaims)).getTokenValue();
        LOGGER.info("Refresh token generated for user: {}", authentication.getName());
        return refreshToken;
    }

    /**
     * Revokes a token, adding it to the blacklist.
     */
    public void revokeToken(String token) {
        LOGGER.info("Revoking token: {}", token);
        if (token != null && !token.isEmpty()) {
            revokedTokens.add(token);
            LOGGER.info("Token added to blacklist: {}", token);
        } else {
            LOGGER.warn("Attempted to revoke an empty or null token");
        }
    }

    /**
     * Checks if a token has been revoked.
     */
    public boolean isTokenRevoked(String token) {
        boolean revoked = token != null && revokedTokens.contains(token);
        LOGGER.debug("Checking if token is revoked: {} -> {}", token, revoked);
        return revoked;
    }

    /**
     * Decodes JWT and validates if it's expired.
     */
    public boolean isTokenExpired(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            Instant expirationTime = jwt.getExpiresAt();
            boolean expired = expirationTime == null || expirationTime.isBefore(Instant.now());
            LOGGER.debug("Checking if token is expired: {} -> {}", token, expired);
            return expired;
        } catch (JwtException e) {
            LOGGER.warn("Failed to decode token: {}", e.getMessage());
            return true; // Treat invalid JWTs as expired
        }
    }

    /**
     * Validates a token by checking both expiration and revocation status.
     */
    public boolean isTokenValid(String token) {
        boolean valid = !isTokenExpired(token) && !isTokenRevoked(token);
        LOGGER.debug("Checking if token is valid: {} -> {}", token, valid);
        return valid;
    }
}
