package app.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class TokenService {

    private final JwtEncoder jwtEncoder;
    private final Set<String> revokedTokens = ConcurrentHashMap.newKeySet(); // Thread-safe blacklist

    private static final int ACCESS_TOKEN_EXPIRATION_MINUTES = 60; // 1 hour
    private static final int REFRESH_TOKEN_EXPIRATION_DAYS = 7; // 7 days

    public TokenService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
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

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
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

        return jwtEncoder.encode(JwtEncoderParameters.from(refreshClaims)).getTokenValue();
    }

    /**
     * Revokes a token, adding it to the blacklist.
     */
    public void revokeToken(String token) {
        if (token != null && !token.isEmpty()) {
            revokedTokens.add(token);
        }
    }

    /**
     * Checks if a token has been revoked.
     */
    public boolean isTokenRevoked(String token) {
        return token != null && revokedTokens.contains(token);
    }

    /**
     * Checks if a token has expired.
     */
    public boolean isTokenExpired(Jwt jwt) {
        Instant expirationTime = jwt.getExpiresAt();
        return expirationTime == null || expirationTime.isBefore(Instant.now());
    }

    /**
     * Validates a token by checking both expiration and revocation status.
     */
    public boolean isTokenValid(Jwt jwt) {
        return !isTokenExpired(jwt) && !isTokenRevoked(jwt.getTokenValue());
    }
}
