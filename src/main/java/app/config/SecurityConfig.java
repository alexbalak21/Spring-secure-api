package app.config;

import app.security.JwtRevocationFilter;
import app.service.TokenService;
import app.utils.CustomJwtAuthenticationProvider;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Set;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RsaKeyProperties rsaKeys;

    public SecurityConfig(RsaKeyProperties rsaKeyProperties) {
        this.rsaKeys = rsaKeyProperties;
    }

    /**
     * Defines an in-memory user store with a single user.
     * The password is hashed using BCrypt for security.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("alex")
                        .password(passwordEncoder().encode("azerty123"))
                        .roles("USER")
                        .build()
        );
    }

    /**
     * Configures security rules for HTTP requests:
     * - Disables CSRF (useful for stateless REST APIs).
     * - Allows unrestricted access to "/login" and "/logout".
     * - Requires authentication for all other requests.
     * - Enables JWT authentication.
     * - Ensures sessions are stateless (no server-side sessions).
     * - Adds a custom JWT revocation filter to block revoked tokens.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, TokenService tokenService) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/logout").permitAll() // Ensure login is accessible
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .addFilterBefore(new JwtRevocationFilter(tokenService, Set.of("/login", "/register")), BearerTokenAuthenticationFilter.class)
                .logout(logout -> logout.logoutUrl("/logout").permitAll()) // Explicit logout handling
                .build();
    }

    /**
     * Configures the AuthenticationManager using a custom authentication provider.
     */
    @Bean
    public AuthenticationManager authenticationManager(CustomJwtAuthenticationProvider jwtAuthProvider) {
        return new ProviderManager(jwtAuthProvider);
    }

    /**
     * Defines a password encoder using BCrypt.
     * BCrypt is recommended for securely hashing passwords.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * JWT Decoder - responsible for verifying JWT tokens using RSA public key.
     */
    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeys.publicKey()).build();
    }

    /**
     * JWT Encoder - generates signed JWT tokens using RSA private key.
     */
    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(rsaKeys.publicKey()).privateKey(rsaKeys.privateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }
}
