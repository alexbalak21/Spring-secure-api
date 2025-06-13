package app.config;

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
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
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
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final RsaKeyProperties rsaKeys;

    // Constructor to inject RSA key properties for JWT
    public SecurityConfig(RsaKeyProperties rsaKeyProperties) {
        this.rsaKeys = rsaKeyProperties;
    }

    /**
     * Defines an in-memory user details service that stores users.
     * Here, we create a user named "alex" with a hashed password.
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("alex")
                        .password(passwordEncoder().encode("azerty123")) // Encrypts password using BCrypt
                        .roles("USER") // Assigns a role to the user
                        .build()
        );
    }

    /**
     * Configures the security filter chain:
     * - Disables CSRF (useful for REST APIs)
     * - Requires authentication for all requests (except login)
     * - Uses JWT-based authentication
     * - Makes sessions stateless
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable) // Disables CSRF protection for stateless API requests
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll() // Allows login without authentication
                        .anyRequest().authenticated() // Protects all other endpoints
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Makes authentication stateless
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())) // Enables JWT authentication
                .build();
    }

    /**
     * Creates an AuthenticationManager using the UserDetailsService and password encoder.
     * This manager is responsible for authenticating users.
     */
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return new ProviderManager(authProvider);
    }

    /**
     * Defines the password encoder for hashing passwords.
     * BCrypt is a strong password hashing algorithm that prevents dictionary attacks.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * JWT Decoder - responsible for decoding JWT tokens using RSA public key.
     * This ensures the tokens provided to users are verified properly.
     */
    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeys.publicKey()).build();
    }

    /**
     * JWT Encoder - responsible for generating JWT tokens using RSA private key.
     * This allows the system to create secure, signed tokens that clients can use for authentication.
     */
    @Bean
    JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(rsaKeys.publicKey()).privateKey(rsaKeys.privateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }
}
