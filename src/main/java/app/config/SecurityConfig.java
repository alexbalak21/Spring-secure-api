package app.config;

import app.security.JwtRevocationFilter;
import app.service.TokenService;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.*;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Set;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfig.class);
    private final RsaKeyProperties rsaKeys;

    public SecurityConfig(RsaKeyProperties rsaKeyProperties) {
        this.rsaKeys = rsaKeyProperties;
    }

    @Bean
    public UserDetailsService userDetailsService() {
        LOGGER.info("🔹 Initializing in-memory user store...");
        return new InMemoryUserDetailsManager(
                User.withUsername("alex")
                        .password(passwordEncoder().encode("azerty123"))
                        .roles("USER")
                        .build()
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, TokenService tokenService) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/login", "/auth/logout").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .addFilterBefore(new JwtRevocationFilter(tokenService, Set.of("/auth/login", "/auth/logout")), BearerTokenAuthenticationFilter.class)
                .logout(logout -> logout
                        .logoutUrl("/auth/logout")
                        .addLogoutHandler((request, response, authentication) -> {
                            LOGGER.info("🔹 Processing logout request...");

                            if (authentication == null) {
                                LOGGER.warn("⚠️ Logout handler: No authentication found. Trying manual extraction...");
                                String authHeader = request.getHeader("Authorization");
                                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                                    String token = authHeader.substring(7);
                                    try {
                                        Jwt decodedJwt = jwtDecoder().decode(token);
                                        authentication = new JwtAuthenticationToken(decodedJwt);
                                        LOGGER.info("✅ Authentication manually set for logout: {}", authentication.getName());
                                    } catch (Exception e) {
                                        LOGGER.error("❌ Failed to decode token: {}", e.getMessage());
                                    }
                                }
                            }

                            if (authentication != null) {
                                LOGGER.info("🔹 Logging out user: {}", authentication.getName());
                                String token = authentication.getCredentials().toString();
                                if (!tokenService.isTokenRevoked(token)) {
                                    tokenService.revokeToken(token);
                                    LOGGER.info("✅ Token successfully revoked: {}", token);
                                } else {
                                    LOGGER.warn("❌ Token already revoked: {}", token);
                                }
                                SecurityContextHolder.clearContext(); // ✅ Ensures full logout
                            }
                        })
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);
                            response.setContentType("application/json");
                            response.getWriter().write("{\"message\": \"Logged out successfully\"}");
                        })
                        .permitAll()
                )
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        LOGGER.info("🔹 Initializing AuthenticationManager...");

        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(); // Deprecated DaoAuthenticationProvider()
        authProvider.setUserDetailsService(userDetailsService); // Deprecated setUserDetailsService()
        authProvider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(List.of(authProvider));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtDecoder jwtDecoder() {
        LOGGER.info("🔹 Initializing JWT Decoder...");
        return NimbusJwtDecoder.withPublicKey(rsaKeys.publicKey()).build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        LOGGER.info("🔹 Initializing JWT Encoder...");
        JWK jwk = new RSAKey.Builder(rsaKeys.publicKey()).privateKey(rsaKeys.privateKey()).build();
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }
}
