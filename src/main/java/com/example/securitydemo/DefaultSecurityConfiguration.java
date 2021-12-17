package com.example.securitydemo;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configures security rules for the application and registers two {@link SupportedJwtTokenIssuer}
 * to enable validation of the JWT tokens issued by different providers.
 */
@Configuration
public class DefaultSecurityConfiguration {

    /**
     * This is a more recent approach to configuring the security chain where
     * instead of extending and overwriting {@link WebSecurityConfigurerAdapter}
     * we just expose a bean of the type {@link SecurityFilterChain}.
     * <p>
     * Note that it is possible to have multiple beans of this type in the same
     * application context.
     */
    @Bean
    public SecurityFilterChain defaultSecurityChain(HttpSecurity http) throws Exception {
        return http
                // First define authorization rules
                .authorizeRequests(auth -> auth
                        .antMatchers("/public").permitAll() // anyone can access
                        .antMatchers("/admin").hasRole("ADMIN") // only users with role "ROLE_ADMIN" can access
                        .anyRequest().authenticated() // only authenticated users can access regardless of role
                )
                // Enable security configuration for OAuth 2 Resource Server
                .oauth2ResourceServer(oauth -> oauth
                        // This is what enables support for multiple token issuers
                        .authenticationManagerResolver(authenticationManagerResolver(null, null))
                )
                .build();
    }

    @Bean
    public SupportedJwtTokenIssuer privateServerJwtTokenIssuer() {
        return new PrivateServerJwtTokenIssuer();
    }

    @Bean
    public SupportedJwtTokenIssuer mockOidcJwtTokenIssuer() {
        return new MockOidcJwtTokenIssuer();
    }

    /**
     * Custom JWT authentication converter with our own implementation of
     * {@link JwtGrantedAuthoritiesConverter} that maps token subject claim
     * to a collection of user roles.
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter(null));
        return jwtAuthenticationConverter;
    }

    /**
     * Implementation of {@link JwtGrantedAuthoritiesConverter} that maps token's
     * subject claim to a collection of user roles.
     */
    @Bean
    public SubjectBasedGrantedAuthoritiesConverter grantedAuthoritiesConverter(SubjectRolesResolver roleProvider) {
        return new SubjectBasedGrantedAuthoritiesConverter(roleProvider);
    }

    /**
     * Instance of the {@link JwtIssuerAuthenticationManagerResolver} preconfigured
     * to map issuers to their respective JwtDecoders based on the available instances
     * of the {@link SupportedJwtTokenIssuer}.
     * <p>
     * It utilizes Spring's ability to inject all beans of a specific type from
     * the application context as a single collection. To add support for a new
     * issuer it is enough to register one more bean of type {@link SupportedJwtTokenIssuer}.
     * <p>
     * This approach to configuring multi-tenancy was taken from the
     * <a href="https://docs.spring.io/spring-security/site/docs/5.5.3/reference/html5/#oauth2resourceserver-multitenancy">documentation</a>
     */
    @Bean
    public JwtIssuerAuthenticationManagerResolver authenticationManagerResolver(
            Collection<SupportedJwtTokenIssuer> supportedIssuers,
            JwtAuthenticationConverter jwtAuthenticationConverter) {
        Map<String, AuthenticationManager> authenticationManagers = new ConcurrentHashMap<>();

        for (SupportedJwtTokenIssuer issuer : supportedIssuers) {
            JwtAuthenticationProvider provider =
                    createJwtAuthenticationProviderForIssuer(issuer, jwtAuthenticationConverter);
            authenticationManagers.put(issuer.getIssuerName(), provider::authenticate);
        }

        return new JwtIssuerAuthenticationManagerResolver(authenticationManagers::get);
    }

    private JwtAuthenticationProvider createJwtAuthenticationProviderForIssuer(SupportedJwtTokenIssuer issuer, JwtAuthenticationConverter converter) {
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(issuer.getJwtDecoder());
        provider.setJwtAuthenticationConverter(converter);
        return provider;
    }

}
