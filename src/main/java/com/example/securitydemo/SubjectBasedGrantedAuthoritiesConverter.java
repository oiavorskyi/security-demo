package com.example.securitydemo;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Custom converter that returns collection of {@link GrantedAuthority}
 * based on the subject claim of the provided JWT token.
 * <p>
 * The implementation relies on {@link SubjectRolesResolver} to perform the actual
 * mapping of the roles.
 * <p>
 * For more details see
 * <a href="https://docs.spring.io/spring-security/site/docs/5.5.3/reference/html5/#oauth2resourceserver-jwt-authorization">Spring Security documentation</a>
 */
public class SubjectBasedGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final SubjectRolesResolver roleProvider;

    public SubjectBasedGrantedAuthoritiesConverter(SubjectRolesResolver roleProvider) {
        this.roleProvider = roleProvider;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {
        return roleProvider.getRolesBySubject(source.getSubject())
                .stream()
                // Match default Spring Security expectations about role names used in authorization rules
                .map(role -> "ROLE_" + role)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }
}
