package com.example.securitydemo;

import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * Implementations of this interface encapsulate details of configuring
 * a {@link JwtDecoder} instance to use in order to decode and validate
 * JWT tokens issued by a provider with a particular <em>issuer name</em>.
 */
public interface SupportedJwtTokenIssuer {

    /**
     * The value of <em>iss</em> claim in JWT token for which this configuration
     * shall be used.
     */
    String getIssuerName();

    /**
     * The decoder to use to validate JWT token issued by the issuer with the
     * name returned from the {@link SupportedJwtTokenIssuer#getIssuerName()}
     * method.
     */
    JwtDecoder getJwtDecoder();

}
