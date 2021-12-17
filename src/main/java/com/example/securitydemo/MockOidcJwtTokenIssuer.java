package com.example.securitydemo;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;

/**
 * Provides decoder for tokens issued by mock OIDC provider.
 * <p>
 * The majority of this implementation is taken from the {@link JwtDecoders} class
 * and customized to accommodate for the deficiencies in the implementation of
 * the mock OIDC provider we use for testing. In production scenarios the configuration
 * of the JwtDecoder could be as simple as:
 * <pre>
 * {@code
 * JwtDecoders.fromOidcIssuerLocation("https://some.issuer");
 * }
 * </pre>
 */
public class MockOidcJwtTokenIssuer implements SupportedJwtTokenIssuer {
    public static final String ISSUER_NAME = "https://oauth.mocklab.io";
    public static final String JWK_SET_URI = "https://oauth.mocklab.io/.well-known/jwks.json";

    @Override
    public String getIssuerName() {
        return ISSUER_NAME;
    }

    @Override
    public JwtDecoder getJwtDecoder() {
        return oidcServerJwtDecoder();
    }

    /**
     * See JwtDecoders#withProviderConfiguration(Map, String)
     * <p>
     * Adjusted implementation to use preconfigured URLs instead of dynamic configuration
     */
    private static JwtDecoder oidcServerJwtDecoder() {
        OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefaultWithIssuer(ISSUER_NAME);
        RemoteJWKSet<SecurityContext> jwkSource = new RemoteJWKSet<>(url(JWK_SET_URI));
        Set<SignatureAlgorithm> signatureAlgorithms = getSignatureAlgorithms(jwkSource);
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI)
                .jwsAlgorithms((algs) -> algs.addAll(signatureAlgorithms)).build();
        jwtDecoder.setJwtValidator(jwtValidator);
        return jwtDecoder;
    }

    /**
     * Copied from package-private JwtDecoderProviderConfigurationUtils class.
     */
    private static Set<SignatureAlgorithm> getSignatureAlgorithms(JWKSource<SecurityContext> jwkSource) {
        JWKMatcher jwkMatcher = new JWKMatcher.Builder().publicOnly(true).keyUses(KeyUse.SIGNATURE, null)
                .keyTypes(KeyType.RSA, KeyType.EC).build();
        Set<JWSAlgorithm> jwsAlgorithms = new HashSet<>();
        try {
            List<? extends JWK> jwks = jwkSource.get(new JWKSelector(jwkMatcher), null);
            for (JWK jwk : jwks) {
                if (jwk.getAlgorithm() != null) {
                    JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(jwk.getAlgorithm().getName());
                    jwsAlgorithms.add(jwsAlgorithm);
                } else {
                    if (jwk.getKeyType() == KeyType.RSA) {
                        jwsAlgorithms.addAll(JWSAlgorithm.Family.RSA);
                    } else if (jwk.getKeyType() == KeyType.EC) {
                        jwsAlgorithms.addAll(JWSAlgorithm.Family.EC);
                    }
                }
            }
        } catch (KeySourceException ex) {
            throw new IllegalStateException(ex);
        }
        Set<SignatureAlgorithm> signatureAlgorithms = new HashSet<>();
        for (JWSAlgorithm jwsAlgorithm : jwsAlgorithms) {
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.from(jwsAlgorithm.getName());
            if (signatureAlgorithm != null) {
                signatureAlgorithms.add(signatureAlgorithm);
            }
        }
        Assert.notEmpty(signatureAlgorithms, "Failed to find any algorithms from the JWK set");
        return signatureAlgorithms;
    }

    /**
     * Copied from JwtDecoders#url(String).
     */
    private static URL url(String url) {
        try {
            return new URL(url);
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
