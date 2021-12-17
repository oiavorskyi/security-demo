package com.example.securitydemo;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.context.ApplicationContextException;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Provides decoder for tokens issued by custom Authorization Server.
 */
public class PrivateServerJwtTokenIssuer implements SupportedJwtTokenIssuer {
    // Use only for sample. In production scenarios it is better to
    // either use public key of the authorization server or jwkSetUri
    public static final SecretKey PRIVATE_AUTH_SERVER_KEY = new SecretKeySpec(randomKeyValue(), JwsAlgorithms.HS256);
    public static final String ISSUER_NAME = "https://private-server.local";

    @Override
    public String getIssuerName() {
        return ISSUER_NAME;
    }

    @Override
    public JwtDecoder getJwtDecoder() {
        return NimbusJwtDecoder.withSecretKey(PRIVATE_AUTH_SERVER_KEY)
                .build();
    }

    private static byte[] randomKeyValue() {
        // 256-bit key
        byte[] result = new byte[32];
        try {
            SecureRandom.getInstanceStrong().nextBytes(result);
        } catch (NoSuchAlgorithmException e) {
            throw new ApplicationContextException("Unable to generate private server key", e);
        }
        return result;
    }
}
