package com.example.securitydemo;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
public class SecurityScenarioTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity()) // This is important to enable security testing
                .build();
    }

    /**
     * Demonstrates ability to access public resources without authenticating.
     * <p>
     * Note that there are no credentials provided at all.
     */
    @Test
    void allowsUnauthenticatedAccessToAPublicResource() throws Exception {
        mvc.perform(get("/public"))
                .andExpect(status().isOk())
                .andExpect(content().string("Public content"));
    }

    /**
     * Demonstrates that attempt to access protected resource without authentications
     * results in the 401 Unauthorized response.
     */
    @Test
    void deniesAccessToProtectedResourceToUnauthenticatedUsers() throws Exception {
        mvc.perform(get("/protected"))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Demonstrates ability to access protected resource when authenticated with
     * a JWT token issued by a private AS.
     * <p>
     * Note that the expected payload contains user id taken from the sub claim
     * of the token.
     */
    @Test
    void allowsAccessToProtectedResourceWithJWTIssuedByPrivateAuthServer() throws Exception {
        mvc.perform(get("/protected")
                        .header("Authorization", "Bearer " + testPrivateAuthServerToken("bob")))
                .andExpect(status().isOk())
                .andExpect(content().string("Protected content for bob"));
    }

    /**
     * Demonstrates that attempt to access protected resource with a bearer token
     * in a wrong format results in the 401 Unauthorized response.
     */
    @Test
    void deniesAccessToProtectedResourceWhenProvidedBearerTokenIsInWrongFormat() throws Exception {
        mvc.perform(get("/protected")
                        .header("Authorization", "Bearer " + "wrong-token"))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Demonstrates that the access to an admin-only resource is granted to authenticated
     * users with the ADMIN role. The role is derived from the sub claim of the token via lookup.
     * <p>
     * See {@link InMemorySubjectRolesResolver} for details of mapping from the subject to
     * roles. You might need to adjust this mapping if you use different subjects in tests.
     * <p>
     * Note that the expected payload contains user id taken from the sub claim of the token.
     */
    @Test
    void allowsAccessToAdminResourceBasedOnRoleMappedFromCustomASSubject() throws Exception {
        mvc.perform(get("/admin")
                        .header("Authorization", "Bearer " + testPrivateAuthServerToken("bob")))
                .andExpect(status().isForbidden());

        mvc.perform(get("/admin")
                        .header("Authorization", "Bearer " + testPrivateAuthServerToken("admin")))
                .andExpect(status().isOk())
                .andExpect(content().string("Admin only content for admin"));
    }

    /**
     * Demonstrates ability to access protected resource when authenticated with
     * a JWT token issued by a mock OIDC provider.
     * <p>
     * Note that the expected payload contains user id taken from the sub claim
     * of the token.
     */
    @Test
    void allowsAccessToProtectedResourceWithJWTIssuedByOIDCServer() throws Exception {
        String oidcSub = "dGVzdEBleGFtcGxlLmNvbQ=="; // It is a sub claim in the test JWT token
        mvc.perform(get("/protected")
                        .header("Authorization", "Bearer " + regularUserOIDCToken()))
                .andExpect(status().isOk())
                .andExpect(content().string("Protected content for " + oidcSub));
    }

    /**
     * Demonstrates that the access to an admin-only resource is granted to authenticated
     * users with the ADMIN role. The role is derived from the sub claim of the token via lookup.
     * <p>
     * See {@link InMemorySubjectRolesResolver} for details of mapping from the subject to
     * roles. You might need to adjust this mapping if you use different subjects in tests.
     * <p>
     * Note that the expected payload contains user id taken from the sub claim of the token.
     */
    @Test
    void allowsAccessToAdminResourceBasedOnRoleMappedFromOIDCSubject() throws Exception {
        String regularUserId = "dGVzdEBleGFtcGxlLmNvbQ=="; // It is a sub claim in the test JWT token
        String adminUserId = "YWRtaW5AZXhhbXBsZS5jb20="; // It is a sub claim in the test JWT token
        mvc.perform(get("/admin")
                        .header("Authorization", "Bearer " + regularUserOIDCToken()))
                .andExpect(status().isForbidden());

        mvc.perform(get("/admin")
                        .header("Authorization", "Bearer " + adminUserOIDCToken()))
                .andExpect(status().isOk())
                .andExpect(content().string("Admin only content for " + adminUserId));
    }

    /**
     * Helper method to generate JWT token that emulates custom Authorization Server scenario.
     */
    private String testPrivateAuthServerToken(String sub) {
        // Only sub and iss are important in this case
        String tokenPayloadJson = String.format("{\n"
                + "  \"sub\": \"%s\",\n"
                + "  \"iat\": 1516239022,\n"
                + "  \"iss\": \"%s\"\n"
                + "}", sub, PrivateServerJwtTokenIssuer.ISSUER_NAME);

        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256),
                new Payload(tokenPayloadJson));

        try {
            // We use the symmetrical key of our "Custom" AS to sign the token
            jwsObject.sign(new MACSigner(PrivateServerJwtTokenIssuer.PRIVATE_AUTH_SERVER_KEY));
        } catch (JOSEException e) {
            throw new RuntimeException("Unable to sign test token", e);
        }
        return jwsObject.serialize();
    }

    /**
     * Represents OIDC JWT token of a regular user. See README.md for the details
     * on how this token was generated
     */
    private String regularUserOIDCToken() {
        return "eyJraWQiOiJyTFU5S0pZd2dCbU5NVHJWNnd1Y2ZXbWlmcVdNZG4iLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJteWNsaWVudCIsInN1YiI6ImRHVnpkRUJsZUdGdGNHeGxMbU52YlE9PSIsImlzcyI6Imh0dHBzOi8vb2F1dGgubW9ja2xhYi5pbyIsImV4cCI6NDc5MzM1NDEyNCwiaWF0IjoxNjM5NzU0MTI0LCJhbGciOiJSUzI1NiIsIm5vbmNlIjoibnVsbCIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSJ9.Xun9198WVOw5xUB4EiaMNE0MLAjgx0gcX0yh_xxyG_eHZNSIG6D681sHMm74qPPzV9ELlwvCelOgxGC1KVWe7fciF3OKNzWQ1GBoTTp6E0pRkJFhbOY2llP1MfCS0RV5SY0fBzpKuy6COfkcjtBrSjed8lRp1CZdY9AHNheRmXKn2LvzTxc306Fz53HwEPXsEUDNFHY6Eo6I2bwOPPgyaMzCE0QfLg3xx0qQp_Ggf0PDWiZ7BoHCyE0OqLZWxm-ZvuseyeJnMatjcfGrbOWn2ykzozXuDiyRIGxz9htCJgUP3IF6maFV0Z00FTIHQwdkI00_1JdY7-qgEo_X5ZyGkQ";
    }

    /**
     * Represents OIDC JWT token of an admin user. See README.md for the details
     * on how this token was generated
     */
    private String adminUserOIDCToken() {
        return "eyJraWQiOiJyTFU5S0pZd2dCbU5NVHJWNnd1Y2ZXbWlmcVdNZG4iLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJteWNsaWVudCIsInN1YiI6IllXUnRhVzVBWlhoaGJYQnNaUzVqYjIwPSIsImlzcyI6Imh0dHBzOi8vb2F1dGgubW9ja2xhYi5pbyIsImV4cCI6NDc5MzM3MTc4NiwiaWF0IjoxNjM5NzcxNzg2LCJhbGciOiJSUzI1NiIsIm5vbmNlIjoibnVsbCIsImVtYWlsIjoiYWRtaW5AZXhhbXBsZS5jb20ifQ.k9jojVIFvUQ0eSnIgiHNK7QKgI9y_rvJ-SbhLW2YtgsJZFynqbJMXWCZ89IYe4Yw-cfQE8fHJQ3iyOpPZvjmHkcOW2GC1E4Mcbos7y2nR3BiT05w9cywQ7v7UrySwC8WMQF_AS5xn2IA8w59qIL3Vfk7YO4QO1wXO4D96dd4zFhkOK9fHBCPRz5zx_NiLNLULX4AAU83FhlaFu0cKbaR60aJ90zk_Jaz4rPwLM0MXTmBYYtLGCKk2CkdGbfeHB2FTsUcZMcBGJPDKX4KDYBiNVtpl5nPn_4TR0aTDIKo8QyOhxt43e4U-brjD16YaC7Mn9TQLqwRioYc2YuK9SGqkQ";
    }

}
