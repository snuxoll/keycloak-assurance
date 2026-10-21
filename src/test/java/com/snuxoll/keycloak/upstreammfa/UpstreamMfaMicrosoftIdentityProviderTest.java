package com.snuxoll.keycloak.upstreammfa;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.representations.IDToken;

class UpstreamMfaMicrosoftIdentityProviderTest {

    private static final String TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47";
    private static final String CONSUMERS = "9188040d-6c67-4c5b-b112-36a304b66dad";

    @Test
    void acceptsATokenFromTheTenantItNames() {
        assertDoesNotThrow(() -> UpstreamMfaMicrosoftIdentityProvider.validateMultiTenantIssuer(
                token(TENANT, "https://login.microsoftonline.com/" + TENANT + "/v2.0")));
        assertDoesNotThrow(() -> UpstreamMfaMicrosoftIdentityProvider.validateMultiTenantIssuer(
                token(CONSUMERS, "https://login.microsoftonline.com/" + CONSUMERS + "/v2.0")));
    }

    @Test
    void rejectsAnIssuerThatDoesNotMatchTid() {
        assertThrows(IdentityBrokerException.class, () -> UpstreamMfaMicrosoftIdentityProvider.validateMultiTenantIssuer(
                token(TENANT, "https://login.microsoftonline.com/" + CONSUMERS + "/v2.0")));
        assertThrows(IdentityBrokerException.class, () -> UpstreamMfaMicrosoftIdentityProvider.validateMultiTenantIssuer(
                token(TENANT, "https://evil.example/" + TENANT + "/v2.0")));
    }

    @Test
    void rejectsATokenWithoutTid() {
        assertThrows(IdentityBrokerException.class, () -> UpstreamMfaMicrosoftIdentityProvider.validateMultiTenantIssuer(
                token(null, "https://login.microsoftonline.com/" + TENANT + "/v2.0")));
    }

    private static IDToken token(String tid, String issuer) {
        IDToken token = new IDToken();
        token.issuer(issuer);
        if (tid != null) {
            token.setOtherClaims("tid", tid);
        }
        return token;
    }
}
