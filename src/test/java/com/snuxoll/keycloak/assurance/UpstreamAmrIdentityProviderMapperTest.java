package com.snuxoll.keycloak.assurance;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

class UpstreamAmrIdentityProviderMapperTest {

    @Test
    void readsClaimFromValidatedIdToken() {
        IDToken token = new IDToken();
        token.setOtherClaims("amr", List.of("pwd", "mfa"));
        assertEquals(List.of("pwd", "mfa"), UpstreamAmrIdentityProviderMapper.extract(token, "amr"));
    }

    @Test
    void honoursConfiguredClaimName() {
        IDToken token = new IDToken();
        token.setOtherClaims("amr", List.of("pwd"));
        token.setOtherClaims("methods", List.of("hwk"));
        assertEquals(List.of("hwk"), UpstreamAmrIdentityProviderMapper.extract(token, "methods"));
    }

    @Test
    void missingTokenOrClaimIsEmpty() {
        assertEquals(List.of(), UpstreamAmrIdentityProviderMapper.extract(null, "amr"));
        assertEquals(List.of(), UpstreamAmrIdentityProviderMapper.extract(new IDToken(), "amr"));
    }

    @Test
    void ignoresAnythingButAToken() {
        // e.g. a raw claims map someone else put in the context data
        assertEquals(List.of(), UpstreamAmrIdentityProviderMapper.extract(Map.of("amr", List.of("mfa")), "amr"));
    }

    @Test
    void anyJsonWebTokenSubtypeWorks() {
        AccessToken token = new AccessToken();
        token.setOtherClaims("amr", "mfa");
        assertEquals(List.of("mfa"), UpstreamAmrIdentityProviderMapper.extract(token, "amr"));
    }
}
