package com.snuxoll.keycloak.assurance;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class UpstreamMfaConditionalAuthenticatorTest {

    @Test
    void matchesWhenAnyAllowedValuePresent() {
        assertTrue(UpstreamMfaConditionalAuthenticator.matches(List.of("pwd", "mfa"), List.of("mfa")));
        assertTrue(UpstreamMfaConditionalAuthenticator.matches(List.of("fido", "mfa"), List.of("hwk", "fido")));
    }

    @Test
    void doesNotMatchWithoutAllowedValue() {
        assertFalse(UpstreamMfaConditionalAuthenticator.matches(List.of("pwd"), List.of("mfa")));
        assertFalse(UpstreamMfaConditionalAuthenticator.matches(List.of("pwd", "mfa"), List.of("hwk", "fido")));
    }

    @Test
    void noUpstreamMethodsNeverMatches() {
        assertFalse(UpstreamMfaConditionalAuthenticator.matches(List.of(), List.of("mfa")));
    }
}
