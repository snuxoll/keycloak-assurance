package com.snuxoll.keycloak.upstreammfa;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class UpstreamAmrTest {

    @Test
    void noteRoundTrips() {
        List<String> amr = List.of("pwd", "mfa");
        assertEquals(amr, UpstreamAmr.fromNote(UpstreamAmr.toNote(amr)));
    }

    @Test
    void missingOrMalformedNoteIsEmpty() {
        assertEquals(List.of(), UpstreamAmr.fromNote(null));
        assertEquals(List.of(), UpstreamAmr.fromNote(""));
        assertEquals(List.of(), UpstreamAmr.fromNote("not json"));
        assertEquals(List.of(), UpstreamAmr.fromNote("{\"amr\":[\"mfa\"]}"));
        assertEquals(List.of(), UpstreamAmr.fromNote("null"));
    }

    @Test
    void noteDropsBlankValues() {
        assertEquals(List.of("mfa"), UpstreamAmr.fromNote("[\"\", \"mfa\", null]"));
    }

    @Test
    void claimAcceptsArrayOrString() {
        assertEquals(List.of("pwd", "mfa"), UpstreamAmr.fromClaim(List.of("pwd", "mfa")));
        assertEquals(List.of("mfa"), UpstreamAmr.fromClaim("mfa"));
    }

    @Test
    void claimIgnoresOtherShapes() {
        assertEquals(List.of(), UpstreamAmr.fromClaim(null));
        assertEquals(List.of(), UpstreamAmr.fromClaim(42));
        assertEquals(List.of(), UpstreamAmr.fromClaim(Map.of("mfa", true)));
        assertEquals(List.of("mfa"), UpstreamAmr.fromClaim(Arrays.asList(1, "mfa", null, "")));
    }

    @Test
    void mergeKeepsLocalFirstAndDedupes() {
        assertEquals(List.of("otp", "pwd", "mfa"),
                UpstreamAmr.merge(List.of("otp", "pwd"), List.of("pwd", "mfa")));
        assertEquals(List.of("mfa"), UpstreamAmr.merge(List.of(), List.of("mfa")));
        assertEquals(List.of("otp"), UpstreamAmr.merge(List.of("otp"), List.of()));
    }

    @Test
    void splitsMultivaluedConfig() {
        assertEquals(List.of("mfa", "hwk"), UpstreamAmr.splitMultivalued("mfa##hwk"));
        assertEquals(List.of("mfa"), UpstreamAmr.splitMultivalued(" mfa ##"));
        assertEquals(List.of(), UpstreamAmr.splitMultivalued(null));
    }
}
