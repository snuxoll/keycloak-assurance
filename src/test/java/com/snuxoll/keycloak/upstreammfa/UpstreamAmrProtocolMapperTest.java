package com.snuxoll.keycloak.upstreammfa;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ServiceLoader;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.ProtocolMapper;

class UpstreamAmrProtocolMapperTest {

    @Test
    void isRegisteredAsProtocolMapper() {
        boolean found = ServiceLoader.load(ProtocolMapper.class).stream()
                .anyMatch(p -> p.type() == UpstreamAmrProtocolMapper.class);
        assertTrue(found, "UpstreamAmrProtocolMapper missing from META-INF/services");
    }
}
