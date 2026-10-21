package com.snuxoll.keycloak.assurance;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ServiceLoader;

import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.protocol.ProtocolMapper;

class ServiceRegistrationTest {

    @Test
    void protocolMapperIsRegistered() {
        assertRegistered(ProtocolMapper.class, UpstreamAmrProtocolMapper.class);
    }

    @Test
    void identityProviderMapperIsRegistered() {
        assertRegistered(IdentityProviderMapper.class, UpstreamAmrIdentityProviderMapper.class);
    }

    @Test
    void conditionIsRegistered() {
        assertRegistered(AuthenticatorFactory.class, UpstreamMfaConditionalAuthenticatorFactory.class);
    }

    @Test
    void providerOverridesAreRegisteredInTheSocialSpi() {
        // Not the generic IdentityProvider SPI: IdP lookup searches that one first and would bypass order().
        assertRegistered(SocialIdentityProviderFactory.class, AssuranceGoogleIdentityProviderFactory.class);
        assertRegistered(SocialIdentityProviderFactory.class, AssuranceMicrosoftIdentityProviderFactory.class);
    }

    private static <T> void assertRegistered(Class<T> spi, Class<? extends T> impl) {
        boolean found = ServiceLoader.load(spi).stream().anyMatch(p -> p.type() == impl);
        assertTrue(found, impl.getSimpleName() + " missing from META-INF/services/" + spi.getName());
    }
}
