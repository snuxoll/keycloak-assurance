package com.snuxoll.keycloak.upstreammfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.social.google.GoogleIdentityProviderFactory;
import org.keycloak.social.microsoft.MicrosoftIdentityProviderFactory;

class ProviderOverrideFactoriesTest {

    @Test
    void googleOverrideTakesTheBuiltInId() {
        UpstreamMfaGoogleIdentityProviderFactory factory = new UpstreamMfaGoogleIdentityProviderFactory();
        assertEquals(GoogleIdentityProviderFactory.PROVIDER_ID, factory.getId());
        assertTrue(factory.order() > new GoogleIdentityProviderFactory().order());
    }

    @Test
    void microsoftOverrideTakesTheBuiltInId() {
        UpstreamMfaMicrosoftIdentityProviderFactory factory = new UpstreamMfaMicrosoftIdentityProviderFactory();
        assertEquals(MicrosoftIdentityProviderFactory.PROVIDER_ID, factory.getId());
        assertEquals(new MicrosoftIdentityProviderFactory().getName(), factory.getName());
        assertTrue(factory.order() > new MicrosoftIdentityProviderFactory().order());
    }

    @Test
    void microsoftOverrideKeepsTheBuiltInAdminSettings() {
        // The admin console renders the winning factory's properties; existing fields must not disappear.
        assertEquals(names(new MicrosoftIdentityProviderFactory().getConfigProperties()),
                names(new UpstreamMfaMicrosoftIdentityProviderFactory().getConfigProperties()));
    }

    private static List<String> names(List<ProviderConfigProperty> properties) {
        return properties.stream().map(ProviderConfigProperty::getName).toList();
    }
}
