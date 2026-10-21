package com.snuxoll.keycloak.upstreammfa;

import java.util.List;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.social.microsoft.MicrosoftIdentityProviderConfig;
import org.keycloak.social.microsoft.MicrosoftIdentityProviderFactory;

/**
 * Replaces the built-in {@code microsoft} factory under the same id, so existing Microsoft IdPs keep their alias,
 * config and account links. Must be registered in the social SPI: IdP lookup searches the generic
 * IdentityProvider SPI first, and {@link #order()} only breaks ties within one SPI.
 */
public class UpstreamMfaMicrosoftIdentityProviderFactory
        extends AbstractIdentityProviderFactory<UpstreamMfaMicrosoftIdentityProvider>
        implements SocialIdentityProviderFactory<UpstreamMfaMicrosoftIdentityProvider> {

    static final int ORDER = 100;

    // The admin console renders this factory's properties for 'microsoft' IdPs, so they must match the built-in's.
    private static final MicrosoftIdentityProviderFactory BUILT_IN = new MicrosoftIdentityProviderFactory();

    @Override
    public String getId() {
        return MicrosoftIdentityProviderFactory.PROVIDER_ID;
    }

    @Override
    public String getName() {
        return BUILT_IN.getName();
    }

    @Override
    public UpstreamMfaMicrosoftIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new UpstreamMfaMicrosoftIdentityProvider(session, new MicrosoftIdentityProviderConfig(model));
    }

    @Override
    public MicrosoftIdentityProviderConfig createConfig() {
        return BUILT_IN.createConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return BUILT_IN.getConfigProperties();
    }

    @Override
    public int order() {
        return ORDER;
    }
}
