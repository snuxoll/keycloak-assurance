package com.snuxoll.keycloak.upstreammfa;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.social.google.GoogleIdentityProvider;
import org.keycloak.social.google.GoogleIdentityProviderConfig;
import org.keycloak.social.google.GoogleIdentityProviderFactory;

/**
 * Replaces the built-in {@code google} factory under the same id, so existing Google IdPs pick up
 * {@link UpstreamMfaGoogleIdentityProvider} without being recreated. Must be registered in the social SPI: IdP
 * lookup searches the generic IdentityProvider SPI first, and {@link #order()} only breaks ties within one SPI.
 */
public class UpstreamMfaGoogleIdentityProviderFactory extends GoogleIdentityProviderFactory {

    static final int ORDER = 100;

    @Override
    public GoogleIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new UpstreamMfaGoogleIdentityProvider(session, new GoogleIdentityProviderConfig(model));
    }

    @Override
    public int order() {
        return ORDER;
    }
}
