package com.snuxoll.keycloak.assurance.it;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.social.google.GoogleIdentityProvider;
import org.keycloak.social.google.GoogleIdentityProviderConfig;

import com.snuxoll.keycloak.assurance.AssuranceGoogleIdentityProvider;
import com.snuxoll.keycloak.assurance.AssuranceGoogleIdentityProviderFactory;

/** Test-only: the production Google override, pointed at the upstream test realm. */
public class ItGoogleIdentityProviderFactory extends AssuranceGoogleIdentityProviderFactory {

    public static final String PROVIDER_ID = "google-it";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public GoogleIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        Map<String, String> itConfig = new HashMap<>(model.getConfig());
        GoogleIdentityProviderConfig config = new GoogleIdentityProviderConfig(model);
        AssuranceGoogleIdentityProvider provider = new AssuranceGoogleIdentityProvider(session, config);
        ItEndpoints.apply(config, itConfig);
        return provider;
    }
}
