package com.snuxoll.keycloak.upstreammfa.it;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.social.microsoft.MicrosoftIdentityProviderConfig;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.snuxoll.keycloak.upstreammfa.UpstreamMfaMicrosoftIdentityProvider;
import com.snuxoll.keycloak.upstreammfa.UpstreamMfaMicrosoftIdentityProviderFactory;

/**
 * Test-only: the production Microsoft override, pointed at the upstream test realm. There is no Graph to call,
 * so the Graph-shaped profile is built from ID token claims; the upstream asserts a {@code graph_id} that differs
 * from {@code sub}, to prove the federated identity is keyed on the Graph id.
 */
public class ItMicrosoftIdentityProviderFactory extends UpstreamMfaMicrosoftIdentityProviderFactory {

    public static final String PROVIDER_ID = "microsoft-it";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public UpstreamMfaMicrosoftIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        Map<String, String> itConfig = new HashMap<>(model.getConfig());
        MicrosoftIdentityProviderConfig config = new MicrosoftIdentityProviderConfig(model);
        UpstreamMfaMicrosoftIdentityProvider provider = new UpstreamMfaMicrosoftIdentityProvider(session, config) {
            @Override
            protected JsonNode fetchProfile(String accessToken, JsonWebToken idToken) {
                Map<String, Object> claims = idToken.getOtherClaims();
                ObjectNode profile = JsonNodeFactory.instance.objectNode();
                profile.put("id", (String) claims.get("graph_id"));
                profile.put("mail", (String) claims.get(IDToken.EMAIL));
                profile.put("userPrincipalName", (String) claims.get(IDToken.EMAIL));
                profile.put("givenName", (String) claims.get(IDToken.GIVEN_NAME));
                profile.put("surname", (String) claims.get(IDToken.FAMILY_NAME));
                return profile;
            }
        };
        ItEndpoints.apply(config, itConfig);
        return provider;
    }
}
