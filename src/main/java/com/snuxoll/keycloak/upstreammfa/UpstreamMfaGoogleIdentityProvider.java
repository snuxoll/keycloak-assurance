package com.snuxoll.keycloak.upstreammfa;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import jakarta.ws.rs.core.UriBuilder;

import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.social.google.GoogleIdentityProvider;
import org.keycloak.social.google.GoogleIdentityProviderConfig;

/**
 * Google, plus the {@code claims} request parameter Google requires on every auth request before it will put
 * {@code amr} and {@code auth_time} in the ID token.
 */
public class UpstreamMfaGoogleIdentityProvider extends GoogleIdentityProvider {

    static final String CLAIMS_PARAM = "claims";
    static final String CLAIMS_REQUEST =
            "{\"id_token\":{\"amr\":{\"essential\":true},\"auth_time\":{\"essential\":true}}}";

    public UpstreamMfaGoogleIdentityProvider(KeycloakSession session, GoogleIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        // Pre-encoded: the builder would read the JSON's braces as URI template variables.
        return super.createAuthorizationUrl(request)
                .queryParam(CLAIMS_PARAM, URLEncoder.encode(CLAIMS_REQUEST, StandardCharsets.UTF_8));
    }
}
