package com.snuxoll.keycloak.upstreammfa.it;

import java.util.Map;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;

/**
 * Test-only: re-points a provider whose endpoints are hardcoded at the upstream test realm. The real values are
 * passed in the IdP config under {@code it.*} keys, because the provider constructors overwrite the standard ones.
 */
final class ItEndpoints {

    static final String AUTHORIZATION_URL = "it.authorizationUrl";
    static final String TOKEN_URL = "it.tokenUrl";
    static final String JWKS_URL = "it.jwksUrl";
    static final String ISSUER = "it.issuer";

    private ItEndpoints() {
    }

    static void apply(OIDCIdentityProviderConfig config, Map<String, String> itConfig) {
        config.setAuthorizationUrl(itConfig.get(AUTHORIZATION_URL));
        config.setTokenUrl(itConfig.get(TOKEN_URL));
        config.setJwksUrl(itConfig.get(JWKS_URL));
        config.setIssuer(itConfig.get(ISSUER));
        config.setUserInfoUrl(null);
        config.setDisableUserInfoService(true);
    }
}
