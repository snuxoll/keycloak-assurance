package com.snuxoll.keycloak.upstreammfa;

import java.io.IOException;
import java.util.Optional;

import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.validation.Validation;
import org.keycloak.social.microsoft.MicrosoftIdentityProviderConfig;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Microsoft Entra ID as a real OpenID Connect provider, so the validated ID token (and its {@code amr}) reaches
 * IdP mappers. The built-in Microsoft provider is plain OAuth2 with scope {@code User.read} and never sees an ID
 * token.
 *
 * <p>The federated identity is still keyed and populated from Microsoft Graph {@code /me}, exactly as the built-in
 * provider does it, so existing account links and user attribute mappers keep working unchanged.
 */
public class UpstreamMfaMicrosoftIdentityProvider extends OIDCIdentityProvider
        implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

    private static final String LOGIN_URL = "https://login.microsoftonline.com/%s";
    static final String GRAPH_PROFILE_URL = "https://graph.microsoft.com/v1.0/me/";
    static final String DEFAULT_SCOPE = "openid profile email User.Read";

    private static final String GRAPH_ID = "upstream-mfa.graph-id";

    public UpstreamMfaMicrosoftIdentityProvider(KeycloakSession session, MicrosoftIdentityProviderConfig config) {
        super(session, config);

        // Same tenant handling as the built-in provider: 'common' unless a tenant is configured.
        String tenant = Optional.ofNullable(config.getTenantId()).map(String::trim).orElse("common");
        String base = String.format(LOGIN_URL, tenant);

        config.setAuthorizationUrl(base + "/oauth2/v2.0/authorize");
        config.setTokenUrl(base + "/oauth2/v2.0/token");
        config.setJwksUrl(base + "/discovery/v2.0/keys");
        config.setUseJwksUrl(true);
        config.setValidateSignature(true);
        // Identity comes from Graph (see extractIdentity), not the OIDC userinfo endpoint.
        config.setDisableUserInfoService(true);
        // Multi-tenant issuers vary per tenant; validateToken checks them against tid instead.
        config.setIssuer(isMultiTenant(tenant) ? null : base + "/v2.0");
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    @Override
    protected JsonWebToken validateToken(String encodedToken, boolean ignoreAudience) {
        JsonWebToken token = super.validateToken(encodedToken, ignoreAudience);
        String issuer = getConfig().getIssuer();
        if (issuer == null || issuer.isBlank()) {
            validateMultiTenantIssuer(token);
        }
        return token;
    }

    /** A multi-tenant token must still be issued by the tenant it claims to come from. */
    static void validateMultiTenantIssuer(JsonWebToken token) {
        Object tid = token.getOtherClaims().get("tid");
        String expected = tid == null ? null : String.format(LOGIN_URL, tid) + "/v2.0";
        if (expected == null || !expected.equals(token.getIssuer())) {
            throw new IdentityBrokerException("Wrong issuer from token. Got: " + token.getIssuer()
                    + " expected: " + expected);
        }
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        BrokeredIdentityContext identity = super.getFederatedIdentity(response);
        // Re-key on the Graph id only now: OIDCIdentityProvider.getFederatedIdentity rejects an identity whose id
        // differs from the ID token's sub, right after extractIdentity returns.
        Object graphId = identity.getContextData().remove(GRAPH_ID);
        if (graphId != null) {
            identity.setId(graphId.toString());
            identity.setBrokerUserId(getConfig().getAlias() + "." + graphId);
        }
        return identity;
    }

    @Override
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken,
                                                      JsonWebToken idToken) throws IOException {
        // Keeps VALIDATED_ID_TOKEN, session id and token handling from the OIDC provider.
        BrokeredIdentityContext identity = super.extractIdentity(tokenResponse, accessToken, idToken);
        identity.getContextData().put(GRAPH_ID, applyProfile(identity, fetchProfile(accessToken, idToken)));
        return identity;
    }

    /** Microsoft Graph {@code /me}. Overridable for tests, which have no Graph to call. */
    protected JsonNode fetchProfile(String accessToken, JsonWebToken idToken) throws IOException {
        JsonNode profile = SimpleHttp.create(session).doGet(GRAPH_PROFILE_URL).auth(accessToken).asJson();
        if (profile.has("error") && !profile.get("error").isNull()) {
            throw new IdentityBrokerException("Error in Microsoft Graph API response. Payload: " + profile);
        }
        return profile;
    }

    /**
     * Mirrors the built-in MicrosoftIdentityProvider.extractIdentityFromProfile, except for the id, which is
     * returned for {@link #getFederatedIdentity} to apply.
     */
    String applyProfile(BrokeredIdentityContext identity, JsonNode profile) {
        String id = getJsonProperty(profile, "id");
        if (id == null) {
            throw new IdentityBrokerException("Microsoft Graph profile has no id");
        }

        String email = getJsonProperty(profile, "mail");
        if (email == null && profile.has("userPrincipalName")) {
            String upn = getJsonProperty(profile, "userPrincipalName");
            if (Validation.isEmailValid(upn)) {
                email = upn;
            }
        }
        identity.setUsername(email != null ? email : id);
        identity.setEmail(email);
        identity.setFirstName(getJsonProperty(profile, "givenName"));
        identity.setLastName(getJsonProperty(profile, "surname"));

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, profile, getConfig().getAlias());
        return id;
    }

    private static boolean isMultiTenant(String tenant) {
        return "common".equalsIgnoreCase(tenant)
                || "organizations".equalsIgnoreCase(tenant)
                || "consumers".equalsIgnoreCase(tenant);
    }
}
