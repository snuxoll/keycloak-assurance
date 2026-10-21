package com.snuxoll.keycloak.upstreammfa;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.JsonWebToken;

/**
 * Copies the upstream ID token's amr into a user-session note on every brokered login.
 */
public class UpstreamAmrIdentityProviderMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "upstream-mfa-idp-mapper";

    public static final String CONF_CLAIM = "claim";
    public static final String CONF_NOTE = "note";

    // Built-in social provider ids; the overrides in this project keep them.
    private static final String[] COMPATIBLE_PROVIDERS = {
            OIDCIdentityProviderFactory.PROVIDER_ID,
            KeycloakOIDCIdentityProviderFactory.PROVIDER_ID,
            "google",
            "microsoft",
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty claim = new ProviderConfigProperty();
        claim.setName(CONF_CLAIM);
        claim.setLabel("Claim");
        claim.setType(ProviderConfigProperty.STRING_TYPE);
        claim.setDefaultValue(UpstreamAmr.DEFAULT_CLAIM);
        claim.setHelpText("Claim in the upstream ID token that holds the authentication methods.");
        CONFIG_PROPERTIES.add(claim);

        ProviderConfigProperty note = new ProviderConfigProperty();
        note.setName(CONF_NOTE);
        note.setLabel("User session note");
        note.setType(ProviderConfigProperty.STRING_TYPE);
        note.setDefaultValue(UpstreamAmr.DEFAULT_NOTE);
        note.setHelpText("User session note to store the upstream methods in, as a JSON array.");
        CONFIG_PROPERTIES.add(note);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "User Session";
    }

    @Override
    public String getDisplayType() {
        return "Upstream AMR to session note";
    }

    @Override
    public String getHelpText() {
        return "Stores the amr claim from the upstream identity provider's validated ID token in a user session "
                + "note, for the upstream MFA condition and the upstream AMR protocol mapper.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        // Only writes session notes, never touches the user.
        return true;
    }

    // Runs on every broker callback, which covers returning users.
    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
                                            IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        storeNote(mapperModel, context);
    }

    // First-broker-login resets the auth session (AuthenticationProcessor.resetFlow), wiping the note written in
    // preprocessFederatedIdentity. Keycloak restores the brokered context afterwards and calls these hooks, so the
    // note is written again: importNewUser for a new user, updateBrokeredUser when linking an existing one (only
    // in sync modes that delegate to it; otherwise the linking login falls back to local MFA).
    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
                              IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        storeNote(mapperModel, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
                                   IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        storeNote(mapperModel, context);
    }

    private static void storeNote(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String claim = UpstreamAmr.configOrDefault(mapperModel.getConfig().get(CONF_CLAIM), UpstreamAmr.DEFAULT_CLAIM);
        String note = UpstreamAmr.configOrDefault(mapperModel.getConfig().get(CONF_NOTE), UpstreamAmr.DEFAULT_NOTE);

        List<String> amr = extract(context.getContextData().get(OIDCIdentityProvider.VALIDATED_ID_TOKEN), claim);
        if (!amr.isEmpty()) {
            context.setSessionNote(note, UpstreamAmr.toNote(amr));
        }
    }

    /** Only a validated ID token counts; userinfo and access tokens are never consulted. */
    static List<String> extract(Object validatedIdToken, String claim) {
        if (!(validatedIdToken instanceof JsonWebToken token) || token.getOtherClaims() == null) {
            return List.of();
        }
        return UpstreamAmr.fromClaim(token.getOtherClaims().get(claim));
    }
}
