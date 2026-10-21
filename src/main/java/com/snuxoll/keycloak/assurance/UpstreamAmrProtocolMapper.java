package com.snuxoll.keycloak.assurance;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.OAuth2Constants;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AmrProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

// Derives from the built-in mapper so local AMR keeps its exact semantics (getAmr); we only add upstream values.
public class UpstreamAmrProtocolMapper extends AmrProtocolMapper
        implements UserInfoTokenMapper {

    // Keycloak ships its own "oidc-amr-mapper"; keep this ID distinct.
    public static final String PROVIDER_ID = "assurance-amr-mapper";

    public static final String CONF_NOTE = "note";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty note = new ProviderConfigProperty();
        note.setName(CONF_NOTE);
        note.setLabel("User session note");
        note.setType(ProviderConfigProperty.STRING_TYPE);
        note.setDefaultValue(UpstreamAmr.DEFAULT_NOTE);
        note.setHelpText("User session note written by the 'Upstream AMR to session note' identity provider mapper.");
        CONFIG_PROPERTIES.add(note);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, UpstreamAmrProtocolMapper.class);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "AMR Mapper (with upstream IdP)";
    }

    @Override
    public String getHelpText() {
        return "Populates the amr (Authentication Methods References) claim from completed local authenticators "
                + "and from the upstream identity provider's amr, when present.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        String noteName = UpstreamAmr.configOrDefault(mappingModel.getConfig().get(CONF_NOTE), UpstreamAmr.DEFAULT_NOTE);
        List<String> local = getAmr(clientSessionCtx.getClientSession(), userSession.getRealm());
        List<String> upstream = UpstreamAmr.fromNote(userSession.getNote(noteName));
        token.setOtherClaims(OAuth2Constants.AUTHENTICATOR_METHOD_REFERENCE, UpstreamAmr.merge(local, upstream));
    }
}
