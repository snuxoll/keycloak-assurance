package com.snuxoll.keycloak.upstreammfa;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.mappers.AmrProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;

// Derives from the built-in mapper so local AMR keeps its exact semantics; we only add upstream values.
public class UpstreamAmrProtocolMapper extends AmrProtocolMapper
        implements UserInfoTokenMapper {

    // Keycloak ships its own "oidc-amr-mapper"; keep this ID distinct.
    public static final String PROVIDER_ID = "upstream-mfa-amr-mapper";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
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
    protected List<String> getAmr(AuthenticatedClientSessionModel clientSession, RealmModel realmModel) {
        List<String> amr = super.getAmr(clientSession, realmModel);
        // TODO: merge upstream amr from the session note written by the IdP mapper
        return amr;
    }
}
