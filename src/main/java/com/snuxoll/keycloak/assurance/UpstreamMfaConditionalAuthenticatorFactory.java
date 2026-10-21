package com.snuxoll.keycloak.assurance;

import java.util.List;

import org.keycloak.Config.Scope;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class UpstreamMfaConditionalAuthenticatorFactory implements ConditionalAuthenticatorFactory {

    public static final String PROVIDER_ID = "assurance-upstream-mfa-condition";

    public static final String CONF_ALLOWED = "allowedAmr";
    public static final String CONF_NOTE = "note";
    public static final String CONF_NEGATE = "negate";

    static final List<String> DEFAULT_ALLOWED = List.of("mfa");

    private static final Requirement[] REQUIREMENT_CHOICES = {
            Requirement.REQUIRED,
            Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        ProviderConfigProperty allowed = new ProviderConfigProperty();
        allowed.setName(CONF_ALLOWED);
        allowed.setLabel("Allowed upstream methods");
        allowed.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        allowed.setDefaultValue(String.join(Constants.CFG_DELIMITER, DEFAULT_ALLOWED));
        allowed.setHelpText("Upstream amr values that satisfy this condition. Any one of them is enough. "
                + "For example 'mfa', or 'hwk', 'swk' and 'fido' for phishing-resistant methods only.");

        ProviderConfigProperty note = new ProviderConfigProperty();
        note.setName(CONF_NOTE);
        note.setLabel("User session note");
        note.setType(ProviderConfigProperty.STRING_TYPE);
        note.setDefaultValue(UpstreamAmr.DEFAULT_NOTE);
        note.setHelpText("User session note written by the 'Upstream AMR to session note' identity provider mapper.");

        ProviderConfigProperty negate = new ProviderConfigProperty();
        negate.setName(CONF_NEGATE);
        negate.setLabel("Negate output");
        negate.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        negate.setHelpText("Apply a NOT to the result. Turn this on to run the rest of the flow only when upstream "
                + "MFA is NOT satisfied, e.g. to skip local 2FA for users who already did MFA upstream.");

        CONFIG_PROPERTIES = List.of(allowed, note, negate);
    }

    @Override
    public void init(Scope config) {
        // no-op
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Condition - upstream MFA";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Flow is executed only if the upstream identity provider reported one of the allowed "
                + "authentication methods (amr).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public ConditionalAuthenticator getSingleton() {
        return UpstreamMfaConditionalAuthenticator.SINGLETON;
    }
}
