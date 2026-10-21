package com.snuxoll.keycloak.assurance;

import java.util.List;
import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Matches when the upstream IdP reported at least one of the allowed authentication methods.
 */
public class UpstreamMfaConditionalAuthenticator implements ConditionalAuthenticator {

    public static final UpstreamMfaConditionalAuthenticator SINGLETON = new UpstreamMfaConditionalAuthenticator();

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();
        Map<String, String> config = authConfig == null || authConfig.getConfig() == null
                ? Map.of() : authConfig.getConfig();

        String noteName = UpstreamAmr.configOrDefault(
                config.get(UpstreamMfaConditionalAuthenticatorFactory.CONF_NOTE), UpstreamAmr.DEFAULT_NOTE);
        List<String> allowed = UpstreamAmr.splitMultivalued(
                config.get(UpstreamMfaConditionalAuthenticatorFactory.CONF_ALLOWED));
        if (allowed.isEmpty()) {
            allowed = UpstreamMfaConditionalAuthenticatorFactory.DEFAULT_ALLOWED;
        }
        boolean negate = Boolean.parseBoolean(config.get(UpstreamMfaConditionalAuthenticatorFactory.CONF_NEGATE));

        // The IdP mapper writes to the auth session's user-session notes; they reach the user session later.
        List<String> upstream = UpstreamAmr.fromNote(context.getAuthenticationSession().getUserSessionNotes().get(noteName));
        return negate != matches(upstream, allowed);
    }

    /** Any-of: true when the upstream methods include at least one allowed value. */
    static boolean matches(List<String> upstream, List<String> allowed) {
        return upstream.stream().anyMatch(allowed::contains);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Not used
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Not used
    }

    @Override
    public void close() {
        // Does nothing
    }
}
