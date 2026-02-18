package com.inventage.keycloak.timeout.event;

import com.inventage.keycloak.timeout.authentication.RoleBasedTimeoutAuthenticatorFactory;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessToken;

import java.util.Map;
import java.util.stream.Stream;

import static com.inventage.keycloak.timeout.authentication.RoleBasedTimeoutAuthenticatorFactory.ROLE_IDLE_TIMEOUTS;
import static com.inventage.keycloak.timeout.authentication.RoleBasedTimeoutAuthenticatorFactory.ROLE_MAX_TIMEOUTS;
import static com.inventage.keycloak.timeout.util.TimeoutValidator.isTimeoutReached;
import static com.inventage.keycloak.timeout.util.TimeoutValidator.parseConfig;
import static org.jboss.logging.Logger.getLogger;
import static org.keycloak.common.util.Time.currentTime;
import static org.keycloak.events.EventType.REFRESH_TOKEN;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;

/**
 * Monitors token refresh events to enforce role-based timeouts on the back-channel.
 * This complements the Browser Authenticator by catching activity from mobile apps,
 * SPAs, or other clients performing background refreshes.
 */
public class RoleBasedTimeoutEventListener implements EventListenerProvider {

    private static final Logger logger = getLogger(RoleBasedTimeoutEventListener.class);

    private final KeycloakSession session;

    /**
     * Constructor.
     *
     * @param session the keycloak session.
     */
    public RoleBasedTimeoutEventListener(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        // We only care about token refreshes
        if (REFRESH_TOKEN.equals(event.getType())) {
            processRefresh(event);
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
    }

    private void processRefresh(Event event) {
        try {
            final RealmModel realm = session.getContext().getRealm();
            final UserSessionModel userSession = session.sessions().getUserSession(realm, event.getSessionId());
            if (userSession == null) {
                return;
            }
            final UserModel user = userSession.getUser();

            if (session.getContext().getHttpRequest() == null) {
                return;
            }
            final String refreshTokenString = session.getContext().getHttpRequest()
                    .getDecodedFormParameters().getFirst("refresh_token");

            // Fail-open: if not a refresh request, do nothing.
            if (refreshTokenString == null) {
                return;
            }

            final JWSInput input = new JWSInput(refreshTokenString);
            final AccessToken token = input.readJsonContent(AccessToken.class);

            boolean shouldLogout = getAllRelevantConfigs(realm)
                    .anyMatch(rawConfig -> isTimeoutReached(
                            user,
                            token.getIat(),
                            currentTime(),
                            parseConfig(rawConfig, ROLE_IDLE_TIMEOUTS),
                            parseConfig(rawConfig, ROLE_MAX_TIMEOUTS),
                            userSession.getStarted()));

            if (shouldLogout) {
                logger.debugf(
                        "Role-based timeout triggered for user '%s' after refresh. Terminating session %s.",
                        user.getUsername(), userSession.getId());
                session.sessions().removeUserSession(realm, userSession);
            }
        } catch (Exception e) {
            logger.warn("Failed to check timeout during refresh event", e);
        }
    }

    private Stream<Map<String, String>> getAllRelevantConfigs(RealmModel realm) {
        return realm.getAuthenticatorConfigsStream()
                // We check if this config belongs to an execution that uses our Authenticator
                // This requires looking up the execution associated with the config
                .filter(config -> realm.getAuthenticationFlowsStream()
                        .flatMap(flow -> realm.getAuthenticationExecutionsStream(flow.getId()))
                        .filter(exec -> !DISABLED.equals(exec.getRequirement()))
                        .anyMatch(exec -> config.getId().equals(exec.getAuthenticatorConfig())
                                && RoleBasedTimeoutAuthenticatorFactory.PROVIDER_ID.equals(exec.getAuthenticator())))
                .map(AuthenticatorConfigModel::getConfig)
                .filter(config -> config == null || config.isEmpty());
    }

    @Override
    public void close() {
    }
}
