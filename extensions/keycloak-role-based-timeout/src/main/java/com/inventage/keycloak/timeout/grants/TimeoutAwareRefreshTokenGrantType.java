package com.inventage.keycloak.timeout.grants;

import com.inventage.keycloak.timeout.authentication.RoleBasedTimeoutAuthenticator;
import com.inventage.keycloak.timeout.authentication.RoleBasedTimeoutAuthenticatorFactory;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.Details;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.grants.RefreshTokenGrantType;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.CorsErrorResponseException;

import java.util.Map;
import java.util.stream.Stream;

import static com.inventage.keycloak.timeout.authentication.RoleBasedTimeoutAuthenticatorFactory.ROLE_IDLE_TIMEOUTS;
import static com.inventage.keycloak.timeout.authentication.RoleBasedTimeoutAuthenticatorFactory.ROLE_MAX_TIMEOUTS;
import static com.inventage.keycloak.timeout.util.TimeoutValidator.isTimeoutReached;
import static com.inventage.keycloak.timeout.util.TimeoutValidator.parseConfig;
import static org.jboss.logging.Logger.getLogger;
import static org.keycloak.common.util.Time.currentTime;
import static org.keycloak.events.Errors.SESSION_EXPIRED;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;

/**
 * Precedes the token refresh {@link RefreshTokenGrantType#process(Context)} to enforce role-based timeouts on the
 * back-channel.
 * This complements the {@link RoleBasedTimeoutAuthenticator} by catching activity from mobile apps,
 * SPAs, or other clients performing background refreshes.
 */
public class TimeoutAwareRefreshTokenGrantType extends RefreshTokenGrantType {

    private static final Logger logger = getLogger(TimeoutAwareRefreshTokenGrantType.class);

    @Override
    public Response process(Context context) {
        checkForRoleBasedTimeout(context);
        return super.process(context);
    }

    private void checkForRoleBasedTimeout(Context context) {
        final KeycloakSession session = context.getSession();

        try {
            final String refreshTokenString = session.getContext().getHttpRequest()
                    .getDecodedFormParameters().getFirst("refresh_token");

            // Fail-open: if not a refresh request, do nothing.
            if (refreshTokenString == null) {
                return;
            }

            final JWSInput input = new JWSInput(refreshTokenString);
            final AccessToken token = input.readJsonContent(AccessToken.class);

            final RealmModel realm = session.getContext().getRealm();
            final UserSessionModel userSession = session.sessions().getUserSession(realm, token.getSessionId());
            if (userSession == null) {
                return;
            }
            final UserModel user = userSession.getUser();

            if (session.getContext().getHttpRequest() == null) {
                return;
            }

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
                context.getSession().sessions().removeUserSession(context.getRealm(), userSession);

                context.getEvent()
                        .detail(Details.REASON, "role_based_timeout")
                        .user(userSession.getUser())
                        .error(SESSION_EXPIRED);

                throw new CorsErrorResponseException(
                        context.getCors(),
                        OAuthErrorException.INVALID_GRANT,
                        "Session expired due to role-based timeout",
                        Response.Status.BAD_REQUEST
                );
            }
        }
        catch (Exception e) {
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
                .filter(config -> config != null && !config.isEmpty());
    }

}
