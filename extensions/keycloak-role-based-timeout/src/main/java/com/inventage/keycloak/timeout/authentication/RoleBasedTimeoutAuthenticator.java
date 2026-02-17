package com.inventage.keycloak.timeout.authentication;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.cookie.CookieProvider;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.AccessToken;

import java.util.Map;
import java.util.stream.Collectors;

import static com.inventage.keycloak.timeout.authentication.RoleBasedTimeoutAuthenticatorFactory.ROLE_IDLE_TIMEOUTS;
import static com.inventage.keycloak.timeout.authentication.RoleBasedTimeoutAuthenticatorFactory.ROLE_MAX_TIMEOUTS;
import static java.lang.Integer.MAX_VALUE;
import static java.lang.Integer.parseInt;
import static java.util.Arrays.stream;
import static java.util.Collections.emptyMap;
import static org.keycloak.cookie.CookieType.IDENTITY;

/**
 * Enforces role-specific session timeouts (Idle and Max) by inspecting the identity cookie.
 * <p>
 * Note, we cannot use {@link UserSessionModel#getLastSessionRefresh()}.
 * By the time this authenticator executes, Keycloak's internal {@code AuthenticationManager}
 * has already identified the user and updated the session's refresh timestamp in the
 * database to "now". This erases the history of the user's actual inactivity.
 * (Even at the cookie step it's too late already.) Thus, we decode the {@code KEYCLOAK_IDENTITY} cookie to read the
 * {@code iat} (Issued At) claim. This timestamp remains static until Keycloak explicitly issues a new cookie,
 * providing us an idle time for the user based on the last issued token.
 * </p>
 * This has the caveats of the idle time being regardless of other interactions with the Keycloak, like token exchanges
 */
public class RoleBasedTimeoutAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(RoleBasedTimeoutAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        final UserModel user = context.getUser();
        if (user == null) {
            context.attempted();
            return;
        }

        final AccessToken token = getIdentityToken(context);
        if (token == null) {
            context.attempted();
            return;
        }

        // Retrieve the user session from DB using the session id claim from the token.
        final UserSessionModel userSession = context.getSession().sessions()
                .getUserSession(context.getRealm(), token.getSessionId());

        if (userSession == null) {
            context.attempted();
            return;
        }

        if (shouldLogout(context, user, userSession, token)) {
            terminateSession(context, userSession);
        } else {
            context.success();
        }
    }

    private AccessToken getIdentityToken(AuthenticationFlowContext context) {
        final String cookieValue = context.getSession().getProvider(CookieProvider.class).get(IDENTITY);
        if (cookieValue == null) {
            return null;
        }

        try {
            final JWSInput input = new JWSInput(cookieValue);
            return input.readJsonContent(AccessToken.class);
        } catch (Exception e) {
            logger.warn("Failed to parse identity cookie for timeout check.", e);
            return null;
        }
    }

    private boolean shouldLogout(AuthenticationFlowContext context, UserModel user,
                                 UserSessionModel userSession, AccessToken token) {
        final AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();

        // Fail-safe: If no config at all, pass.
        if (configModel == null || configModel.getConfig() == null) {
            return false;
        }

        // Parse both configurations
        final Map<String, Integer> idleTimeouts = parseConfig(configModel.getConfig(), ROLE_IDLE_TIMEOUTS);
        final Map<String, Integer> maxTimeouts = parseConfig(configModel.getConfig(), ROLE_MAX_TIMEOUTS);

        if (idleTimeouts.isEmpty() && maxTimeouts.isEmpty()) {
            return false;
        }

        // Resolve limits for this user
        final int userIdleLimit = resolveMinTimeout(user, idleTimeouts);
        final int userMaxLimit = resolveMinTimeout(user, maxTimeouts);

        // If user has no relevant roles for either, just pass
        if (userIdleLimit == MAX_VALUE && userMaxLimit == MAX_VALUE) {
            return false;
        }

        final int currentTime = Time.currentTime();

        if (userMaxLimit != MAX_VALUE) {
            final int absoluteAge = currentTime - userSession.getStarted();

            if (absoluteAge > userMaxLimit) {
                logger.infof("Role based max session limit of %ds exceeded for user '%s' (Age: %ds). Terminating.",
                        userMaxLimit, user.getUsername(), absoluteAge);
                return true;
            }
        }

        // check idle timeout (based on cookie issuance timestamp)
        if (userIdleLimit != MAX_VALUE) {
            long tokenIat = token.getIat();
            if (tokenIat <= 0) {
                tokenIat = userSession.getStarted();
            }

            final long idleTime = currentTime - tokenIat;
            if (idleTime > userIdleLimit) {
                logger.infof("IDLE limit (%ds) reached for user '%s' (Idle: %ds).",
                        userIdleLimit, user.getUsername(), idleTime);
                return true;
            }
        }

        logger.debugf("User '%s' checks passed. MaxLimit: %s, IdleLimit: %s.",
                user.getUsername(),
                (userMaxLimit == MAX_VALUE ? "None" : userMaxLimit),
                (userIdleLimit == MAX_VALUE ? "None" : userIdleLimit));
        return false;
    }

    /**
     * Helper to parse the Keycloak "##" delimited config string into a Map.
     *
     * @param config the config.
     * @param key the config key to parse.
     * @return the role to timeout map.
     */
    private Map<String, Integer> parseConfig(Map<String, String> config, String key) {
        final String value = config.get(key);
        if (value == null || value.isBlank()) {
            return emptyMap();
        }
        try {
            return stream(value.split("##"))
                    .map(s -> s.split(":", 2))
                    .filter(a -> a.length == 2 && !a[0].isBlank() && !a[1].isBlank())
                    .collect(Collectors.toMap(
                            a -> a[0].trim(),
                            a -> parseInt(a[1].trim()),
                            (existing, replacement) -> existing
                    ));
        }
        catch (NumberFormatException e) {
            logger.warnf("Invalid format for config key %s. Ignoring.", key);
            return emptyMap();
        }
    }

    /**
     * Helper to find the shortest timeout among the user's roles.
     *
     * @param user the user model.
     * @param timeouts the role to timeout map.
     * @return the timeout or fallback to max value.
     */
    private int resolveMinTimeout(UserModel user, Map<String, Integer> timeouts) {
        if (timeouts.isEmpty()) {
            return MAX_VALUE;
        }
        return user.getRoleMappingsStream()
                .map(role -> {
                    if (role.getContainer() instanceof ClientModel client) {
                        return client.getClientId() + "/" + role.getName();
                    }
                    return role.getName();
                })
                .filter(timeouts::containsKey)
                .mapToInt(timeouts::get)
                .min()
                .orElse(MAX_VALUE);
    }

    private void terminateSession(AuthenticationFlowContext context, UserSessionModel userSession) {
        context.getSession().sessions().removeUserSession(context.getRealm(), userSession);

        // Show the Info Page
        final Response challenge = context.form()
                .setInfo("admin.session.timeout")
                .createInfoPage();
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // User clicked "Continue" on the Info Page -> Restart to get clean Login Form
        context.resetFlow();
    }

    @Override
    public boolean requiresUser() {
        return true; // We need the user object to check roles
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true; // can't be used, as we don't have the AuthenticationFlowContext that provides the configuration.
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
