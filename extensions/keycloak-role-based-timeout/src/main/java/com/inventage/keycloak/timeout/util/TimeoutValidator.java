package com.inventage.keycloak.timeout.util;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;

import java.util.AbstractMap.SimpleEntry;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Stream;

import static java.lang.Integer.MAX_VALUE;
import static java.lang.Integer.parseInt;
import static java.util.Arrays.stream;
import static java.util.Collections.emptyMap;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.Stream.empty;

/**
 * Util class to parse the timeout configuration and check whether a timeout was reached.
 */
public class TimeoutValidator {

    private static final Logger logger = Logger.getLogger(TimeoutValidator.class);

    /**
     * Helper to parse the Keycloak "##" delimited config string into a Map.
     *
     * @param config the config.
     * @param key the config key to parse.
     * @return the role to timeout map.
     */
    public static Map<String, Integer> parseConfig(Map<String, String> config, String key) {
        try {
            final String value = config.get(key);
            if (value == null || value.isBlank()) {
                return emptyMap();
            }
            return stream(value.split("##"))
                    .map(s -> s.split(":", 2))
                    .filter(a -> a.length == 2 && !a[0].isBlank() && !a[1].isBlank())
                    .flatMap(a -> {
                        try {
                            String roleName = a[0].trim();
                            Integer timeout = parseInt(a[1].trim());
                            return Stream.of(new SimpleEntry<>(roleName, timeout));
                        } catch (NumberFormatException e) {
                            logger.warnf("Invalid number format for role '%s' in config key %s. Ignoring.", a[0], key);
                            return empty(); // Discards only this malformed segment
                        }
                    })
                    .collect(toMap(Entry::getKey, Entry::getValue,
                            (existing, replacement) -> existing)); // Handles duplicate roles by keeping the first
        }
        catch (Exception e) {
            logger.warnf(e, "Unexpected error parsing config key %s. Falling back to empty map.", key);
            return emptyMap();
        }
    }

    /**
     * Determines if the current activity duration exceeds the user's role-based limit.
     *
     * @param user             the user.
     * @param iat              the latest known session token iat as epoch timestamp defining the latest user activity.
     * @param currentTime      the current time as epoch timestamp.
     * @param idleTimeouts     the map of roles to idle timeouts in seconds.
     * @param maxTimeouts      the map of roles to max timeouts in seconds.
     * @param sessionStartedAt session started at as epoch timestamp.
     * @return whether the user should be logged based on timeout limits.
     */
    public static boolean isTimeoutReached(UserModel user, long iat, int currentTime,
                                           Map<String /* role */, Integer> idleTimeouts,
                                           Map<String /* role */, Integer> maxTimeouts,
                                           int sessionStartedAt) {

        final int userIdleLimit = resolveMinTimeout(user, idleTimeouts);
        final int userMaxLimit = resolveMinTimeout(user, maxTimeouts);

        // Max Session Check
        if (userMaxLimit != MAX_VALUE) {
            final int absoluteAge = currentTime - sessionStartedAt;
            if (absoluteAge > userMaxLimit) {
                logger.infof("Role based max session limit of %ds exceeded for user '%s' (Age: %ds). Terminating.",
                        userMaxLimit, user.getUsername(), absoluteAge);
                return true;
            }
        }

        // Idle Check
        if (userIdleLimit != MAX_VALUE) {
            final long idleTime;
            if (iat <= 0) {
                idleTime = currentTime - sessionStartedAt;
            }
            else {
                idleTime = currentTime - iat;
            }
            if (idleTime > userIdleLimit) {
                logger.infof("Idle limit (%ds) reached for user '%s' (Idle: %ds).",
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
     * Helper to find the shortest timeout among the user's roles.
     *
     * @param user the user model.
     * @param timeouts the role to timeout map.
     * @return the timeout or fallback to max value.
     */
    private static int resolveMinTimeout(UserModel user, Map<String, Integer> timeouts) {
        if (timeouts.isEmpty()) return MAX_VALUE;
        return user.getRoleMappingsStream()
                .map(role -> {
                    if (role.getContainer() instanceof ClientModel client)
                        return client.getClientId() + "/" + role.getName();
                    return role.getName();
                })
                .filter(timeouts::containsKey)
                .mapToInt(timeouts::get).min().orElse(MAX_VALUE);
    }

    private TimeoutValidator() {
        // no-op
    }
}
