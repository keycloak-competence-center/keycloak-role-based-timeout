package com.inventage.keycloak.timeout.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import java.util.Map;
import java.util.stream.Stream;

import static com.inventage.keycloak.timeout.util.TimeoutValidator.isTimeoutReached;
import static com.inventage.keycloak.timeout.util.TimeoutValidator.parseConfig;
import static java.util.Collections.emptyMap;
import static java.util.stream.Stream.of;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TimeoutValidatorTest {

    private UserModel user;
    private RoleModel adminRole;
    private RoleModel userRole;

    @BeforeEach
    void setUp() {
        user = mock(UserModel.class);
        adminRole = mock(RoleModel.class);
        userRole = mock(RoleModel.class);

        when(adminRole.getName()).thenReturn("admin");
        when(userRole.getName()).thenReturn("user");
    }

    @Test
    void testParseConfigValid() {
        final Map<String, String> config = Map.of("role-idle-timeouts", "admin:900##user:3600");
        final Map<String, Integer> parsed = parseConfig(config, "role-idle-timeouts");

        assertEquals(2, parsed.size());
        assertEquals(900, parsed.get("admin"));
        assertEquals(3600, parsed.get("user"));
    }

    @Test
    void testParseConfigMalformed() {
        // Test with invalid numbers and bad delimiters
        final Map<String, String> config = Map.of("role-idle-timeouts", "admin:abc##user:3600##bad-entry");
        final Map<String, Integer> parsed = parseConfig(config, "role-idle-timeouts");

        // Should ignore "admin:abc" due to NumberFormatException and "bad-entry" due to split length
        assertEquals(1, parsed.size());
        assertEquals(3600, parsed.get("user"));
    }

    @Test
    void testIdleTimeoutReached() {
        when(user.getRoleMappingsStream()).thenReturn(of(adminRole));
        final Map<String, Integer> idleTimeouts = Map.of("admin", 900);

        final int now = 10000;
        final int iat = now - 901; // 901 seconds ago (exceeds 900)

        final boolean result = isTimeoutReached(user, iat, now, idleTimeouts, emptyMap(), now - 1000);
        assertTrue(result, "Should trigger timeout as idle time (901s) is greater than limit (900s)");
    }

    @Test
    void testIdleTimeoutNotReached() {
        when(user.getRoleMappingsStream()).thenReturn(of(adminRole));
        final Map<String, Integer> idleTimeouts = Map.of("admin", 900);

        final int now = 10000;
        final int iat = now - 899; // 899 seconds ago (within 900)

        final boolean result = isTimeoutReached(user, iat, now, idleTimeouts, emptyMap(), now - 1000);
        assertFalse(result, "Should not trigger timeout as idle time (899s) is within limit (900s)");
    }

    @Test
    void testMaxTimeoutReached() {
        when(user.getRoleMappingsStream()).thenReturn(of(userRole));
        final Map<String, Integer> maxTimeouts = Map.of("user", 3600);

        final int now = 10000;
        final int sessionStart = now - 3601; // 3601 seconds ago (exceeds 3600)

        final boolean result = isTimeoutReached(user, now - 10, now, emptyMap(), maxTimeouts, sessionStart);
        assertTrue(result, "Should trigger timeout as absolute session age exceeds max limit");
    }

    @Test
    void testStrictestRoleResolution() {
        // User has both roles
        when(user.getRoleMappingsStream()).thenReturn(of(adminRole, userRole));

        // Admin is stricter (600s) than User (3600s)
        final Map<String, Integer> idleTimeouts = Map.of(
                "admin", 600,
                "user", 3600
        );

        final int now = 10000;
        final int iat = now - 700; // 700s idle. Valid for 'user' but should be caught by 'admin' limit.

        final boolean result = isTimeoutReached(user, iat, now, idleTimeouts, emptyMap(), now - 1000);
        assertTrue(result, "Should pick the strictest (minimum) timeout of all user roles");
    }

    @Test
    void testNoMatchingRolesFailOpen() {
        // User has a role not defined in config
        final RoleModel otherRole = mock(RoleModel.class);
        when(otherRole.getName()).thenReturn("guest");
        when(user.getRoleMappingsStream()).thenReturn(of(otherRole));

        final Map<String, Integer> idleTimeouts = Map.of("admin", 600);

        int now = 10000;
        int iat = now - 5000; // Long idle time

        final boolean result = isTimeoutReached(user, iat, now, idleTimeouts, emptyMap(), now - 6000);
        assertFalse(result, "Should fail-open and return false if user has no roles matching the config");
    }

    @Test
    void testZeroIatFallback() {
        // Tests the logic: if (iat <= 0) { idleTime = currentTime - sessionStartedAt; }
        when(user.getRoleMappingsStream()).thenReturn(of(adminRole));
        final Map<String, Integer> idleTimeouts = Map.of("admin", 500);

        final int now = 10000;
        final int sessionStart = now - 600;

        // Pass 0 as IAT (common if token/cookie is malformed or missing IAT)
        final boolean result = isTimeoutReached(user, 0, now, idleTimeouts, emptyMap(), sessionStart);
        assertTrue(result, "Should use session start time if IAT is 0 or missing");
    }

    @Test
    void testRoleFromGroupMembership() {
        final GroupModel managerGroup = mock(GroupModel.class);
        when(user.getRoleMappingsStream()).thenReturn(Stream.empty());
        when(user.getGroupsStream()).thenReturn(of(managerGroup));

        when(managerGroup.getRoleMappingsStream()).thenReturn(of(adminRole));

        // Config: Admin role has 500s timeout
        final Map<String, Integer> idleTimeouts = Map.of("admin", 500);
        final int now = 10000;

        // Idle for 600s
        final boolean result = isTimeoutReached(user, now - 600, now, idleTimeouts, emptyMap(), now - 1000);

        assertTrue(result, "Should catch timeout from role inherited via Group membership");
    }

    @Test
    void testRoleFromCompositeExpansion() {
        final RoleModel superRole = mock(RoleModel.class);
        when(superRole.getName()).thenReturn("super-role");
        when(superRole.isComposite()).thenReturn(true);

        when(user.getRoleMappingsStream()).thenReturn(Stream.of(superRole));
        when(superRole.getCompositesStream()).thenReturn(Stream.of(adminRole));

        final Map<String, Integer> idleTimeouts = Map.of("admin", 300);
        final int now = 10000;

        final boolean result = isTimeoutReached(user, now - 400, now, idleTimeouts, emptyMap(), now - 1000);

        assertTrue(result, "Should catch timeout from child role inside a composite");
    }

    @Test
    void testClientSpecificRoleTimeout() {
        final RoleModel clientRole = mock(RoleModel.class);
        final ClientModel client = mock(ClientModel.class);

        when(clientRole.getName()).thenReturn("editor");
        when(clientRole.isClientRole()).thenReturn(true);
        when(clientRole.getContainer()).thenReturn(client);
        when(client.getClientId()).thenReturn("my-app");

        when(user.getRoleMappingsStream()).thenReturn(Stream.of(clientRole));

        final Map<String, Integer> idleTimeouts = Map.of("my-app/editor", 120);
        final int now = 10000;

        // Idle for 150s
        final boolean result = isTimeoutReached(user, now - 150, now, idleTimeouts, emptyMap(), now - 1000);

        assertTrue(result, "Should resolve client-specific role using 'clientId/roleName' format");
    }

}
