package com.inventage.keycloak.timeout.authentication;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

import static java.util.Collections.unmodifiableList;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED;

/**
 * {@link AuthenticatorFactory} for {@link RoleBasedTimeoutAuthenticator}.
 */
public class RoleBasedTimeoutAuthenticatorFactory implements AuthenticatorFactory {

    /** Provider ID. */
    public static final String PROVIDER_ID = "role-based-timeout-authenticator";
    /** idle timeout configuration name. */
    public static final String ROLE_IDLE_TIMEOUTS = "role-idle-timeouts";
    /** max timeout configuration name. */
    public static final String ROLE_MAX_TIMEOUTS = "role-max-timeouts";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        final List<ProviderConfigProperty> configProperties = new ArrayList<>();

        // 1. Idle Timeout Config
        final ProviderConfigProperty idleProp = new ProviderConfigProperty();
        idleProp.setName(ROLE_IDLE_TIMEOUTS);
        idleProp.setLabel("Role Based IDLE Timeouts");
        idleProp.setHelpText("Terminates session if user is inactive for X seconds. " +
                "Format: 'rolename:seconds' for realm roles or 'clientid/rolename:seconds' for client roles. " +
                "Example: 'admin:900' (15 min idle).");
        idleProp.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        configProperties.add(idleProp);

        // 2. Max Timeout Config
        final ProviderConfigProperty maxProp = new ProviderConfigProperty();
        maxProp.setName(ROLE_MAX_TIMEOUTS);
        maxProp.setLabel("Role Based MAX Timeouts");
        maxProp.setHelpText("Terminates session strictly after X seconds (Absolute limit). " +
                "Format: 'rolename:seconds' for realm roles or 'clientid/rolename:seconds' for client roles. " +
                "Example: 'temp-user:3600' (1 hour max).");
        maxProp.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        configProperties.add(maxProp);

        CONFIG_PROPERTIES = unmodifiableList(configProperties);
    }

    @Override
    public String getDisplayType() {
        return "Role Based Timeout Authenticator";
    }

    @Override
    public String getReferenceCategory() {
        return "Session Control";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
                REQUIRED,
                DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Enforces role-specific idle and max session timeouts.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new RoleBasedTimeoutAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * Default constructor.
     */
    public RoleBasedTimeoutAuthenticatorFactory() {
        // no-op
    }
}
