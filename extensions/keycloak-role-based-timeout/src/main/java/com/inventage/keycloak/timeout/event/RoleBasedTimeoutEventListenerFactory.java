package com.inventage.keycloak.timeout.event;

import org.keycloak.Config.Scope;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * {@link EventListenerProviderFactory} for {@link RoleBasedTimeoutEventListener}.
 */
public class RoleBasedTimeoutEventListenerFactory implements EventListenerProviderFactory {

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new RoleBasedTimeoutEventListener(session);
    }

    @Override
    public String getId() {
        return "role-based-timeout-listener";
    }

    @Override
    public void init(Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    /**
     * Default constructor.
     */
    public RoleBasedTimeoutEventListenerFactory() {
        // no-op
    }
}
