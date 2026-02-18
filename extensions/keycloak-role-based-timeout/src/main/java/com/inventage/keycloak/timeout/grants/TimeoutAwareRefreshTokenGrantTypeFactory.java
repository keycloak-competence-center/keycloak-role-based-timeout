package com.inventage.keycloak.timeout.grants;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.RefreshTokenGrantTypeFactory;

/**
 * Custom implementation of {@link RefreshTokenGrantTypeFactory} to force using the
 * {@link TimeoutAwareRefreshTokenGrantType}.
 */
public class TimeoutAwareRefreshTokenGrantTypeFactory extends RefreshTokenGrantTypeFactory {

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new TimeoutAwareRefreshTokenGrantType();
    }

    @Override
    public int order() {
        return 1;
    }
}
