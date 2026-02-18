Keycloak role based session timeout extension
===

The keycloak-role-based-timeout extension allows configuring lower session timeout for users with specified roles as authentication step for browser flows and hooks into the refresh token grant process to apply the timeouts also there.

Both components are "fail-open"; if a configuration error occurs, it will allow the refresh or authentication step to proceed rather than locking users out.

### Installation
To install the extension add the jar to the Keycloak server:

```shell
cp target/keycloak-role-based-timeout-<VERSION>.jar <KEYCLOAK_HOME>/providers/
```

Upon successful installation the authenticator "Role Based Timeout Authenticator" (`role-based-timeout-authenticator`) is available.
The authenticator step can be configured and the access token refresh uses the authenticator configuration. In case of multiple authenticator configurations for the realm, all are applied for the token refresh (thus the most restrictive configuration is used). Note, configurations from disabled authenticators are ignored.

### Setup of the authenticator step
1. Navigate to **Authentication** -> the flow used by **Browser flow** in the Admin Console.
2. Create a basic flow subflow with requirement "ALTERNATIVE" replacing the "Cookie" execution step.
3. Add the Cookie authenticator as first step in the subflow as "REQUIRED"
4. Add the Role Based Timeout Authenticator as second step in the subflow as "REQUIRED".
5. Configure the role based timeout authenticator step.

### Authenticator configuration

The following snippet is an excerpt of a `realm.json` file using the `role-based-timeout-authenticator` authenticator.

```json
{
  "authenticationFlows": [
    {
      "alias": "browser2",
      "description": "browser based authentication",
      "providerId": "basic-flow",
      "topLevel": true,
      "builtIn": false,
      "authenticationExecutions": [
        {
          "authenticatorFlow": true,
          "flowAlias": "cookie & timeout",
          "priority": 10,
          "requirement": "ALTERNATIVE",
          "userSetupAllowed": false
        },
        {
          "authenticator": "auth-spnego",
          "authenticatorFlow": false,
          "requirement": "DISABLED",
          "priority": 20,
          "userSetupAllowed": false
        },
        {
          "authenticator": "identity-provider-redirector",
          "authenticatorFlow": false,
          "requirement": "ALTERNATIVE",
          "priority": 25,
          "userSetupAllowed": false
        },
        {
          "authenticatorFlow": true,
          "requirement": "ALTERNATIVE",
          "priority": 30,
          "flowAlias": "browser2 forms",
          "userSetupAllowed": false
        }
      ]
    },
    {
      "alias": "cookie & timeout",
      "authenticationExecutions": [
        {
          "authenticator": "auth-cookie",
          "authenticatorFlow": false,
          "priority": 0,
          "requirement": "REQUIRED",
          "userSetupAllowed": false
        },
        {
          "authenticator": "role-based-timeout-authenticator",
          "authenticatorConfig": "browserflow session and idle timeout config",
          "authenticatorFlow": false,
          "priority": 1,
          "requirement": "REQUIRED",
          "userSetupAllowed": false
        }
      ],
      "builtIn": false,
      "description": "",
      "providerId": "basic-flow",
      "topLevel": false
    }
  ],
  "authenticatorConfig": [
    {
      "alias": "browserflow session and idle timeout config",
      "config": {
        "role-idle-timeouts": "offline_access:30",
        "role-max-timeouts": "account/delete-account:120"
      }
    }
  ]
}
```

