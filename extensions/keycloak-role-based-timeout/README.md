Keycloak role based session timeout extension
===

The keycloak-role-based-timeout extension allows configuring lower session timeout for users with specified roles.

To install the extension add the jar to the Keycloak server:

```shell
cp target/keycloak-role-based-timeout-<VERSION>.jar <KEYCLOAK_HOME>/providers/
```

Upon successful installation the authenticator "Role Based Session Timeout" (`role-based-timeout-authenticator`) is available.

Configuration
---

The following snippet is an excerpt of a `realm.json` file using the new authenticator.

```json
{
    "authenticationFlows": [
        {
            "alias": "browser-sms Browser - Conditional SMS",
            "description": "Flow to determine if the SMS is required for the authentication",
            "providerId": "basic-flow",
            "topLevel": false,
            "builtIn": false,
            "authenticationExecutions": [
                {
                    "authenticator": "conditional-user-configured",
                    "authenticatorFlow": false,
                    "requirement": "REQUIRED",
                    "priority": 10,
                    "autheticatorFlow": false,
                    "userSetupAllowed": false
                },
                {
                    "authenticator": "sms-authenticator",
                    "authenticatorConfig": "sms-authenticator",
                    "authenticatorFlow": false,
                    "requirement": "REQUIRED",
                    "priority": 20,
                    "autheticatorFlow": false,
                    "userSetupAllowed": false
                }
            ]
        }
    ],
    "authenticatorConfig": [
        {
            "alias": "sms-authenticator",
            "config": {
                "sms-service-provider-id": "uniport-sms-service",
                "sms-code-ttl": "60",
                "sms-code-length": "4", 
                "sms-show-phone-number": false
      }
    }
  ]
}
```
