Keycloak role based session timeout extension
===

The keycloak-role-based-timeout extension allows configuring lower session timeout for users with specified roles as authentication step for browser flows and hooks into the refresh token grant process to apply the timeouts also there.

Both components are "fail-open"; if a configuration error occurs, it will allow the refresh or authentication step to proceed rather than locking users out.

If a timeout does happen during an authentication flow, the info page is called with `info` set to message key `ext.admin.session.keycloak` with attribute `ext_roleBasedTimeout` set to `true`. 
This allows for showing the info page with the default message `For your security, your session has ended. Please log in again to continue.`, a custom message or using the attribute to handle the page specially in a custom info template.

### Installation

To install the extension, add the jar to the Keycloak server's `providers` directory.

#### Prerequisites

- Java 21 or later (only needed when building from source)

#### From Maven Central

The extension is published to Maven Central. Download the jar directly:

```shell
curl -O https://repo.maven.apache.org/maven2/com/inventage/keycloak/role-based-timeout/keycloak-role-based-timeout/<VERSION>/keycloak-role-based-timeout-<VERSION>.jar
```

Or add it as a dependency in your build:

```xml
<dependency>
    <groupId>com.inventage.keycloak.role-based-timeout</groupId>
    <artifactId>keycloak-role-based-timeout</artifactId>
    <version>VERSION</version>
</dependency>
```

Copy the jar to the Keycloak providers directory:

```shell
cp keycloak-role-based-timeout-<VERSION>.jar <KEYCLOAK_HOME>/providers/
```

#### Building from source

Clone the repository and build the extension module using the included Maven wrapper:

```shell
./mvnw clean package -pl extensions/keycloak-role-based-timeout -am
```

This builds the jar at `extensions/keycloak-role-based-timeout/target/keycloak-role-based-timeout-<VERSION>.jar`. Copy it to the Keycloak providers directory:

```shell
cp extensions/keycloak-role-based-timeout/target/keycloak-role-based-timeout-<VERSION>.jar <KEYCLOAK_HOME>/providers/
```

#### Docker

When building a custom Keycloak Docker image, copy the jar into the providers directory in your Dockerfile:

```dockerfile
COPY keycloak-role-based-timeout-<VERSION>.jar /opt/keycloak/providers/
```

After adding the provider, rebuild Keycloak to pick up the extension:

```shell
/opt/keycloak/bin/kc.sh build
```

Upon successful installation the authenticator "Role Based Timeout Authenticator" (`role-based-timeout-authenticator`) is available.
The authenticator step can be configured and the access token refresh uses the authenticator configuration. In case of multiple authenticator configurations for the realm, all are applied for the token refresh (thus the most restrictive configuration is used). Note, configurations from disabled authenticators are ignored.

### Setup of the authenticator step
1. Navigate to **Authentication** -> the flow used by **Browser flow** in the Admin Console.
2. Create a basic flow subflow with requirement "ALTERNATIVE" replacing the "Cookie" execution step.
3. Add the Cookie authenticator as first step in the subflow as "REQUIRED"
4. Add the Role Based Timeout Authenticator as second step in the subflow as "REQUIRED".
5. Configure the role based timeout authenticator step. The format for roles and timeouts is 'rolename:seconds' for realm roles or 'clientid/rolename:seconds' for client roles.

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
        "role-idle-timeouts": "offline_access:30##account/view-consent:40",
        "role-max-timeouts": "account/delete-account:120"
      }
    }
  ]
}
```

