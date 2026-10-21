# keycloak-upstream-mfa

Keycloak extensions for trusting MFA performed at an upstream identity provider.

When a user signs in through a brokered IdP such as Google or Microsoft Entra ID and already
completed MFA there, Keycloak normally can't tell, so it asks for its own second factor anyway.
This project reads the upstream IdP's `amr` (Authentication Methods References) claim, lets a
post-broker-login flow skip local MFA when the upstream methods meet a configurable bar, and
carries the upstream methods through to the `amr` claim in Keycloak's own tokens.

> **Status:** early development. Only the protocol mapper is scaffolded so far.

## Components

| Component | Provider id | Status |
|---|---|---|
| Protocol mapper: emits `amr` merging local and upstream methods | `upstream-mfa-amr-mapper` | Scaffolded |
| IdP mapper: copies the upstream ID token's `amr` into a user-session note | `upstream-mfa-idp-mapper` | Planned |
| Conditional authenticator: matches upstream `amr` against an allowed list | `upstream-mfa-condition` | Planned |
| Google provider override: requests the `amr` claim from Google | `google` | Planned |
| Microsoft provider override: validates Entra's ID token and keeps existing account links | `microsoft` | Planned |

The two provider overrides replace Keycloak's built-in `google` and `microsoft` social
providers under the same ids. That way existing IdP configurations and linked accounts keep
working. They depend on Keycloak internals and must be rechecked on every Keycloak upgrade.

## Requirements

- Keycloak 26.8.1
- Java 21, Maven

## Build

```sh
mvn package
```

The provider jar is written to `target/keycloak-upstream-mfa-<version>.jar`. To install it,
copy it into Keycloak's `providers/` directory and run `kc.sh build` (or restart in dev mode).

## Local Keycloak

```sh
mvn package
docker compose up
```

This starts Keycloak 26.8.1 in dev mode at <http://localhost:8080> (admin / admin) with the
built jar mounted as a provider.
