# keycloak-upstream-mfa

Keycloak extensions for trusting MFA performed at an upstream identity provider.

When a user signs in through a brokered IdP such as Google or Microsoft Entra ID and already
completed MFA there, Keycloak normally can't tell, so it asks for its own second factor anyway.
This project reads the upstream IdP's `amr` (Authentication Methods References) claim, lets a
post-broker-login flow skip local MFA when the upstream methods meet a configurable bar, and
carries the upstream methods through to the `amr` claim in Keycloak's own tokens.

> **Status:** early development. The IdP mapper, condition and protocol mapper work end to end against a
> generic OIDC IdP. The Google and Microsoft provider overrides are not written yet.

## Components

| Component | Provider id | Status |
|---|---|---|
| Protocol mapper: emits `amr` merging local and upstream methods | `upstream-mfa-amr-mapper` | Done |
| IdP mapper: copies the upstream ID token's `amr` into a user-session note | `upstream-mfa-idp-mapper` | Done |
| Conditional authenticator: matches upstream `amr` against an allowed list | `upstream-mfa-condition` | Done |
| Google provider override: requests the `amr` claim from Google | `google` | Planned |
| Microsoft provider override: validates Entra's ID token and keeps existing account links | `microsoft` | Planned |

The two provider overrides replace Keycloak's built-in `google` and `microsoft` social
providers under the same ids. That way existing IdP configurations and linked accounts keep
working. They depend on Keycloak internals and must be rechecked on every Keycloak upgrade.

## Configuration

1. On each brokered IdP, add the **Upstream AMR to session note** mapper (`upstream-mfa-idp-mapper`).
2. In the IdP's post-login flow, wrap the local MFA steps in a conditional subflow gated by
   **Condition - upstream MFA** with *Negate output* on. Then add **Allow access** as a REQUIRED step after the
   subflow:

   ```
   post-broker-login
   ├─ Conditional subflow                       CONDITIONAL
   │  ├─ Condition - upstream MFA (negated)     REQUIRED
   │  └─ <local MFA steps>                      REQUIRED
   └─ Allow access                              REQUIRED
   ```

   You need the **Allow access** step. When the condition skips the subflow, Keycloak drops it, and a flow left
   with nothing to run fails with `invalid_user_credentials`.
3. On clients that should see upstream methods, use **AMR Mapper (with upstream IdP)**
   (`upstream-mfa-amr-mapper`) in place of the built-in AMR mapper.

The upstream note is missing on the login that links a brokered identity to an *existing* account, unless the
IdP's sync mode delegates to mappers on update. In that case the user gets local MFA, which is the safe fallback.

## Requirements

- Keycloak 26.8.1
- Java 21, Maven

## Build

```sh
mvn package
```

The provider jar is written to `target/keycloak-upstream-mfa-<version>.jar`. To install it,
copy it into Keycloak's `providers/` directory and run `kc.sh build` (or restart in dev mode).

## Tests

```sh
mvn test     # unit tests
mvn verify   # unit + integration tests (needs Docker or Podman)
```

The integration test (`UpstreamMfaIT`) starts Keycloak 26.8.1 with Testcontainers and two realms. `upstream`
stands in for the external IdP: one client asserts `amr: ["pwd","mfa"]` and another `["pwd"]`. `downstream`
brokers to it through generic OIDC IdPs that use this project's mapper, condition and post-broker flow. The test
drives the login over plain HTTP and checks that local OTP is skipped or required, and that the token's `amr`
carries the upstream values. Keycloak's container log is saved to `target/keycloak-it.log`.

## Local Keycloak

```sh
mvn package
docker compose up
```

This starts Keycloak 26.8.1 in dev mode at <http://localhost:8080> (admin / admin) with the
built jar mounted as a provider.
