# Security Policy

## Reported Security issues

- Impersonation vulnerability

  reported by: Pierre Bogossian bogossian@mail.com, Nikifor Georgiev
  fixed version: 2.9.3

  Vulnerability inherited from louketo-proxy project. User could forge access token and in case he has access to valid
  refresh token of other person he can gain access to other person access token. This was caused by not explicitly calling
  validate signature method but by calling external library method which validates several properties at once but which doesn't do it in correct order.

  Deployments with any of these gogatekeeper flags enabled not affected:

    --enable-encrypted-token=true
    --store-url=<redis-url>
    --enable-idp-session-check=true

- CVE-2020-14359 keycloak-gatekeeper: gatekeeper bypass via cURL when using lower case HTTP headers

  fixed version: 1.4.0

  Inconsistency in EnableDefaultDeny option implementation, it applies default deny on all UPPERCASE HTTP METHODS, not lowercase, this can be workarounded for existing versions by explicitly listing all methods in different letter case (which is error prone and cumbersome). Fix was delivered in version 1.4.0

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
|  3.5.0   | :white_check_mark: |

## Reporting a Vulnerability

For security issues please email to pavol.ipoth@protonmail.com or direct message @p53 on discord
