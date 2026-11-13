@interface:passkey
Feature: Passkey and recovery key records (prism/identity/2)
  A Prism account is a set of keys named by kappa: passkeys on devices and
  recovery keys the owner keeps outside them. The registry stores the public
  halves after checking the ceremony or signature that added them, serves
  them to anyone, and cannot forge them: readers check every key ID and
  signature themselves.

  # Not tagged @status:enforced: tests/bdd.rs is not built by any Cargo
  # target in this workspace (see features/README.md). The same scenarios
  # run against the real server binary in
  # crates/kappa-server/tests/integration/passkey_http.rs.

  Scenario: a passkey registers, binds a device, reads back and is revoked
    Given a registry accepting the identity origin "http://localhost:8790"
    When a passkey registers with a challenge the registry issued
    And a second passkey registers with a bind assertion from the first
    Then both credentials resolve to records of the first key's account
    When the first key revokes the second
    Then the second credential answers 410 with error "revoked"

  Scenario: a recovery key brings an account to a new device
    Given a registry accepting the identity origin "http://localhost:8790"
    When a passkey registers with a challenge the registry issued
    And it adds a recovery key with a bind assertion
    And a passkey on a new device registers with a bind signature from the recovery key
    Then the new device's credential resolves to a record of the first key's account
    When the recovery key revokes the first key
    Then the first credential answers 410 with error "revoked"

  Scenario: a challenge registers once
    Given a registry accepting the identity origin "http://localhost:8790"
    When a passkey registers with a challenge the registry issued
    And another passkey registers with the same challenge
    Then the response status is 400 with error "challenge"

  Scenario: only identity origins write from a browser
    Given a registry accepting the identity origin "http://localhost:8790"
    When a page at "https://evil.example" posts to /passkey/challenge
    Then the response status is 403 with error "origin"
