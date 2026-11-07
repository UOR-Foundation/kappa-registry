@interface:passkey
Feature: Passkey key records (prism/identity/1)
  A Prism account is a passkey. The registry stores the public half after
  checking the WebAuthn ceremony that made it, serves it to anyone, and
  cannot forge it: readers check every key ID and signature themselves.

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

  Scenario: a challenge registers once
    Given a registry accepting the identity origin "http://localhost:8790"
    When a passkey registers with a challenge the registry issued
    And another passkey registers with the same challenge
    Then the response status is 400 with error "challenge"

  Scenario: only identity origins write from a browser
    Given a registry accepting the identity origin "http://localhost:8790"
    When a page at "https://evil.example" posts to /passkey/challenge
    Then the response status is 403 with error "origin"
