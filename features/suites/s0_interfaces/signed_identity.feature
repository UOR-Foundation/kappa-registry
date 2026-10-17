@interface:identity @status:implemented
Feature: Authenticated signed identity records
  Scenario: COSE admission and persisted revocation through the public HTTP boundary
    Given a fresh registry application
    When I exercise signed identity admission through HTTP
    And the registry process is killed and restarted with the same store
    Then signed identity resolution retains revocation and rejects forged subjects
