@interface:events
Feature: Registry event subscriptions
  Event subscriptions expose bounded replay and explicit resume contracts.

  Scenario: Malformed resume cursors are rejected at the HTTP boundary
    Given a fresh registry application
    When I subscribe with a malformed event cursor
    Then the event subscription rejects the cursor with status 400

  @interface:openapi
  Scenario: Event replay and resynchronization are documented
    Given a fresh registry application
    When I request the OpenAPI document
    Then the response status is 200
    And the document describes event resume and resynchronization
