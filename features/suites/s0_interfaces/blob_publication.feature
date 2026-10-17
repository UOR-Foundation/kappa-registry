@interface:http-api @status:pending
Feature: Durable blob publication through the registry application
  Scenario: Acknowledged multichunk content survives process termination
    Given a fresh registry application
    When I upload a verified multichunk blob through HTTP
    And the registry process is killed and restarted with the same store
    Then the published blob and its range are exact through HTTP
