@interface:node-authority @status:pending
Feature: Node signing authority rotation and status
  An administrator rotates the node's signing authority and verifies which
  authority is current, which are retired, and that every guarantee
  completing the rotation holds, before and after a restart.

  Scenario: Rotations retire earlier authorities and survive a restart
    Given a fresh registry application
    When I read the node authority status as the root delegate
    Then the node signs with an active committed authority and every guarantee holds
    When I rotate the node signing authority as the root delegate
    Then the rotation committed from the previous authority with every guarantee holding
    And the root delegate can still administer the registry
    When I rotate the node signing authority as the root delegate
    Then the rotation committed from the previous authority with every guarantee holding
    When I read the node authority status as the root delegate
    Then the status names the latest authority as active with every earlier one retired
    And the registry reports ready
    When the registry process is killed and restarted with the same store
    And I read the node authority status as the root delegate
    Then the status names the latest authority as active with every earlier one retired
    And the root delegate can still administer the registry
    And the registry reports ready

  Scenario: Rotation without credentials changes nothing
    Given a fresh registry application
    When I read the node authority status as the root delegate
    Then the node signs with an active committed authority and every guarantee holds
    When I rotate the node signing authority without credentials
    Then the rotation is refused with status 403
    And the node authority is unchanged

  Scenario Outline: A malformed rotation request changes nothing
    Given a fresh registry application
    When I read the node authority status as the root delegate
    Then the node signs with an active committed authority and every guarantee holds
    When I rotate the node signing authority as the root delegate with the body '<body>'
    Then the rotation is refused with status 400
    And the node authority is unchanged
    When I read the node authority status as the root delegate
    Then the node signs with an active committed authority and every guarantee holds

    Examples:
      | body                                 |
      | []                                   |
      | null                                 |
      | 7                                    |
      | {"algorithm": 7}                     |
      | {"algorithm": "rsa"}                 |
      | {"algorithm": "ed25519", "extra": 1} |
