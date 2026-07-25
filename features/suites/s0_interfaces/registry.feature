@status:enforced
Feature: Public registry interfaces
  The registry exposes its behavior through public interfaces that must remain
  executable and discoverable.

  @interface:http-api
  Scenario: registry HTTP API exposes its version
    Given a fresh registry application
    When I request the registry version
    Then the response status is 200
    And the response identifies the kappa distribution protocol

  @interface:openapi
  Scenario: OpenAPI interface describes the public routes
    Given a fresh registry application
    When I request the OpenAPI document
    Then the response status is 200
    And the response is a valid OpenAPI document
    And the document includes the Scalar documentation routes

  @interface:scalar
  Scenario: Scalar interface renders the API reference
    Given a fresh registry application
    When I open the Scalar API reference
    Then the response status is 200
    And the response is a Scalar HTML page
    When I request the Scalar JavaScript asset
    Then the response status is 200
    And the response is a JavaScript asset
