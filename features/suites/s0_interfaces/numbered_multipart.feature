@status:implemented
Feature: S3 numbered multipart uploads
  Scenario: Replacement and selected completion survive registry restart
    Given a fresh registry application
    When I complete an S3 upload with replaced and selectively assembled numbered parts
    Then the selected S3 object bytes are exact through HTTP
    When the registry process is killed and restarted with the same store
    Then the selected S3 object bytes are exact through HTTP
