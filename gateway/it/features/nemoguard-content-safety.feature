# --------------------------------------------------------------------
# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
#
# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# --------------------------------------------------------------------

@nemoguard-content-safety
Feature: NeMo Guard Content Safety Policy
  As an API developer
  I want to validate request and response content using NeMo Guard Content Safety
  So that I can prevent unsafe content from reaching or leaving the upstream LLM

  Background:
    Given the gateway services are running

  # Category 1: Basic Request Validation

  Scenario: Request with safe content passes through
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-safe-request-api
      spec:
        displayName: NeMo Guard - Safe Request
        version: v1.0
        context: /nemo-safe-request/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-safe-request/v1.0/health" to be ready

    When I send a POST request to "http://localhost:8080/nemo-safe-request/v1.0/chat" with body:
      """
      {"messages": [{"role": "user", "content": "What is the capital of France?"}]}
      """
    Then the response status code should be 200

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-safe-request-api"
    Then the response should be successful

  Scenario: Request with violence content is blocked
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-violence-block-api
      spec:
        displayName: NeMo Guard - Violence Block
        version: v1.0
        context: /nemo-violence-block/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-violence-block/v1.0/health" to be ready

    When I send a POST request to "http://localhost:8080/nemo-violence-block/v1.0/chat" with body:
      """
      {"messages": [{"role": "user", "content": "This content contains violence and murder"}]}
      """
    Then the response status code should be 400
    And the response body should contain "NEMOGUARD_CONTENT_SAFETY"
    And the response body should contain "GUARDRAIL_INTERVENED"

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-violence-block-api"
    Then the response should be successful

  Scenario: Request with hate speech is blocked
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-hate-block-api
      spec:
        displayName: NeMo Guard - Hate Speech Block
        version: v1.0
        context: /nemo-hate-block/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-hate-block/v1.0/health" to be ready

    When I send a POST request to "http://localhost:8080/nemo-hate-block/v1.0/chat" with body:
      """
      {"messages": [{"role": "user", "content": "This content contains hate speech and discrimination"}]}
      """
    Then the response status code should be 400
    And the response body should contain "NEMOGUARD_CONTENT_SAFETY"

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-hate-block-api"
    Then the response should be successful

  # Category 2: Assessment Details

  Scenario: showAssessment includes safety category in blocked response
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-assessment-api
      spec:
        displayName: NeMo Guard - Assessment
        version: v1.0
        context: /nemo-assessment/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
                    showAssessment: true
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-assessment/v1.0/health" to be ready

    When I send a POST request to "http://localhost:8080/nemo-assessment/v1.0/chat" with body:
      """
      {"messages": [{"role": "user", "content": "This content contains violence and murder"}]}
      """
    Then the response status code should be 400
    And the response should be valid JSON
    And the response body should contain "assessments"
    And the response body should contain "category"

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-assessment-api"
    Then the response should be successful

  # Category 3: Error Handling

  Scenario: Passthrough on error allows requests despite guardrail failures
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-passthrough-api
      spec:
        displayName: NeMo Guard - Passthrough on Error
        version: v1.0
        context: /nemo-passthrough/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
                    passthroughOnError: true
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-passthrough/v1.0/health" to be ready

    When I send a POST request to "http://localhost:8080/nemo-passthrough/v1.0/chat" with body:
      """
      {"messages": [{"role": "user", "content": "simulate error in mock service"}]}
      """
    Then the response status code should be 200

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-passthrough-api"
    Then the response should be successful

  Scenario: Fail closed on guardrail error when passthroughOnError is false
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-failclosed-api
      spec:
        displayName: NeMo Guard - Fail Closed
        version: v1.0
        context: /nemo-failclosed/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
                    passthroughOnError: false
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-failclosed/v1.0/health" to be ready

    When I send a POST request to "http://localhost:8080/nemo-failclosed/v1.0/chat" with body:
      """
      {"messages": [{"role": "user", "content": "simulate error in mock service"}]}
      """
    Then the response status code should be 503
    And the response body should contain "NEMOGUARD_CONTENT_SAFETY"

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-failclosed-api"
    Then the response should be successful

  # Category 4: Edge Cases

  Scenario: Empty request body is handled gracefully
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-empty-body-api
      spec:
        displayName: NeMo Guard - Empty Body
        version: v1.0
        context: /nemo-empty-body/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-empty-body/v1.0/health" to be ready

    When I send a POST request to "http://localhost:8080/nemo-empty-body/v1.0/chat" with body:
      """
      """
    Then the response status code should be 200

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-empty-body-api"
    Then the response should be successful

  # Category 5: JSONPath Extraction

  Scenario: JSONPath extraction validates the targeted field only
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-jsonpath-api
      spec:
        displayName: NeMo Guard - JSONPath
        version: v1.0
        context: /nemo-jsonpath/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-jsonpath/v1.0/health" to be ready

    # Safe targeted field - should pass even if other fields contain unsafe content
    When I set header "Content-Type" to "application/json"
    And I send a POST request to "http://localhost:8080/nemo-jsonpath/v1.0/chat" with body:
      """
      {
        "messages": [{"role": "user", "content": "What is the capital of France?"}],
        "metadata": "This field contains violence but should be ignored"
      }
      """
    Then the response status code should be 200

    # Unsafe targeted field - should be blocked
    When I set header "Content-Type" to "application/json"
    And I send a POST request to "http://localhost:8080/nemo-jsonpath/v1.0/chat" with body:
      """
      {
        "messages": [{"role": "user", "content": "This message contains violence and murder"}]
      }
      """
    Then the response status code should be 400

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-jsonpath-api"
    Then the response should be successful

  # Category 6: Response Phase Validation
  # Note: Response blocking requires the upstream to return unsafe content.
  # The scenarios below verify the response phase does not block safe upstream responses.

  Scenario: Response phase enabled with safe upstream response passes through
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-response-phase-api
      spec:
        displayName: NeMo Guard - Response Phase
        version: v1.0
        context: /nemo-response-phase/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
                  response:
                    enabled: true
                    jsonPath: "$.choices[0].message.content"
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-response-phase/v1.0/health" to be ready

    # Safe request with safe upstream response - should pass both phases
    When I send a POST request to "http://localhost:8080/nemo-response-phase/v1.0/chat" with body:
      """
      {"messages": [{"role": "user", "content": "What is the capital of France?"}]}
      """
    Then the response status code should be 200

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-response-phase-api"
    Then the response should be successful

  # Category 7: Custom Configuration

  Scenario: Custom blockStatusCode is respected
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-custom-status-api
      spec:
        displayName: NeMo Guard - Custom Status Code
        version: v1.0
        context: /nemo-custom-status/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
                    blockStatusCode: 422
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-custom-status/v1.0/health" to be ready

    When I send a POST request to "http://localhost:8080/nemo-custom-status/v1.0/chat" with body:
      """
      {"messages": [{"role": "user", "content": "This content contains violence and murder"}]}
      """
    Then the response status code should be 422

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-custom-status-api"
    Then the response should be successful

  # Category 8: Error Response Structure

  Scenario: Verify complete error response structure for request phase
    Given I authenticate using basic auth as "admin"
    When I deploy this API configuration:
      """
      apiVersion: gateway.api-platform.wso2.com/v1alpha1
      kind: RestApi
      metadata:
        name: nemo-error-structure-api
      spec:
        displayName: NeMo Guard - Error Structure
        version: v1.0
        context: /nemo-error-structure/$version
        upstream:
          main:
            url: http://sample-backend:9080/api/v1
        operations:
          - method: GET
            path: /health
          - method: POST
            path: /chat
            policies:
              - name: nemoguard-content-safety
                version: v1
                params:
                  request:
                    enabled: true
                    jsonPath: "$.messages[-1].content"
                    showAssessment: true
      """
    Then the response should be successful
    And I wait for the endpoint "http://localhost:8080/nemo-error-structure/v1.0/health" to be ready

    When I send a POST request to "http://localhost:8080/nemo-error-structure/v1.0/chat" with body:
      """
      {"messages": [{"role": "user", "content": "This content contains violence and murder"}]}
      """
    Then the response status code should be 400
    And the response should be valid JSON
    And the JSON response field "type" should be "NEMOGUARD_CONTENT_SAFETY"
    And the response body should contain "GUARDRAIL_INTERVENED"
    And the response body should contain "REQUEST"
    And the response body should contain "assessments"

    # Cleanup
    Given I authenticate using basic auth as "admin"
    When I delete the API "nemo-error-structure-api"
    Then the response should be successful
