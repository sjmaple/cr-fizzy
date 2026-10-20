require "test_helper"

# The delegation exchange (RFC 8693) the hosted MCP server uses, at the token
# endpoint. Its wire contract is bc3's (doc/oauth/mcp_token_delegation.md),
# which fizzy-mcp-server's exchange client is built against.
class OauthTokenExchangeTest < ActionDispatch::IntegrationTest
  include OauthAvailabilityTestHelper, OauthClientCredentialsTestHelper

  RESOURCE = "https://mcp.example.com/mcp"
  GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
  ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

  setup do
    @saved_resources = Rails.application.config.x.oauth.mcp_resources
    Rails.application.config.x.oauth.mcp_resources = [ RESOURCE ]

    @client = Oauth::Client.provision_mcp_client!(protected_resource: RESOURCE)
    @secret = @client.rotate_secret!
    @subject = audienced_grant
  end

  teardown do
    Rails.application.config.x.oauth.mcp_resources = @saved_resources
  end

  test "an audienced, account-bound grant is exchanged for a short-lived API token" do
    assert_difference -> { Identity::AccessToken.delegated.count }, +1 do
      exchange
    end

    assert_response :success
    body = response.parsed_body
    assert body["access_token"].start_with?("fizzy_dt_")
    assert_equal "Bearer", body["token_type"]
    assert_equal ACCESS_TOKEN_TYPE, body["issued_token_type"]
    assert_equal "read write", body["scope"]
    assert_operator body["expires_in"], :>, 0
    assert_operator body["expires_in"], :<=, 300
    assert_not body.key?("refresh_token")

    delegated = Identity::AccessToken.find_by_raw_token(body["access_token"])
    assert_equal @subject, delegated.delegated_from
    assert_equal @client, delegated.oauth_client
    assert_equal accounts("37s"), delegated.account
    assert_nil delegated.audience
    assert_nil delegated.refresh_token_digest
    assert delegated.write?
  end

  test "the delegated token authenticates the API, and the subject grant does not chain" do
    exchange
    delegated = response.parsed_body["access_token"]

    get user_path(users(:david)), env: { "HTTP_AUTHORIZATION" => "Bearer #{delegated}" }, as: :json
    assert_response :success

    exchange subject_token: delegated
    assert_invalid_grant "Subject token is not valid"
  end

  test "the token lives no longer than the subject" do
    @subject.update_columns expires_at: 90.seconds.from_now

    exchange

    assert_response :success
    assert_operator response.parsed_body["expires_in"], :<=, 90
  end

  test "the response always names the scope, and a requested scope only narrows" do
    exchange scope: "read"

    assert_response :success
    assert_equal "read", response.parsed_body["scope"]
    delegated = response.parsed_body["access_token"]

    patch user_path(users(:david)), params: { user: { name: "Nope" } }, env: { "HTTP_AUTHORIZATION" => "Bearer #{delegated}" }, as: :json
    assert_response :forbidden
  end

  test "a read grant gets a read token, and asking for write is refused" do
    @subject.update_columns permission: "read"

    exchange
    assert_response :success
    assert_equal "read", response.parsed_body["scope"]

    exchange scope: "read write"
    assert_oauth_error "invalid_scope", "Scope exceeds the subject token's scope"
  end

  test "an unknown or empty scope is refused" do
    exchange scope: "admin"
    assert_oauth_error "invalid_scope", "Unknown scope: admin"

    exchange scope: ""
    assert_oauth_error "invalid_scope", "Scope must include 'read' or 'write' for API access"
  end

  test "a scope the client may not hold is refused rather than narrowed" do
    @client.update! scopes: %w[ read ]

    exchange
    assert_oauth_error "invalid_scope", "Scope 'write' not allowed for this client"
  end

  test "tokens that aren't audienced to the client's resource are refused" do
    fizzy_grant = identities(:david).access_tokens.create!(oauth_client: oauth_clients(:mcp_client), permission: :write, account: accounts("37s"))
    elsewhere = audienced_grant(audience: "https://other.example.com/mcp")

    [ fizzy_grant.raw_token, elsewhere.raw_token ].each do |token|
      exchange subject_token: token
      assert_invalid_grant "Subject token is not audienced to this client's protected resource"
    end

    exchange subject_token: identity_access_tokens(:davids_api_token).token
    assert_invalid_grant "Subject token is not valid"
  end

  test "a grant bound to no account is refused" do
    @subject.update_columns account_id: nil

    exchange
    assert_invalid_grant "Subject token is not account-bound"
  end

  test "a person who has left the account is refused" do
    users(:david).update_columns active: false

    exchange
    assert_invalid_grant "Subject token's user no longer has account access"
  end

  test "unknown, expired and lapsed subjects get the one answer" do
    exchange subject_token: "fizzy_at_nothing"
    assert_invalid_grant "Subject token is not valid"

    @subject.update_columns expires_at: 1.minute.ago
    exchange
    assert_invalid_grant "Subject token is not valid"

    @subject.update_columns expires_at: 1.hour.from_now, updated_at: (Identity::AccessToken::REFRESH_IDLE_LIMIT + 1.day).ago
    exchange
    assert_invalid_grant "Subject token is not valid"
  end

  test "a subject whose client OAuth is dark for is refused" do
    with_oauth_availability(acceptance: false, pilot_client_ids: [ @client.client_id ]) do
      exchange
    end

    assert_invalid_grant "Subject token is not valid"
  end

  test "only the MCP server's client, authenticated, may exchange" do
    exchange headers: {}, params: { client_id: @client.client_id, client_secret: "wrong" }
    assert_client_authentication_failed basic: false

    exchange headers: basic(@client.client_id, "wrong"), params: {}
    assert_client_authentication_failed

    exchange params: { client_id: oauth_clients(:mcp_client).client_id }
    assert_client_authentication_failed basic: false

    exchange params: { client_id: oauth_clients(:confidential_client).client_id, client_secret: "confidential_secret_789" }
    assert_oauth_error "unauthorized_client", "Client not configured for token delegation"
  end

  test "the client authenticates with HTTP Basic too" do
    exchange params: {}, headers: basic(@client.client_id, @secret)

    assert_response :success
  end

  test "a client whose resource is no longer configured can't exchange" do
    Rails.application.config.x.oauth.mcp_resources = [ RESOURCE, "https://other.example.com/mcp" ]
    @client.update! protected_resource: "https://retired.example.com/mcp"

    exchange
    assert_oauth_error "unauthorized_client", "Client not configured for token delegation"
  end

  test "an install that configures no resource answers as if the grant didn't exist" do
    Rails.application.config.x.oauth.mcp_resources = []

    exchange
    assert_oauth_error "unsupported_grant_type", "Only authorization_code and refresh_token grants are supported"
  end

  test "the exchange is dark while issuance is" do
    with_oauth_availability(acceptance: true, issuance: false) do
      exchange
    end

    assert_response :service_unavailable
  end

  test "a malformed request is invalid_request" do
    exchange subject_token: ""
    assert_oauth_error "invalid_request", "subject_token required"

    exchange subject_token_type: "urn:ietf:params:oauth:token-type:refresh_token"
    assert_oauth_error "invalid_request", "Only access_token subject_token_type supported"

    exchange requested_token_type: "urn:ietf:params:oauth:token-type:refresh_token"
    assert_oauth_error "invalid_request", "Only access_token requested_token_type supported"
  end

  test "a resource other than Fizzy's own API is invalid_target" do
    exchange resource: "http://www.example.com"
    assert_response :success

    exchange resource: RESOURCE
    assert_oauth_error "invalid_target", "resource does not match the subject token's account"
  end

  test "ending the subject grant sweeps its delegated tokens" do
    exchange
    delegated = response.parsed_body["access_token"]

    @subject.destroy

    assert_not Identity::AccessToken.find_by_raw_token(delegated)
    get user_path(users(:david)), env: { "HTTP_AUTHORIZATION" => "Bearer #{delegated}" }, as: :json
    assert_response :unauthorized
  end

  test "a delegated token is refused at use once its grant is gone, swept or not" do
    exchange
    delegated = response.parsed_body["access_token"]

    Identity::AccessToken.where(id: @subject.id).delete_all

    get user_path(users(:david)), env: { "HTTP_AUTHORIZATION" => "Bearer #{delegated}" }, as: :json
    assert_response :unauthorized
  end

  test "an exchange that loses the race with a revocation is refused" do
    Identity::AccessToken.stubs(:lock).returns(Identity::AccessToken.where(id: nil))

    exchange
    assert_invalid_grant "Subject token is not valid"
  end

  test "Connected Apps lists the subject grant, never the delegated tokens" do
    exchange

    assert_equal [ @subject ], identities(:david).access_tokens.grants.where(oauth_client: [ @client, @subject.oauth_client ]).to_a
  end

  test "the authenticated MCP client is charged to its own budget, not the per-IP limit" do
    Rails.cache.stubs(:increment).with { |key, *| key.include?(":client:") }.returns(Oauth::TokenExchangesController::CLIENT_BUDGET)
    Rails.cache.stubs(:increment).with { |key, *| !key.include?(":client:") }.returns(1_000)

    exchange
    assert_response :success

    Rails.cache.stubs(:increment).with { |key, *| key.include?(":client:") }.returns(Oauth::TokenExchangesController::CLIENT_BUDGET + 1)

    exchange
    assert_response :too_many_requests
    assert_equal "60", response.headers["Retry-After"]
  end

  test "a failed authentication is held to the per-IP limit" do
    Rails.cache.stubs(:increment).returns(21)

    exchange params: { client_id: @client.client_id, client_secret: "wrong" }
    assert_response :too_many_requests
  end

  test "the metadata advertises the exchange only where it's configured" do
    untenanted { get "/.well-known/oauth-authorization-server" }
    assert_includes response.parsed_body["grant_types_supported"], GRANT_TYPE

    Rails.application.config.x.oauth.mcp_resources = []
    untenanted { get "/.well-known/oauth-authorization-server" }
    assert_not_includes response.parsed_body["grant_types_supported"], GRANT_TYPE
  end

  test "a refresh still reaches the token endpoint beside the exchange" do
    untenanted do
      post oauth_token_path, params: { grant_type: "refresh_token", refresh_token: @subject.raw_refresh_token,
        client_id: @subject.oauth_client.client_id }
    end

    assert_response :success
  end

  private
    def audienced_grant(audience: RESOURCE)
      identities(:david).access_tokens.create! \
        oauth_client: oauth_clients(:mcp_client), permission: :write, audience: audience, account: accounts("37s")
    end

    def exchange(subject_token: @subject.raw_token, params: nil, headers: {}, **extra)
      params ||= { client_id: @client.client_id, client_secret: @secret }
      body = { grant_type: GRANT_TYPE, subject_token: subject_token, subject_token_type: ACCESS_TOKEN_TYPE }.merge(extra).merge(params)

      untenanted { post oauth_token_path, params: body, headers: headers }
    end

    def assert_oauth_error(error, description)
      assert_response :bad_request
      assert_equal error, response.parsed_body["error"]
      assert_equal description, response.parsed_body["error_description"]
    end

    def assert_invalid_grant(description)
      assert_oauth_error "invalid_grant", description
    end
end
