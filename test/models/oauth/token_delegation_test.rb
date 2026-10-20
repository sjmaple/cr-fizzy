require "test_helper"

class Oauth::TokenDelegationTest < ActiveSupport::TestCase
  RESOURCE = "https://mcp.example.com/mcp"

  setup do
    @saved_resources = Rails.application.config.x.oauth.mcp_resources
    Rails.application.config.x.oauth.mcp_resources = [ RESOURCE ]

    @client = Oauth::Client.provision_mcp_client!(protected_resource: RESOURCE)
    @subject = identities(:david).access_tokens.create! \
      oauth_client: oauth_clients(:mcp_client), permission: :write, audience: RESOURCE, account: accounts("37s")
  end

  teardown do
    Rails.application.config.x.oauth.mcp_resources = @saved_resources
  end

  test "mint issues one token under the subject grant, with no refresh token and no client touch" do
    assert_no_changes -> { @client.reload.updated_at } do
      @token = delegation.validate!.mint!
    end

    assert @token.delegated?
    assert @token.raw_token.start_with?("fizzy_dt_")
    assert_nil @token.refresh_token_digest
    assert_equal @subject, @token.delegated_from
  end

  test "the token lives at most five minutes" do
    token = delegation.validate!.mint!

    assert_operator token.expires_at, :<=, Oauth::TokenDelegation::TTL_CAP.from_now
  end

  test "a delegated token is honored only while its grant is" do
    token = delegation.validate!.mint!
    assert token.honored?

    @subject.update_columns updated_at: (Identity::AccessToken::REFRESH_IDLE_LIMIT + 1.day).ago
    assert_not token.reload.honored?
  end

  test "a delegated token the replica misses is looked up on the primary" do
    token = delegation.validate!.mint!
    relation = Identity::AccessToken.active
    Identity::AccessToken.stubs(:active).returns(relation)
    relation.stubs(:find_by_raw_token).returns(nil).then.returns(token)
    ApplicationRecord.expects(:with_writing_role).yields.returns(token)

    assert_equal token, Identity::AccessToken.find_active(token.raw_token)
  end

  test "an unknown token without the delegated prefix never costs a primary read" do
    ApplicationRecord.expects(:with_writing_role).never

    assert_nil Identity::AccessToken.find_active("fizzy_at_unknown")
  end

  test "expired delegated tokens are cleaned up, and grants are not" do
    expired = delegation.validate!.mint!
    expired.update_columns expires_at: 2.hours.ago
    live = delegation.validate!.mint!

    Identity::AccessToken.cleanup_delegated

    assert_not Identity::AccessToken.exists?(expired.id)
    assert Identity::AccessToken.exists?(live.id)
    assert Identity::AccessToken.exists?(@subject.id)
  end

  test "the lapsed-grant sweep and Connected Apps see grants only" do
    token = delegation.validate!.mint!

    assert_not_includes Identity::AccessToken.grants, token
    assert_includes Identity::AccessToken.grants, @subject
  end

  test "provisioning converges the client and keeps its secret" do
    secret = @client.rotate_secret!

    client = Oauth::Client.provision_mcp_client!(protected_resource: RESOURCE)

    assert_equal @client, client
    assert client.authenticate_secret(secret)
    assert client.delegation_client?
    assert_empty client.redirect_uris
  end

  test "a new client holds a secret nobody knows until one is minted" do
    assert @client.client_secret_digest.present?

    secret = @client.rotate_secret!

    assert secret.start_with?("fizzy_cs_")
    assert @client.reload.authenticate_secret(secret)
  end

  test "rotating a secret retires the old one" do
    old = @client.rotate_secret!
    @client.rotate_secret!

    assert_not @client.reload.authenticate_secret(old)
  end

  test "a self-registered client's secret can't be minted" do
    assert_raises(ArgumentError) { oauth_clients(:confidential_client).rotate_secret! }
  end

  test "a client that fronts no resource still needs a redirect" do
    client = Oauth::Client.new(name: "No redirects", redirect_uris: [])

    assert_not client.valid?
    assert client.errors[:redirect_uris].any?
  end

  private
    def delegation(**options)
      Oauth::TokenDelegation.new(client: @client, subject_token: @subject.raw_token, **options)
    end
end
