# frozen_string_literal: true

require_relative "test_helper"

require "action_controller/railtie"
require "cgi"
require "json"
require "logger"
require "rack/test"
require "rails"
require "uri"
require "webmock/minitest"

class RailsIntegrationSessionsController < ActionController::Base
  def create
    auth = request.env.fetch("omniauth.auth")
    render json: {
      uid: auth["uid"],
      email: auth.dig("info", "email")
    }
  end

  def failure
    render json: {error: params[:message]}, status: :unauthorized
  end
end

class RailsIntegrationApp < Rails::Application
  config.root = File.expand_path("..", __dir__)
  config.eager_load = false
  config.secret_key_base = "slack2-rails-integration-test-secret-key"
  config.active_support.cache_format_version = 7.1 if config.active_support.respond_to?(:cache_format_version=)

  if config.active_support.respond_to?(:to_time_preserves_timezone=) &&
      Rails.gem_version < Gem::Version.new("8.1.0")
    config.active_support.to_time_preserves_timezone = :zone
  end
  config.hosts.clear
  config.hosts << "example.org"
  config.logger = Logger.new(nil)

  config.middleware.use OmniAuth::Builder do
    provider :slack2, "client-id", "client-secret"
    provider :slack, "client-id", "client-secret"
  end

  routes.append do
    match "/auth/:provider/callback", to: "rails_integration_sessions#create", via: %i[get post]
    get "/auth/failure", to: "rails_integration_sessions#failure"
  end
end

RailsIntegrationApp.initialize! unless RailsIntegrationApp.initialized?

class RailsIntegrationTest < Minitest::Test
  include Rack::Test::Methods

  REALISTIC_USER_ID = "U0R7MFMJM"
  REALISTIC_TEAM_ID = "T0123ABC456"
  REALISTIC_EMAIL = "sample@example.test"
  REALISTIC_TEAM_NAME = "Sample Workspace"
  REALISTIC_TEAM_DOMAIN = "sampleworkspace"
  REALISTIC_PICTURE = "https://secure.gravatar.com/avatar/example.jpg?s=512&d=https%3A%2F%2Fa.slack-edge.com%2Fexample.png"
  REALISTIC_TEAM_IMAGE = "https://avatars.slack-edge.com/example-team_132.jpg"
  REALISTIC_DATE_EMAIL_VERIFIED = 1_775_000_482

  def setup
    super
    @previous_test_mode = OmniAuth.config.test_mode
    @previous_allowed_request_methods = OmniAuth.config.allowed_request_methods
    @previous_request_validation_phase = OmniAuth.config.request_validation_phase

    OmniAuth.config.test_mode = false
    OmniAuth.config.allowed_request_methods = [:post]
    OmniAuth.config.request_validation_phase = nil
  end

  def teardown
    OmniAuth.config.test_mode = @previous_test_mode
    OmniAuth.config.allowed_request_methods = @previous_allowed_request_methods
    OmniAuth.config.request_validation_phase = @previous_request_validation_phase
    WebMock.reset!
    super
  end

  def app
    RailsIntegrationApp
  end

  def test_rails_request_and_callback_flow_returns_expected_auth_payload
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    kid = "test-key-id"

    stub_slack_token_exchange(rsa_key, kid)
    stub_slack_jwks(rsa_key, kid)
    stub_slack_userinfo

    post "/auth/slack2"

    assert_equal 302, last_response.status

    authorize_uri = URI.parse(last_response["Location"])

    assert_equal "slack.com", authorize_uri.host
    query_params = CGI.parse(authorize_uri.query)
    state = query_params.fetch("state").first
    nonce = query_params.fetch("nonce").first

    assert_pkce_authorize_query(query_params)
    refute_nil nonce

    get "/auth/slack2/callback", {code: "oauth-test-code", state: state}

    assert_equal 200, last_response.status

    payload = JSON.parse(last_response.body)

    assert_equal REALISTIC_USER_ID, payload["uid"]
    assert_equal REALISTIC_EMAIL, payload["email"]

    assert_slack_token_exchange_includes_code_verifier
    assert_requested :get, "https://slack.com/openid/connect/keys", times: 1
    assert_requested :get, "https://slack.com/api/openid.connect.userInfo", times: 1
  end

  def test_compat_slack_alias_uses_same_pkce_request_and_callback_flow
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    kid = "test-key-id"

    stub_slack_token_exchange(rsa_key, kid)
    stub_slack_jwks(rsa_key, kid)
    stub_slack_userinfo

    post "/auth/slack"

    assert_equal 302, last_response.status

    authorize_uri = URI.parse(last_response["Location"])

    assert_equal "slack.com", authorize_uri.host
    query_params = CGI.parse(authorize_uri.query)
    state = query_params.fetch("state").first

    assert_pkce_authorize_query(query_params)

    get "/auth/slack/callback", {code: "oauth-test-code", state: state}

    assert_equal 200, last_response.status

    payload = JSON.parse(last_response.body)

    assert_equal REALISTIC_USER_ID, payload["uid"]
    assert_equal REALISTIC_EMAIL, payload["email"]

    assert_slack_token_exchange_includes_code_verifier
  end

  private

  def assert_pkce_authorize_query(query_params)
    refute_nil query_params["code_challenge"]&.first
    assert_equal ["S256"], query_params["code_challenge_method"]
  end

  def assert_slack_token_exchange_includes_code_verifier
    assert_requested(:post, "https://slack.com/api/openid.connect.token", times: 1) do |request|
      params = Rack::Utils.parse_nested_query(request.body.to_s)
      params.key?("code_verifier") && !params["code_verifier"].to_s.empty?
    end
  end

  def stub_slack_token_exchange(rsa_key, kid)
    now = Time.now.to_i
    id_token_payload = realistic_id_token_payload(
      aud: "client-id",
      nonce: nil,
      iat: now,
      exp: now + 3600,
      auth_time: now
    )
    id_token = JWT.encode(id_token_payload, rsa_key, "RS256", {kid: kid})

    stub_request(:post, "https://slack.com/api/openid.connect.token").to_return(
      status: 200,
      headers: {"Content-Type" => "application/json"},
      body: {
        ok: true,
        access_token: "xoxp-test-access-token",
        token_type: "Bearer",
        id_token: id_token,
        expires_in: 3600,
        refresh_token: "xoxe-1-test-refresh-token",
        scope: "openid email profile"
      }.to_json
    )
  end

  def stub_slack_jwks(rsa_key, kid)
    jwks_response = {
      keys: [JWT::JWK.new(rsa_key.public_key, kid: kid).export]
    }

    stub_request(:get, "https://slack.com/openid/connect/keys").to_return(
      status: 200,
      headers: {"Content-Type" => "application/json"},
      body: jwks_response.to_json
    )
  end

  def stub_slack_userinfo
    stub_request(:get, "https://slack.com/api/openid.connect.userInfo").to_return(
      status: 200,
      headers: {"Content-Type" => "application/json"},
      body: realistic_raw_info_payload.to_json
    )
  end

  def realistic_raw_info_payload
    {
      :ok => true,
      :sub => REALISTIC_USER_ID,
      :"https://slack.com/user_id" => REALISTIC_USER_ID,
      :"https://slack.com/team_id" => REALISTIC_TEAM_ID,
      :email => REALISTIC_EMAIL,
      :email_verified => true,
      :date_email_verified => REALISTIC_DATE_EMAIL_VERIFIED,
      :name => "Sample User",
      :picture => REALISTIC_PICTURE,
      :given_name => "Sample",
      :family_name => "User",
      :locale => "en-US",
      :"https://slack.com/team_name" => REALISTIC_TEAM_NAME,
      :"https://slack.com/team_domain" => REALISTIC_TEAM_DOMAIN,
      "https://slack.com/user_image_24" => "https://secure.gravatar.com/avatar/example.jpg?s=24&d=https%3A%2F%2Fa.slack-edge.com%2Fexample-24.png",
      "https://slack.com/user_image_32" => "https://secure.gravatar.com/avatar/example.jpg?s=32&d=https%3A%2F%2Fa.slack-edge.com%2Fexample-32.png",
      "https://slack.com/user_image_48" => "https://secure.gravatar.com/avatar/example.jpg?s=48&d=https%3A%2F%2Fa.slack-edge.com%2Fexample-48.png",
      "https://slack.com/user_image_72" => "https://secure.gravatar.com/avatar/example.jpg?s=72&d=https%3A%2F%2Fa.slack-edge.com%2Fexample-72.png",
      "https://slack.com/user_image_192" => "https://secure.gravatar.com/avatar/example.jpg?s=192&d=https%3A%2F%2Fa.slack-edge.com%2Fexample-192.png",
      "https://slack.com/user_image_512" => REALISTIC_PICTURE,
      "https://slack.com/team_image_34" => "https://avatars.slack-edge.com/example-team_34.jpg",
      "https://slack.com/team_image_44" => "https://avatars.slack-edge.com/example-team_44.jpg",
      "https://slack.com/team_image_68" => "https://avatars.slack-edge.com/example-team_68.jpg",
      "https://slack.com/team_image_88" => "https://avatars.slack-edge.com/example-team_88.jpg",
      "https://slack.com/team_image_102" => "https://avatars.slack-edge.com/example-team_102.jpg",
      "https://slack.com/team_image_132" => REALISTIC_TEAM_IMAGE,
      "https://slack.com/team_image_230" => REALISTIC_TEAM_IMAGE,
      "https://slack.com/team_image_default" => false
    }
  end

  def realistic_id_token_payload(aud:, nonce:, iat:, exp:, auth_time:)
    {
      "iss" => "https://slack.com",
      "sub" => REALISTIC_USER_ID,
      "aud" => aud,
      "exp" => exp,
      "iat" => iat,
      "auth_time" => auth_time,
      "at_hash" => "sample-at-hash",
      "https://slack.com/team_id" => REALISTIC_TEAM_ID,
      "https://slack.com/user_id" => REALISTIC_USER_ID,
      "email" => REALISTIC_EMAIL,
      "email_verified" => true,
      "date_email_verified" => REALISTIC_DATE_EMAIL_VERIFIED,
      "locale" => "en-US",
      "name" => "Sample User",
      "picture" => REALISTIC_PICTURE,
      "given_name" => "Sample",
      "family_name" => "User",
      "https://slack.com/team_name" => REALISTIC_TEAM_NAME,
      "https://slack.com/team_domain" => REALISTIC_TEAM_DOMAIN,
      "https://slack.com/team_image_230" => REALISTIC_TEAM_IMAGE,
      "https://slack.com/team_image_default" => false
    }.tap do |payload|
      payload["nonce"] = nonce if nonce
    end
  end
end
