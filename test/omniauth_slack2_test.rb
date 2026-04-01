# frozen_string_literal: true

require_relative "test_helper"

require "base64"
require "json"
require "openssl"
require "uri"
require "webmock/minitest"

class OmniauthSlack2Test < Minitest::Test
  REALISTIC_USER_ID = "U0R7MFMJM"
  REALISTIC_TEAM_ID = "T0123ABC456"
  REALISTIC_EMAIL = "sample@example.test"
  REALISTIC_TEAM_NAME = "Sample Workspace"
  REALISTIC_TEAM_DOMAIN = "sampleworkspace"
  REALISTIC_PICTURE = "https://secure.gravatar.com/avatar/example.jpg?s=512&d=https%3A%2F%2Fa.slack-edge.com%2Fexample.png"
  REALISTIC_TEAM_IMAGE = "https://avatars.slack-edge.com/example-team_132.jpg"
  REALISTIC_DATE_EMAIL_VERIFIED = 1_775_000_482

  def build_strategy
    OmniAuth::Strategies::Slack2.new(nil, "client-id", "client-secret")
  end

  def test_uses_slack_oidc_endpoints
    client_options = build_strategy.options.client_options

    assert_equal "https://slack.com", client_options.site
    assert_equal "https://slack.com/openid/connect/authorize", client_options.authorize_url
    assert_equal "https://slack.com/api/openid.connect.token", client_options.token_url
  end

  def test_uid_is_extracted_from_raw_info_sub
    strategy = build_strategy
    strategy.instance_variable_set(:@raw_info, {"sub" => "U0R7MFMJM"})

    assert_equal "U0R7MFMJM", strategy.uid
  end

  TOKEN_SCOPE = "openid email profile"

  def test_uid_info_credentials_and_extra_are_derived_from_raw_info
    strategy = build_strategy
    payload = realistic_raw_info_payload

    token = FakeAccessToken.new(payload)
    strategy.define_singleton_method(:access_token) { token }
    strategy.define_singleton_method(:id_info) { nil }

    assert_equal REALISTIC_USER_ID, strategy.uid
    assert_equal(
      {
        name: "Sample User",
        email: REALISTIC_EMAIL,
        unverified_email: REALISTIC_EMAIL,
        email_verified: true,
        first_name: "Sample",
        last_name: "User",
        image: REALISTIC_PICTURE,
        locale: "en-US"
      },
      strategy.info
    )
    assert_equal(
      {
        "token" => "access-token",
        "refresh_token" => "refresh-token",
        "expires_at" => 1_772_691_847,
        "expires" => true,
        "scope" => TOKEN_SCOPE
      },
      strategy.credentials
    )
    assert_equal payload, strategy.extra["raw_info"]
    assert_equal REALISTIC_TEAM_ID, strategy.extra["team_id"]
    assert_equal REALISTIC_TEAM_NAME, strategy.extra["team_name"]
    assert_equal REALISTIC_TEAM_DOMAIN, strategy.extra["team_domain"]
  end

  def test_extra_includes_realistic_decoded_id_token_claims
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    kid = "test-key-id"
    now = Time.now.to_i
    id_token_payload = realistic_id_token_payload(
      aud: "client-id",
      nonce: "test-nonce-value",
      iat: now,
      exp: now + 3600,
      auth_time: now
    )
    id_token = JWT.encode(id_token_payload, rsa_key, "RS256", {kid: kid})

    jwks_response = {
      keys: [JWT::JWK.new(rsa_key.public_key, kid: kid).export]
    }

    stub_request(:get, "https://slack.com/openid/connect/keys")
      .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

    strategy = build_strategy
    token = FakeAccessToken.new(realistic_raw_info_payload, id_token: id_token)
    strategy.define_singleton_method(:access_token) { token }
    strategy.define_singleton_method(:session) do
      {"omniauth.nonce" => "test-nonce-value"}
    end

    extra = strategy.extra

    assert_equal id_token, extra["id_token"]
    assert_equal REALISTIC_USER_ID, extra["id_info"]["sub"]
    assert_equal REALISTIC_TEAM_ID, extra["id_info"]["https://slack.com/team_id"]
    assert_equal REALISTIC_TEAM_NAME, extra["id_info"]["https://slack.com/team_name"]
    assert_equal REALISTIC_EMAIL, extra["id_info"]["email"]
    assert_equal REALISTIC_PICTURE, extra["id_info"]["picture"]
    refute extra["id_info"]["https://slack.com/team_image_default"]
  end

  def test_info_hides_unverified_email
    strategy = build_strategy
    payload = {
      "sub" => "U0R7MFMJM",
      "name" => "Kain",
      "email" => "kain@example.test",
      "email_verified" => false
    }

    strategy.instance_variable_set(:@raw_info, payload)

    refute strategy.info.key?(:email)
    assert_equal "kain@example.test", strategy.info[:unverified_email]
  end

  def test_jwks_verification_decodes_and_verifies_id_token
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    kid = "test-key-id"
    now = Time.now.to_i
    id_token_payload = realistic_id_token_payload(
      aud: "client-id",
      nonce: "test-nonce-value",
      iat: now,
      exp: now + 3600,
      auth_time: now
    )
    id_token = JWT.encode(id_token_payload, rsa_key, "RS256", {kid: kid})

    jwks_response = {
      keys: [JWT::JWK.new(rsa_key.public_key, kid: kid).export]
    }

    stub_request(:get, "https://slack.com/openid/connect/keys")
      .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

    strategy = build_strategy
    strategy.define_singleton_method(:session) do
      {"omniauth.nonce" => "test-nonce-value"}
    end

    result = strategy.send(:decode_and_verify_id_token, id_token)

    assert_equal REALISTIC_USER_ID, result["sub"]
    assert_equal REALISTIC_EMAIL, result["email"]
    assert_equal "https://slack.com", result["iss"]
    assert_equal REALISTIC_TEAM_NAME, result["https://slack.com/team_name"]
    assert_equal REALISTIC_TEAM_DOMAIN, result["https://slack.com/team_domain"]
    refute result["https://slack.com/team_image_default"]
  end

  def test_nonce_mismatch_raises_callback_error
    rsa_key = OpenSSL::PKey::RSA.generate(2048)
    kid = "test-key-id"
    id_token_payload = {
      "iss" => "https://slack.com",
      "aud" => "client-id",
      "sub" => "U0R7MFMJM",
      "nonce" => "correct-nonce",
      "iat" => Time.now.to_i,
      "exp" => Time.now.to_i + 3600
    }
    id_token = JWT.encode(id_token_payload, rsa_key, "RS256", {kid: kid})

    jwks_response = {
      keys: [JWT::JWK.new(rsa_key.public_key, kid: kid).export]
    }

    stub_request(:get, "https://slack.com/openid/connect/keys")
      .to_return(status: 200, body: jwks_response.to_json, headers: {"Content-Type" => "application/json"})

    strategy = build_strategy
    strategy.define_singleton_method(:session) do
      {"omniauth.nonce" => "wrong-nonce"}
    end

    assert_raises(OmniAuth::Strategies::Slack2::CallbackError) do
      strategy.send(:decode_and_verify_id_token, id_token)
    end
  end

  def test_skip_jwt_bypasses_verification
    strategy = build_strategy
    strategy.options[:skip_jwt] = true

    payload = {"sub" => "U0R7MFMJM", "email" => "kain@example.test"}
    unsigned_token = [
      Base64.urlsafe_encode64('{"alg":"none"}', padding: false),
      Base64.urlsafe_encode64(payload.to_json, padding: false),
      ""
    ].join(".")

    result = strategy.send(:verify_and_decode_id_token, unsigned_token)

    assert_equal "U0R7MFMJM", result["sub"]
  end

  def test_nonce_is_auto_generated_in_authorize_params
    strategy = build_strategy
    session = {}
    request = Rack::Request.new(Rack::MockRequest.env_for("/auth/slack2"))
    strategy.define_singleton_method(:request) { request }
    strategy.define_singleton_method(:session) { session }

    params = strategy.authorize_params

    refute_nil params[:nonce]
    assert_equal params[:nonce], session["omniauth.nonce"]
  end

  def test_pkce_is_enabled_by_default_in_authorize_params
    strategy = build_strategy
    session = {}
    request = Rack::Request.new(Rack::MockRequest.env_for("/auth/slack2"))
    strategy.define_singleton_method(:request) { request }
    strategy.define_singleton_method(:session) { session }

    params = strategy.authorize_params

    refute_nil params[:code_challenge]
    assert_equal "S256", params[:code_challenge_method]
    refute_nil session["omniauth.pkce.verifier"]
  end

  def test_token_params_include_pkce_code_verifier
    strategy = build_strategy
    session = {"omniauth.pkce.verifier" => "stored-verifier"}
    strategy.define_singleton_method(:session) { session }

    params = strategy.send(:token_params)

    assert_equal "stored-verifier", params[:code_verifier]
    refute session.key?("omniauth.pkce.verifier")
  end

  def test_supports_slack_strategy_name_for_compatibility
    legacy_strategy = OmniAuth::Strategies::Slack.new(nil, "client-id", "client-secret")

    assert_equal "slack", legacy_strategy.options.name
    assert_equal "https://slack.com/openid/connect/authorize", legacy_strategy.options.client_options.authorize_url
  end

  def test_callback_url_prefers_configured_value
    strategy = build_strategy
    callback = "https://example.test/auth/slack2/callback"
    strategy.options[:callback_url] = callback

    assert_equal callback, strategy.callback_url
  end

  def test_query_string_is_ignored_during_callback_request
    strategy = build_strategy
    request = Rack::Request.new(Rack::MockRequest.env_for("/auth/slack2/callback?code=abc&state=xyz"))
    strategy.define_singleton_method(:request) { request }

    assert_equal "", strategy.query_string
  end

  def test_authorize_params_preserves_team_option
    strategy = build_strategy
    request = Rack::Request.new(Rack::MockRequest.env_for("/auth/slack2?team=T0123ABC456"))
    strategy.define_singleton_method(:request) { request }
    strategy.define_singleton_method(:session) { {} }

    params = strategy.authorize_params

    assert_equal "T0123ABC456", params[:team]
  end

  class FakeAccessToken
    attr_reader :params, :token, :refresh_token, :expires_at

    def initialize(parsed_payload, id_token: nil)
      @parsed_payload = parsed_payload
      @id_token = id_token
      @params = {"scope" => TOKEN_SCOPE}
      @token = "access-token"
      @refresh_token = "refresh-token"
      @expires_at = 1_772_691_847
    end

    def get(path)
      @calls ||= []
      @calls << {path: path}
      Struct.new(:parsed).new(@parsed_payload)
    end

    def [](key)
      {"id_token" => @id_token}[key]
    end

    def expires?
      true
    end
  end

  private

  def realistic_raw_info_payload
    {
      "ok" => true,
      "sub" => REALISTIC_USER_ID,
      "https://slack.com/user_id" => REALISTIC_USER_ID,
      "https://slack.com/team_id" => REALISTIC_TEAM_ID,
      "email" => REALISTIC_EMAIL,
      "email_verified" => true,
      "date_email_verified" => REALISTIC_DATE_EMAIL_VERIFIED,
      "name" => "Sample User",
      "picture" => REALISTIC_PICTURE,
      "given_name" => "Sample",
      "family_name" => "User",
      "locale" => "en-US",
      "https://slack.com/team_name" => REALISTIC_TEAM_NAME,
      "https://slack.com/team_domain" => REALISTIC_TEAM_DOMAIN,
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
      "nonce" => nonce,
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
    }
  end
end
