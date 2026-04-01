# frozen_string_literal: true

require "base64"
require "jwt"
require "net/http"
require "omniauth-oauth2"
require "securerandom"
require "uri"

module OmniAuth
  module Strategies
    # OmniAuth strategy for Slack OpenID Connect.
    class Slack2 < OmniAuth::Strategies::OAuth2
      ISSUER = "https://slack.com"
      JWKS_URL = "https://slack.com/openid/connect/keys"
      USER_INFO_URL = "https://slack.com/api/openid.connect.userInfo"
      DEFAULT_SCOPE = "openid email profile"

      option :name, "slack2"
      option :authorize_options, %i[scope state nonce team]
      option :scope, DEFAULT_SCOPE
      option :pkce, true
      option :skip_jwt, false

      option :client_options,
        site: ISSUER,
        authorize_url: "https://slack.com/openid/connect/authorize",
        token_url: "https://slack.com/api/openid.connect.token",
        connection_opts: {
          headers: {
            user_agent: "icoretech-omniauth-slack2 gem",
            accept: "application/json",
            content_type: "application/json"
          }
        }

      uid { raw_info["sub"] }

      info do
        {
          name: raw_info["name"],
          email: raw_info["email_verified"] ? raw_info["email"] : nil,
          unverified_email: raw_info["email"],
          email_verified: raw_info["email_verified"],
          first_name: raw_info["given_name"],
          last_name: raw_info["family_name"],
          image: raw_info["picture"],
          locale: raw_info["locale"]
        }.reject { |_, v| v.nil? || (v.respond_to?(:empty?) && v.empty?) }
      end

      credentials do
        {
          "token" => access_token.token,
          "refresh_token" => access_token.refresh_token,
          "expires_at" => access_token.expires_at,
          "expires" => access_token.expires?,
          "scope" => token_scope
        }.compact
      end

      extra do
        data = {
          "raw_info" => raw_info,
          "team_id" => raw_info["https://slack.com/team_id"],
          "team_name" => raw_info["https://slack.com/team_name"],
          "team_domain" => raw_info["https://slack.com/team_domain"]
        }

        id_token_raw = access_token["id_token"]
        unless blank?(id_token_raw)
          data["id_token"] = id_token_raw
          decoded = verify_and_decode_id_token(id_token_raw)
          data["id_info"] = decoded if decoded
        end

        data.compact
      end

      # Error raised when callback validation fails.
      class CallbackError < StandardError; end

      def authorize_params
        super.tap do |params|
          apply_request_authorize_overrides(params)
          params[:nonce] ||= new_nonce
        end
      end

      def callback_url
        options[:callback_url] || options[:redirect_uri] || super
      end

      def query_string
        return "" if request.params["code"]

        super
      end

      def raw_info
        @raw_info ||= access_token.get(USER_INFO_URL).parsed
      end

      private

      def verify_and_decode_id_token(token)
        return skip_jwt_decode(token) if options[:skip_jwt]

        decode_and_verify_id_token(token)
      end

      def skip_jwt_decode(token)
        payload, = JWT.decode(token, nil, false)
        payload
      rescue JWT::DecodeError
        nil
      end

      def decode_and_verify_id_token(token)
        jwk = fetch_jwk(extract_kid(token))
        payload = decode_payload(token, jwk)
        verify_nonce!(payload)
        payload
      rescue JSON::ParserError, ArgumentError, JWT::DecodeError => e
        raise CallbackError, e.message
      end

      def verify_nonce!(payload)
        return unless payload.key?("nonce")

        expected_nonce = stored_nonce
        return if payload["nonce"] == expected_nonce

        raise CallbackError, "nonce does not match"
      end

      def fetch_jwk(expected_kid)
        jwks = fetch_jwks_keys
        matching_key = jwks.find { |key| key["kid"] == expected_kid }
        raise CallbackError, "JWKS key not found: #{expected_kid}" unless matching_key

        JWT::JWK.import(matching_key)
      rescue JSON::ParserError, SocketError, SystemCallError => e
        raise CallbackError, e.message
      end

      def fetch_jwks_keys
        uri = URI(JWKS_URL)
        response = Net::HTTP.get_response(uri)
        raise CallbackError, "JWKS fetch failed: #{response.code}" unless response.is_a?(Net::HTTPSuccess)

        JSON.parse(response.body).fetch("keys", [])
      end

      def extract_kid(token)
        header_segment = token.split(".").first
        decoded_header = Base64.urlsafe_decode64(pad_base64(header_segment))
        JSON.parse(decoded_header)["kid"]
      end

      def decode_payload(token, jwk)
        payload, = JWT.decode(
          token,
          jwk.public_key,
          true,
          decode_options
        )
        payload
      end

      def decode_options
        {
          algorithms: ["RS256"],
          iss: ISSUER,
          verify_iss: true,
          aud: options.client_id,
          verify_aud: true,
          verify_iat: true,
          verify_expiration: true
        }
      end

      def new_nonce
        session["omniauth.nonce"] = SecureRandom.urlsafe_base64(16)
      end

      def stored_nonce
        session.delete("omniauth.nonce")
      end

      def apply_request_authorize_overrides(params)
        options[:authorize_options].each do |key|
          request_value = request.params[key.to_s]
          params[key] = request_value unless blank?(request_value)
        end
      end

      def token_scope
        access_token.params["scope"] || access_token["scope"]
      end

      def pad_base64(value)
        value + ("=" * ((4 - (value.length % 4)) % 4))
      end

      def blank?(value)
        value.nil? || (value.respond_to?(:empty?) && value.empty?)
      end
    end

    # Backward-compatible strategy name for existing callback paths.
    class Slack < Slack2
      option :name, "slack"
    end
  end
end

OmniAuth.config.add_camelization "slack2", "Slack2"
OmniAuth.config.add_camelization "slack", "Slack"
