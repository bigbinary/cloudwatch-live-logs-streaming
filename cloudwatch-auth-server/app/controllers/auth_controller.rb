class AuthController < ApplicationController
  skip_before_action :authenticate_request, only: [:sign_in, :refresh_token]
  require 'base64'
  require 'openssl'

  def sign_in
    begin
      auth_response = COGNITO_CLIENT.initiate_auth({
        client_id: ENV['COGNITO_CLIENT_ID'],
        auth_flow: 'USER_PASSWORD_AUTH',
        auth_parameters: {
          'USERNAME' => params[:username],
          'PASSWORD' => params[:password],
          'SECRET_HASH' => calculate_secret_hash(params[:username])
        }
      })

      render json: {
        access_token: auth_response.authentication_result.access_token,
        id_token: auth_response.authentication_result.id_token,
        refresh_token: auth_response.authentication_result.refresh_token
      }
    rescue Aws::CognitoIdentityProvider::Errors::NotAuthorizedException
      render json: { error: 'Invalid credentials' }, status: :unauthorized
    rescue => e
      render json: { error: e.message }, status: :internal_server_error
    end
  end

  def refresh_token
    begin
      auth_response = COGNITO_CLIENT.initiate_auth({
        client_id: ENV['COGNITO_CLIENT_ID'],
        auth_flow: 'REFRESH_TOKEN_AUTH',
        auth_parameters: {
          'REFRESH_TOKEN' => params[:refresh_token],
          'SECRET_HASH' => calculate_secret_hash(params[:username])
        }
      })

      render json: {
        access_token: auth_response.authentication_result.access_token,
        id_token: auth_response.authentication_result.id_token
      }
    rescue => e
      render json: { error: e.message }, status: :unauthorized
    end
  end

  private

  def calculate_secret_hash(username)
    message = username + ENV['COGNITO_CLIENT_ID']
    hmac = OpenSSL::HMAC.digest(
      OpenSSL::Digest.new('sha256'),
      ENV['COGNITO_CLIENT_SECRET'],
      message
    )
    Base64.strict_encode64(hmac)
  end
end
