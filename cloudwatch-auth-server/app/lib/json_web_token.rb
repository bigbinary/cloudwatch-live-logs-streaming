require 'net/http'
require 'jwt'

class JsonWebToken
  def self.verify(token)
    JWT.decode(token, nil,
               true, # Verify the signature
               algorithms: ['RS256'],
               jwks: jwks)[0]
  rescue JWT::DecodeError
    nil
  end

  def self.jwks
    # Get the JSON Web Key Set from Cognito
    jwks_uri = "https://cognito-idp.#{ENV['AWS_REGION']}.amazonaws.com/#{ENV['COGNITO_USER_POOL_ID']}/.well-known/jwks.json"
    response = Net::HTTP.get_response(URI(jwks_uri))
    JSON.parse(response.body)
  end
end

