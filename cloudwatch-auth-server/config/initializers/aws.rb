require 'aws-sdk-cognitoidentityprovider'

COGNITO_CLIENT = Aws::CognitoIdentityProvider::Client.new(
  region: ENV['AWS_REGION'],
  credentials: Aws::Credentials.new(
    ENV['AWS_ACCESS_KEY_ID'],
    ENV['AWS_SECRET_ACCESS_KEY']
  )
)

