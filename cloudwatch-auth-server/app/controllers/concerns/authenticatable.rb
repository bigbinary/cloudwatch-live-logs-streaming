module Authenticatable
  extend ActiveSupport::Concern

  def authenticate_request
    header = request.headers['Authorization']
    if header && token = header.split(' ').last
      decoded = JsonWebToken.verify(token)
      if decoded
        @current_user = decoded
        return true
      end
    end
    render json: { error: 'Unauthorized' }, status: :unauthorized
  end

  def current_user
    @current_user
  end
end

