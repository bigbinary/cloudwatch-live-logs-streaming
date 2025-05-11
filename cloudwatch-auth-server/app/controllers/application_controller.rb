class ApplicationController < ActionController::API
  include Authenticatable
  before_action :authenticate_request
end
