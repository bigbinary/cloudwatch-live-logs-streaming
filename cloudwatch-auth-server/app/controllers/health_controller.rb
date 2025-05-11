class HealthController < ApplicationController
  skip_before_action :authenticate_request, only: [:check]

  def check
    render json: { status: 'ok' }, status: :ok
  end
end

