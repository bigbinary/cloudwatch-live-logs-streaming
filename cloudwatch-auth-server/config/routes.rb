Rails.application.routes.draw do
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check
  get '/health', to: 'health#check'
  
  post '/auth/sign_in', to: 'auth#sign_in'
  post '/auth/refresh_token', to: 'auth#refresh_token'

  # Defines the root path route ("/")
  # root "posts#index"
end
