require 'aws-sdk-cloudwatchlogs'
require 'aws-sdk-cognitoidentity'
require 'aws-sdk-sts'
require 'net/http'
require 'uri'
require 'time'
require 'json'
require 'colorize'
require 'optimist'

class CloudWatchLogStreamer
  TOKEN_REFRESH_THRESHOLD = 300 # Refresh token if it expires in less than 5 minutes
  POLL_INTERVAL = 2.0
  MAX_STREAMS = 10
  LOG_HISTORY_MINUTES = 5

  def initialize(options)
    @log_group_name = options[:log_group_name]
    @auth_server_url = options[:auth_url]
    @username = options[:username]
    @password = options[:password]
    @identity_pool_id = options[:identity_pool_id]
    @region = @identity_pool_id&.split(':')&.first || 'us-east-1'
    @poll_interval = options[:poll_interval] || POLL_INTERVAL
    @max_streams = options[:max_streams] || MAX_STREAMS
    @verbose = options[:verbose] || false
    @show_stream_name = options[:show_stream] || false
    @minutes = options[:minutes] || LOG_HISTORY_MINUTES
    @last_ingested_map = {}
    @tokens = nil
    @backoff_sleep = 1
    
    authenticate
    colorize_log_levels
  end
  
  def authenticate
    log "Authenticating with auth server..." if @verbose
    
    uri = URI("#{@auth_server_url}/auth/sign_in")
    request = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
    request.body = { username: @username, password: @password }.to_json
    
    response = make_http_request(uri, request)
    
    unless response.is_a?(Net::HTTPSuccess)
      raise "Authentication failed: #{response.body}"
    end
    
    @tokens = JSON.parse(response.body)
    log "Successfully authenticated" if @verbose
    
    setup_cloudwatch_client
  end
  
  def make_http_request(uri, request)
    http = Net::HTTP.new(uri.hostname, uri.port)
    http.use_ssl = uri.scheme == 'https'
    http.request(request)
  end
  
  def refresh_tokens
    return if @tokens.nil? || !@tokens['refresh_token']
    
    log "Refreshing tokens..." if @verbose
    
    uri = URI("#{@auth_server_url}/auth/refresh_token")
    request = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
    request.body = { 
      refresh_token: @tokens['refresh_token'],
      username: @username 
    }.to_json
    
    response = make_http_request(uri, request)
    
    unless response.is_a?(Net::HTTPSuccess)
      log "Token refresh failed: #{response.body}" if @verbose
      # If refresh fails, try full authentication
      authenticate
      return
    end
    
    @tokens = JSON.parse(response.body)
    log "Successfully refreshed tokens" if @verbose
    @backoff_sleep = 1
    
    setup_cloudwatch_client
  end
  
  def setup_cloudwatch_client
    return if @identity_pool_id.nil? || @tokens.nil?

    log "Setting up CloudWatch client..." if @verbose
    
    cognito_client = Aws::CognitoIdentity::Client.new(region: @region)
    
    # Extract the user pool ID from the token's issuer
    id_token = @tokens['id_token']
    if !id_token
      raise "Failed to get AWS credentials from auth server"
    end
    
    resp = cognito_client.get_id(
      identity_pool_id: @identity_pool_id,
      logins: {
        "cognito-idp.#{@region}.amazonaws.com/#{extract_user_pool_id}" => id_token
      }
    )
    
    credentials_resp = cognito_client.get_credentials_for_identity(
      identity_id: resp.identity_id,
      logins: {
        "cognito-idp.#{@region}.amazonaws.com/#{extract_user_pool_id}" => id_token
      }
    )
    
    credentials = credentials_resp.credentials
    
    @client = Aws::CloudWatchLogs::Client.new(
      region: @region,
      credentials: Aws::Credentials.new(
        credentials.access_key_id,
        credentials.secret_key,
        credentials.session_token
      )
    )
    
    log "CloudWatch client setup complete" if @verbose
    verify_log_group
  end
  
  def extract_user_pool_id
    parts = @tokens['id_token'].split('.')
    raise "Invalid ID token format" if parts.length < 2

    # Decode the JWT payload
    payload = JSON.parse(Base64.decode64(parts[1] + '=='))
    
    # Extract the user pool ID from the issuer claim
    iss = payload['iss']
    user_pool_id = iss.split('/').last
    
    log "Extracted user pool ID: #{user_pool_id}" if @verbose
    user_pool_id
  end
  
  def verify_log_group
    log "Verifying log group: #{@log_group_name}" if @verbose
    begin
      response = @client.describe_log_groups(log_group_name_prefix: @log_group_name)
      unless response.log_groups.any? { |g| g.log_group_name == @log_group_name }
        raise "Log group '#{@log_group_name}' does not exist"
      end
    rescue => e
      raise "Failed to verify log group: #{e.message}"
    end
    log "Log group verified" if @verbose
  end
  
  def colorize_log_levels
    @colors = {
      'ERROR' => :red,
      'WARN' => :yellow,
      'WARNING' => :yellow,
      'INFO' => :green,
      'DEBUG' => :cyan,
      'TRACE' => :magenta
    }
  end
  
  def parse_log_message(message)
    if message.strip.start_with?('{') && message.strip.end_with?('}')
      begin
        parsed = JSON.parse(message)
        timestamp = parsed['timestamp'] || parsed['time'] || parsed['@timestamp']
        level = parsed['level'] || parsed['severity'] || parsed['log_level'] || 'INFO'
        message = parsed['message'] || parsed['msg'] || message
        return { timestamp: timestamp, level: level, message: message }
      rescue JSON::ParserError
      end
    end
    
    level_match = message.match(/\b(ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE)\b/i)
    level = level_match ? level_match[1].upcase : 'INFO'
    
    return { timestamp: nil, level: level, message: message }
  end
  
  def colorize_output(parsed)
    level = parsed[:level].upcase
    color = @colors[level] || :white
    formatted_level = level.ljust(7)
    "#{formatted_level.colorize(color)} #{parsed[:message]}"
  end
  
  def log(message)
    puts message.colorize(:blue)
  end
  
  def stream_logs
    puts "Connected to log group: #{@log_group_name}".colorize(:green)
    puts "Starting log streaming...".colorize(:green)
    puts "Press Ctrl+C to stop.".colorize(:yellow)
    
    start_time = (Time.now.to_i - @minutes * 60) * 1000  # x minutes ago
    
    loop do
      begin
        check_token_expiration
        fetch_and_display_logs(start_time)
        sleep @poll_interval
      rescue Interrupt
        puts "\nLog streaming stopped.".colorize(:yellow)
        exit 0
      rescue StandardError => e
        warn "Error: #{e.message}".colorize(:red)
        sleep backoff_and_increment
      end
    end
  end
  
  def check_token_expiration
    return unless @tokens && @tokens['exp']
    
    expiry_time = Time.at(@tokens['exp'])
    current_time = Time.now
    
    # If token expires in less than 5 minutes, refresh it
    if expiry_time - current_time < TOKEN_REFRESH_THRESHOLD
      log "Token expiring soon, refreshing..." if @verbose
      refresh_tokens
    end
  end
  
  def backoff_and_increment
    delay = @backoff_sleep
    @backoff_sleep = [@backoff_sleep * 2, 30].min  # Exponential backoff with max 30 seconds
    delay
  end
  
  def fetch_and_display_logs(start_time)
    streams_resp = @client.describe_log_streams(
      log_group_name: @log_group_name,
      order_by: 'LastEventTime',
      descending: true,
      limit: @max_streams
    )
    
    streams_resp.log_streams.each do |stream|
      stream_start_time = @last_ingested_map[stream.log_stream_name] || start_time
      
      events_resp = @client.get_log_events(
        log_group_name: @log_group_name,
        log_stream_name: stream.log_stream_name,
        start_time: stream_start_time + 1,
        start_from_head: true
      )
      
      events_resp.events.each do |event|
        parsed = parse_log_message(event.message)
        timestamp = Time.at(event.timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')
        
        if @show_stream_name
          display_text = "[#{timestamp}] [#{stream.log_stream_name}] #{colorize_output(parsed)}"
        else
          display_text = "[#{timestamp}] #{colorize_output(parsed)}"
        end
        
        puts display_text
        
        # Update the last ingested timestamp for this stream
        @last_ingested_map[stream.log_stream_name] = event.timestamp
      end
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  opts = Optimist::options do
    banner "Usage: ruby cloudwatch_log_streamer.rb [options]"
    opt :log_group_name, "CloudWatch Log Group Name", type: :string, required: true
    opt :auth_url, "Authentication Server URL", type: :string, required: true
    opt :username, "Username for authentication", type: :string, required: true
    opt :password, "Password for authentication", type: :string, required: true
    opt :identity_pool_id, "Cognito Identity Pool ID", type: :string, required: true
    opt :region, "AWS Region (default: extracted from identity pool ID)", type: :string
    opt :minutes, "Minutes of log history to retrieve", type: :int, default: CloudWatchLogStreamer::LOG_HISTORY_MINUTES
    opt :poll_interval, "Seconds between log polling", type: :float, default: CloudWatchLogStreamer::POLL_INTERVAL
    opt :max_streams, "Maximum number of log streams to process", type: :int, default: CloudWatchLogStreamer::MAX_STREAMS
    opt :verbose, "Enable verbose logging", default: false
    opt :show_stream, "Show stream name in log output", default: false
  end
  
  streamer = CloudWatchLogStreamer.new(opts)
  streamer.stream_logs
end

