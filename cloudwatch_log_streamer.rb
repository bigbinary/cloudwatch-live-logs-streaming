require 'aws-sdk-cloudwatchlogs'
require 'aws-sdk-cognitoidentity'
require 'aws-sdk-sts'
require 'time'
require 'json'
require 'colorize'
require 'optimist'

class CloudWatchLogStreamer
  POLL_INTERVAL = 1.0
  MAX_STREAMS = 10
  LOG_HISTORY_MINUTES = 5

  def initialize(options)
    @log_group_name = options[:log_group_name]
    @identity_pool_id = options[:identity_pool_id]
    @region = options[:region] || @identity_pool_id&.split(':')&.first || 'us-east-1'
    @poll_interval = options[:poll_interval] || POLL_INTERVAL
    @max_streams = options[:max_streams] || MAX_STREAMS
    @verbose = options[:verbose] || false
    @show_stream_name = options[:show_stream] || false
    @minutes = options[:minutes] || LOG_HISTORY_MINUTES
    @last_ingested_map = {}
    @backoff_sleep = 1
    
    setup_cloudwatch_client
    colorize_log_levels
  end
  
  def setup_cloudwatch_client
    return if @identity_pool_id.nil?

    log "Setting up CloudWatch client..." if @verbose
    
    cognito_client = Aws::CognitoIdentity::Client.new(region: @region)
    
    # Get identity ID from the identity pool (unauthenticated access)
    resp = cognito_client.get_id(
      identity_pool_id: @identity_pool_id,
      logins: {}
    )
    
    # Get credentials for the identity
    credentials_resp = cognito_client.get_credentials_for_identity(
      identity_id: resp.identity_id,
      logins: {}
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

