# CloudWatch Log Streamer

Real-time streaming of AWS CloudWatch logs directly using Cognito authentication. 

- **Ruby CLI**: Command-line interface for terminal-based log streaming
- **HTML Viewer**: Web-based interface for browser-based log streaming

The CloudWatch Log Streamer tools allow you to view AWS CloudWatch logs in real-time. Both implementations authenticate directly with AWS Cognito using an Identity Pool and stream logs from specified CloudWatch Log Groups.

## Requirements
- AWS Cognito Identity Pool with unauthenticated access enabled
- CloudWatch Log Group with appropriate read permissions
- IAM role configured for the Cognito Identity Pool with permissions for CloudWatch Logs:
  - `logs:DescribeLogGroups`
  - `logs:DescribeLogStreams`
  - `logs:GetLogEvents`

### Ruby Implementation
- Ruby 2.7 or higher
- Required gems:
  - aws-sdk-cloudwatchlogs
  - aws-sdk-cognitoidentity
  - aws-sdk-sts
  - colorize
  - optimist
  - json

### HTML Implementation
- Modern web browser with JavaScript enabled
- No server required (static HTML file)

## Setup Instructions

### Ruby Implementation

1. Install required gems:
   ```bash
   gem install aws-sdk-cloudwatchlogs aws-sdk-cognitoidentity aws-sdk-sts colorize optimist json
   ```

2. Save the `cloudwatch_log_streamer.rb` file to your local system

### HTML Implementation

1. Download the `cloudwatch_log_viewer.html` file to your computer
2. Open the file in any modern web browser

## Usage Examples

### Ruby Implementation

Basic usage:
```bash
ruby cloudwatch_log_streamer.rb --log-group-name /aws/lambda/my-function --identity-pool-id us-east-1:12345678-1234-1234-1234-123456789012
```

## Authentication Details

Both implementations use AWS Cognito for direct authentication without requiring an authentication server:

1. **Identity Pool Authentication**: Both tools use a Cognito Identity Pool to obtain AWS credentials
2. **Unauthenticated Access**: The implementations use the unauthenticated identity flow to obtain temporary credentials
3. **IAM Role Permissions**: The unauthenticated IAM role needs CloudWatch Logs read permissions
4. **Security**: Access is controlled through AWS IAM, so you can restrict which logs are accessible

### IAM Policy Example

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:GetLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
```

