# Wiz Sensor Version Inventory Tool

A Python tool that queries the Wiz API to retrieve comprehensive information about all Wiz Sensor deployments across your cloud infrastructure. This tool helps you monitor sensor versions, identify end-of-life deployments, and ensure your sensors are up-to-date.

## Features

- **Complete Sensor Inventory**: Discover all Wiz Sensor deployments across AWS, Azure, GCP, and Kubernetes
- **Version Lifecycle Management**: Track current versions, EOL dates, and latest available versions
- **OAuth2 Authentication**: Secure client credentials flow with automatic DC detection
- **Multiple Output Formats**: Human-readable tables or CSV for analysis/reporting
- **Filtering Options**: Focus on problematic sensors that need attention
- **Comprehensive Help**: Built-in documentation with usage examples

## Setup

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Set up environment variables:**
```bash
export WIZ_CLIENT_ID="your_client_id_here"
export WIZ_CLIENT_SECRET="your_client_secret_here"
```

## Usage

### Command Line Options

```bash
python get-data.py [OPTIONS]
```

**Options:**
- `--help, -h` - Show comprehensive help information
- `--eol-only` - Show only problematic sensors (EOL or non-latest versions)  
- `--format FORMAT` - Output format: 'table' (default) or 'csv'

### Examples

**Show all sensors (default table format):**
```bash
python get-data.py
```

**Show only problematic sensors that need attention:**
```bash
python get-data.py --eol-only
```

**Export all sensor data to CSV:**
```bash
python get-data.py --format csv
```

**Export only problematic sensors to CSV:**
```bash
python get-data.py --format csv --eol-only
```

**Save CSV output to file:**
```bash
python get-data.py --format csv > wiz-sensors.csv
```

**Get help information:**
```bash
python get-data.py --help
```

## Output Information

The tool provides the following information for each Wiz Sensor deployment:

| Column | Description |
|--------|-------------|
| Container Name | Name of the container running Wiz Sensor |
| Host Name | Name of the host/VM where container is running |
| Technology | Technology name (always "Wiz Sensor") |
| Current Version | Currently deployed sensor version |
| EOL Date | End of life date for current version |
| Latest Version | Latest available sensor version |
| Is Latest | True if current version is the latest available |
| Is EOL | True if current version is end of life |
| Cloud Platform | Cloud platform (AWS, Azure, GCP, Kubernetes, etc.) |

## Sample Output

**Table Format:**
```
Container Name                    Host Name           Current Version  EOL Date     Latest Version  Is Latest  Is EOL  Cloud Platform
wiz-sensor-container-12345       ip-10-0-1-100       1.0.6816        None         1.0.6816        True       False   AWS
wiz-sensor-container-67890       ip-10-0-2-200       1.0.3891        2023-12-01   1.0.6816        False      True    AWS
```

**CSV Format:**
```csv
Container Name,Host Name,Technology,Current Version,EOL Date,Latest Version,Is Latest,Is EOL,Cloud Platform
wiz-sensor-container-12345,ip-10-0-1-100,Wiz Sensor,1.0.6816,,1.0.6816,True,False,AWS
wiz-sensor-container-67890,ip-10-0-2-200,Wiz Sensor,1.0.3891,2023-12-01,1.0.6816,False,True,AWS
```

## Authentication

The tool uses OAuth2 client credentials flow to authenticate with the Wiz API:

1. **Service Account Setup**: Create a service account in your Wiz tenant with appropriate permissions
2. **Environment Variables**: Set `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET`
3. **Automatic DC Detection**: The tool automatically detects your Wiz data center from the JWT token
4. **Secure Headers**: All API requests include proper authentication headers

### Required Permissions

Your Wiz service account needs the following permissions:
- Read access to hosted technologies
- Read access to container and virtual machine inventory
- Read access to cloud platform information

## Technical Implementation

### GraphQL Query Structure

The tool uses a complex GraphQL query that traverses relationships:
```
HOSTED_TECHNOLOGY (Wiz Sensor) → CONTAINER_IMAGE → CONTAINER → VIRTUAL_MACHINE
```

This relationship traversal allows the tool to:
- Find all Wiz Sensor technology deployments
- Identify the containers running these sensors
- Locate the host VMs where containers are deployed
- Extract version and lifecycle information

### Key Classes

- **WizClient**: Handles OAuth2 authentication and GraphQL queries
- **Pagination Support**: Automatically handles large result sets
- **Error Handling**: Comprehensive error handling for network and API issues

## Troubleshooting

### Common Issues

**Authentication Errors:**
- Verify `WIZ_CLIENT_ID` and `WIZ_CLIENT_SECRET` are set correctly
- Ensure your service account has not been disabled
- Check that your service account has the required permissions

**Network Errors:**
- Verify internet connectivity
- Check if your organization uses a proxy (not currently supported)
- Ensure Wiz API endpoints are accessible from your network

**No Results:**
- Verify Wiz Sensors are actually deployed in your environment
- Check that your service account has access to the projects containing sensors
- Ensure sensors are properly registered in Wiz inventory

### Debug Information

For troubleshooting, the tool provides:
- Clear error messages for authentication failures
- Network timeout handling
- Graceful handling of API rate limits
- Detailed help information via `--help`

## Exit Codes

- `0` - Success
- `1` - Error (authentication, network, or argument parsing)

## Security Considerations

- **Environment Variables**: Never commit credentials to version control
- **Token Security**: Tokens are handled securely and not logged
- **API Endpoints**: Endpoints are automatically constructed using extracted DC values
- **Timeout Settings**: All requests include appropriate timeout values 