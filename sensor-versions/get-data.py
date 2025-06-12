#!/usr/bin/env python3
"""
Wiz Sensor Version Inventory Tool

This script queries the Wiz API to retrieve information about all Wiz Sensor deployments
across your cloud infrastructure. It shows container names, host names, current versions,
end-of-life dates, and other version lifecycle information.

Features:
- OAuth2 authentication to Wiz API
- GraphQL queries with automatic pagination
- Flattened relationship view (HOSTED_TECHNOLOGY -> CONTAINER -> VIRTUAL_MACHINE)
- Multiple output formats (table, CSV)
- Filtering options (all sensors vs. EOL/problematic only)
- Verbose logging for troubleshooting and monitoring

Usage Examples:
    python get-data.py                           # Show all sensors in table format
    python get-data.py --eol-only               # Show only problematic sensors
    python get-data.py --format csv             # Export all to CSV
    python get-data.py --format csv --eol-only  # Export problematic sensors to CSV
    python get-data.py --verbose                # Show detailed logging information

Environment Variables Required:
    WIZ_CLIENT_ID     - Your Wiz OAuth2 client ID
    WIZ_CLIENT_SECRET - Your Wiz OAuth2 client secret
"""

import os
import requests
import json
import base64
import logging
from typing import Optional, Dict, Any
from tabulate import tabulate

# Headers for different types of HTTP requests to Wiz API
HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded"}  # OAuth2 token requests
HEADERS = {"Content-Type": "application/json"}                        # GraphQL API requests

# Set up logging
logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False):
    """
    Set up logging configuration based on verbosity level.
    
    Args:
        verbose: If True, enable DEBUG level logging. Otherwise, use INFO level.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    if verbose:
        logger.info("Verbose logging enabled")
    else:
        logger.info("Standard logging enabled")


def pad_base64(data):
    """
    Add padding to base64 string if needed for proper decoding.
    
    Base64 strings must be a multiple of 4 characters. This function
    adds the necessary '=' padding characters to ensure proper decoding
    of JWT token payloads from the Wiz authentication response.
    """
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return data


def extract_table_data(result):
    """
    Extract and flatten relationship data from GraphQL result.
    
    This function processes the complex GraphQL response containing relationship
    paths (HOSTED_TECHNOLOGY -> CONTAINER -> VIRTUAL_MACHINE) and flattens them
    into a simple table format with one row per Wiz Sensor deployment.
    
    Args:
        result: GraphQL response containing nodes with entities
        
    Returns:
        List of lists containing flattened sensor data for table display
    """
    logger.info("Starting data extraction from GraphQL result")
    table_data = []
    
    def safe_get(value, default='N/A'):
        """Safely convert values to strings, handling None cases"""
        return str(value) if value is not None else default
    
    if 'data' in result and 'graphSearch' in result['data']:
        nodes = result['data']['graphSearch'].get('nodes', [])
        logger.info(f"Processing {len(nodes)} relationship nodes")
        
        # Process each relationship path (node) from the GraphQL response
        processed_sensors = 0
        skipped_incomplete = 0
        
        for i, node in enumerate(nodes):
            logger.debug(f"Processing node {i+1}/{len(nodes)}")
            entities = node.get('entities', [])
            
            # Group entities by type for this relationship path
            # Each node contains a path: HOSTED_TECHNOLOGY -> CONTAINER -> VIRTUAL_MACHINE
            hosted_tech = None  # The Wiz Sensor technology
            container = None    # The container running the sensor
            vm = None          # The host (VM) running the container
            
            # Categorize entities by their type
            entity_types = []
            for entity in entities:
                entity_type = entity.get('type')
                entity_types.append(entity_type)
                
                if entity_type == 'HOSTED_TECHNOLOGY':
                    hosted_tech = entity
                elif entity_type == 'CONTAINER':
                    container = entity
                elif entity_type == 'VIRTUAL_MACHINE':
                    vm = entity
            
            logger.debug(f"Node {i+1} entity types: {entity_types}")
            
            # Only process complete relationship paths (all three entities present)
            if hosted_tech and container and vm:
                logger.debug(f"Processing complete sensor relationship in node {i+1}")
                

                
                # Extract container information
                container_name = safe_get(container.get('name'))
                
                # Extract host (Virtual Machine) information
                host_name = safe_get(vm.get('name'))
                vm_properties = vm.get('properties', {}) or {}
                cloud_platform = safe_get(vm_properties.get('cloudPlatform'))
                vm_external_id = safe_get(vm_properties.get('externalId'))
                

                
                # Extract technology (Wiz Sensor) information
                tech_properties = hosted_tech.get('properties', {}) or {}
                tech_name = safe_get(tech_properties.get('techName'))
                current_version = safe_get(tech_properties.get('version'))
                
                # Extract version lifecycle information
                version_eol_date = safe_get(tech_properties.get('versionEndOfLifeDate'))
                latest_version = safe_get(tech_properties.get('latestVersion'))
                is_latest = safe_get(tech_properties.get('isLatestVersion'))
                is_eol = safe_get(tech_properties.get('isVersionEndOfLife'))
                
                logger.debug(f"Sensor details - Container: {container_name}, Host: {host_name}, "
                           f"VM External ID: {vm_external_id}, Version: {current_version}, EOL: {is_eol}, Latest: {is_latest}")
                
                # Add flattened row combining data from all three entities
                table_data.append([
                    container_name,       # Container name (full name, no truncation)
                    host_name,           # Host/VM name (full name, no truncation)
                    vm_external_id,      # VM external ID (cloud provider's unique identifier)
                    tech_name,           # Technology name (Wiz Sensor)
                    current_version,     # Current sensor version
                    version_eol_date,    # End of life date
                    latest_version,      # Latest available version
                    is_latest,          # Boolean: is current version the latest?
                    is_eol,             # Boolean: is current version end of life?
                    cloud_platform      # Cloud platform (AWS, Azure, GCP, etc.)
                ])
                
                processed_sensors += 1
            else:
                logger.debug(f"Skipping incomplete relationship in node {i+1} - "
                           f"Missing: {[t for t in ['HOSTED_TECHNOLOGY', 'CONTAINER', 'VIRTUAL_MACHINE'] if t not in entity_types]}")
                skipped_incomplete += 1
        
        logger.info(f"Data extraction completed: {processed_sensors} sensors processed, {skipped_incomplete} incomplete relationships skipped")
    else:
        logger.warning("No valid data found in GraphQL result")
    
    logger.info(f"Extracted {len(table_data)} sensor records")
    return table_data


def print_summary_table(result, show_only_eol=False, output_format='table'):
    """
    Print formatted output of Wiz Sensor data.
    
    Args:
        result: GraphQL response containing sensor data
        show_only_eol: If True, show only problematic sensors (EOL or non-latest)
        output_format: Either 'table' for formatted table or 'csv' for CSV output
    """
    logger.info(f"Preparing output in {output_format} format")
    table_data = extract_table_data(result)
    
    original_count = len(table_data)
    
    # Apply filtering if requested - show only sensors that need attention
    if show_only_eol:
        logger.info("Applying EOL/non-latest filter")
        # Filter for sensors that are either not latest (row[7] == 'False') or EOL (row[8] == 'True')
        # Note: indices shifted due to adding VM External ID column
        table_data = [row for row in table_data if row[7] == 'False' or row[8] == 'True']
        filtered_count = len(table_data)
        logger.info(f"Filtered {original_count} sensors down to {filtered_count} problematic sensors")
    
    # Define column headers for output
    headers = [
        'Container Name',    # Name of the container running Wiz Sensor
        'Host Name',         # Name of the host/VM
        'VM External ID',    # Cloud provider's unique identifier for the VM
        'Technology',        # Should always be "Wiz Sensor"
        'Current Version',   # Currently deployed version
        'EOL Date',          # End of life date for current version
        'Latest Version',    # Latest available version
        'Is Latest',         # True if current version is latest
        'Is EOL',           # True if current version is end of life
        'Cloud Platform'     # AWS, Azure, GCP, etc.
    ]
    
    # Output data in requested format
    if table_data:
        logger.info(f"Displaying {len(table_data)} sensor records")
        if output_format == 'csv':
            logger.debug("Generating CSV output")
            # Output as CSV for spreadsheet/analysis tools
            import csv
            import sys
            writer = csv.writer(sys.stdout)
            writer.writerow(headers)
            writer.writerows(table_data)
        else:  # table format (default)
            logger.debug("Generating table output")
            # Output as formatted table for terminal viewing
            print(tabulate(table_data, headers=headers, tablefmt='grid'))
            print(f"\nTotal Wiz Sensors: {len(table_data)}")
    else:
        # Handle case where no data was found
        logger.warning("No sensor data to display")
        if output_format == 'csv':
            # Still output headers for CSV even if no data
            import csv
            import sys
            writer = csv.writer(sys.stdout)
            writer.writerow(headers)
        else:
            print("No Wiz Sensors found.")


# GraphQL query for finding Wiz Sensor deployments and their relationships
# This optimized query only requests the fields that are actually used by the application
# The relationship path is: HOSTED_TECHNOLOGY (Wiz Sensor) -> CONTAINER -> VIRTUAL_MACHINE (Host)
QUERY = """
    query GraphSearch($query: GraphEntityQueryInput, $projectId: String!, $first: Int, $after: String, $quick: Boolean = true) {
      graphSearch(
        query: $query
        projectId: $projectId
        first: $first
        after: $after
        quick: $quick
      ) {
        pageInfo {
          endCursor
          hasNextPage
        }
        nodes {
          entities {
            id
            name
            type
            properties
          }
        }
      }
    }
"""

# Variables for the optimized GraphQL query
# Only the essential parameters needed for the simplified query
VARIABLES = {
  "quick": True,                        # Use quick mode for faster queries
  "first": 100,                         # Number of results per page
  "query": {
    # This complex relationship query traverses the Wiz graph to find Wiz Sensors and their infrastructure
    # The path is: HOSTED_TECHNOLOGY (Wiz Sensor) -> CONTAINER_IMAGE -> CONTAINER -> VIRTUAL_MACHINE
    "relationships": [
      {
        # First relationship: HOSTED_TECHNOLOGY "RUNS" on CONTAINER_IMAGE (reverse traversal)
        "type": [
          {
            "reverse": True,  # Traverse relationship backwards
            "type": "RUNS"    # Relationship type
          }
        ],
        "with": {
          "relationships": [
            {
              # Second relationship: CONTAINER_IMAGE is "INSTANCE_OF" CONTAINER (reverse traversal)
              "type": [
                {
                  "reverse": True,
                  "type": "INSTANCE_OF"
                }
              ],
              "with": {
                "relationships": [
                  {
                    # Third relationship: CONTAINER "RUNS" on VIRTUAL_MACHINE (reverse traversal)
                    "type": [
                      {
                        "reverse": True,
                        "type": "RUNS"
                      }
                    ],
                    "with": {
                      "select": True,        # Include VIRTUAL_MACHINE entities in results
                      "type": [
                        "VIRTUAL_MACHINE"    # Target entity type (hosts)
                      ]
                    }
                  }
                ],
                "select": True,              # Include CONTAINER entities in results  
                "type": [
                  "CONTAINER"                # Intermediate entity type
                ]
              }
            }
          ],
          "type": [
            "CONTAINER_IMAGE"                # Intermediate entity type
          ]
        }
      }
    ],
    "select": True,                          # Include HOSTED_TECHNOLOGY entities in results
    "type": [
      "HOSTED_TECHNOLOGY"                    # Starting entity type (Wiz Sensors)
    ],
    "where": {
      # Filter to only Wiz Sensor technology (techId "9130")
      "techId": {
        "EQUALS": [
          "9130"                             # Wiz Sensor technology ID
        ]
      }
    }
  },
  "projectId": "*"
}

class WizClient:
    """
    Handles OAuth2 authentication and GraphQL API queries for Wiz platform.
    
    This class manages the complete authentication flow including:
    - OAuth2 client credentials authentication
    - Direct bearer token authentication (from browser/manual extraction)
    - JWT token parsing to extract datacenter (DC) information  
    - Authenticated GraphQL API requests with proper headers
    - Error handling for network and authentication issues
    """
    
    def __init__(self, bearer_token=None):
        """
        Initialize the Wiz client with credentials from environment variables or bearer token.
        
        Args:
            bearer_token: Optional pre-extracted bearer token from browser or other source
        
        Required Environment Variables (if not using bearer_token):
            WIZ_CLIENT_ID: OAuth2 client ID for your Wiz service account
            WIZ_CLIENT_SECRET: OAuth2 client secret for your Wiz service account
        """
        logger.debug("Initializing Wiz client")
        
        self.bearer_token = bearer_token
        self.client_id = os.getenv('WIZ_CLIENT_ID')
        self.client_secret = os.getenv('WIZ_CLIENT_SECRET')
        self.auth_url = 'https://auth.app.wiz.io/oauth/token'
        self.token = None  # Will store the JWT access token
        self.dc = None     # Will store the datacenter identifier from token
        
        if self.bearer_token:
            logger.info("Using provided bearer token for authentication")
            # Extract token from "Bearer <token>" format if needed
            if self.bearer_token.startswith('Bearer '):
                self.token = self.bearer_token[7:]  # Remove "Bearer " prefix
                logger.debug("Removed 'Bearer ' prefix from token")
            else:
                self.token = self.bearer_token
            
            # Extract DC from the provided token
            try:
                self._extract_dc_from_token()
                logger.info(f"Successfully extracted datacenter from provided token: {self.dc}")
            except Exception as e:
                logger.error(f"Failed to extract datacenter from provided token: {e}")
                raise ValueError(f"Invalid bearer token provided: {e}")
        else:
            logger.info("Using OAuth2 client credentials for authentication")
            if not self.client_id or not self.client_secret:
                logger.error("Missing required environment variables: WIZ_CLIENT_ID and/or WIZ_CLIENT_SECRET")
                raise ValueError("WIZ_CLIENT_ID and WIZ_CLIENT_SECRET environment variables must be set when not using bearer token")
            
            logger.debug(f"Client ID found: {self.client_id[:10]}...")
            logger.debug("Client secret found (masked)")
        
        logger.info("Wiz client initialized successfully")
    
    def _extract_dc_from_token(self):
        """Extract datacenter information from JWT token."""
        if not self.token:
            raise ValueError("No token available to extract DC from")
        
        logger.debug("Extracting datacenter information from JWT token")
        token_payload = self.token.split(".")[1]
        response_json_decoded = json.loads(
            base64.standard_b64decode(pad_base64(token_payload))
        )
        self.dc = response_json_decoded["dc"]
        logger.debug(f"Extracted datacenter: {self.dc}")
    
    def authenticate(self) -> Dict[str, Any]:
        """
        Authenticate to Wiz API and retrieve access token and DC value.
        
        If a bearer token was provided during initialization, this method will
        validate it and extract the datacenter. Otherwise, it performs OAuth2
        client credentials authentication.
        
        Returns:
            Dict containing the authentication response (or token info for bearer tokens)
            
        Raises:
            requests.RequestException: If the authentication request fails
            ValueError: If the response doesn't contain expected fields
        """
        if self.bearer_token:
            logger.info("Validating provided bearer token")
            # Token and DC should already be set in __init__, just validate
            if not self.token or not self.dc:
                raise ValueError("Bearer token validation failed - missing token or datacenter")
            
            logger.info(f"Bearer token validated successfully! Datacenter: {self.dc}")
            logger.debug(f"Token (first 20 chars): {self.token[:20]}...")
            
            # Return a mock response for consistency
            return {
                "access_token": self.token,
                "token_type": "Bearer",
                "source": "provided_bearer_token"
            }
        
        # Original OAuth2 authentication flow
        logger.info("Starting OAuth2 authentication to Wiz API")
        logger.debug(f"Authentication URL: {self.auth_url}")
        
        auth_payload = {
            'grant_type': 'client_credentials',
            'audience': 'wiz-api',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        logger.debug("Sending OAuth2 authentication request")
        try:
            response = requests.post(
                url=self.auth_url,
                headers=HEADERS_AUTH,
                data=auth_payload,
                timeout=180
            )
            response.raise_for_status()
            logger.debug(f"OAuth2 authentication request completed with status: {response.status_code}")
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error during OAuth2 authentication: {str(e)}")
            print(f"Error authenticating to Wiz (4xx/5xx): {str(e)}")
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during OAuth2 authentication: {str(e)}")
            print(f"Network problem (DNS failure, refused connection, etc): {str(e)}")
            raise
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout during OAuth2 authentication: {str(e)}")
            print(f"Request timed out: {str(e)}")
            raise
        
        try:
            response_json = response.json()
            token = response_json.get('access_token')
            if not token:
                message = f"Could not retrieve token from Wiz: {response_json.get('message')}"
                logger.error(f"Token not found in OAuth2 response: {message}")
                raise ValueError(message)
                
            logger.debug("OAuth2 access token received successfully")
            
            # Extract DC value from JWT token payload
            self.token = token
            self._extract_dc_from_token()
            
            logger.info(f"OAuth2 authentication successful! Datacenter: {self.dc}")
            logger.debug(f"Token (first 20 chars): {token[:20]}...")
            
            return response_json
            
        except ValueError as exception:
            message = f"Could not parse API response {exception}. Check Service Account details and variables"
            logger.error(f"ValueError during OAuth2 token parsing: {message}")
            raise ValueError(message) from exception
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"JSON decode error during OAuth2 authentication: {e}")
            print(f"Error parsing authentication response: {e}")
            raise
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get headers for authenticated requests.
        
        Returns:
            Dict containing authorization headers
            
        Raises:
            ValueError: If not authenticated yet
        """
        if not self.token:
            raise ValueError("Not authenticated. Call authenticate() first.")
        
        return {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
    
    def is_authenticated(self) -> bool:
        """Check if currently authenticated (has valid token and dc)."""
        return self.token is not None and self.dc is not None
    
    def query_graphql(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        """
        Query Wiz API using GraphQL.
        
        Args:
            query: GraphQL query string
            variables: Variables for the GraphQL query
            
        Returns:
            Dict containing the API response
            
        Raises:
            ValueError: If not authenticated yet
            requests.RequestException: If the API request fails
        """
        if not self.is_authenticated():
            logger.error("Attempted to query GraphQL without authentication")
            raise ValueError("Not authenticated. Call authenticate() first.")
        
        logger.debug("Preparing GraphQL query")
        logger.debug(f"Query variables: {variables}")
        
        # Prepare headers with authentication
        headers = self.get_auth_headers()
        
        # Prepare the GraphQL request data
        data = {
            "variables": variables,
            "query": query
        }
        
        # Build the API URL using the DC value
        api_url = f"https://api.{self.dc}.app.wiz.io/graphql"
        logger.debug(f"Sending GraphQL request to: {api_url}")
        
        try:
            result = requests.post(
                url=api_url,
                json=data,
                headers=headers,
                timeout=180
            )
            result.raise_for_status()
            logger.debug(f"GraphQL request completed with status: {result.status_code}")
            
            response_json = result.json()
            
            # Check for GraphQL errors
            if 'errors' in response_json:
                logger.warning(f"GraphQL query returned errors: {response_json['errors']}")
            
            # Log response summary
            if 'data' in response_json and 'graphSearch' in response_json['data']:
                search_data = response_json['data']['graphSearch']
                node_count = len(search_data.get('nodes', []))
                logger.debug(f"GraphQL query returned {node_count} nodes")
                
                page_info = search_data.get('pageInfo', {})
                if page_info.get('hasNextPage'):
                    logger.debug(f"More pages available, end cursor: {page_info.get('endCursor')}")
                else:
                    logger.debug("This is the last page of results")
            
            return response_json
            
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error during GraphQL query: {str(e)}")
            print(f"Wiz-API-Error (4xx/5xx): {str(e)}")
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error during GraphQL query: {str(e)}")
            print(f"Network problem (DNS failure, refused connection, etc): {str(e)}")
            raise
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout during GraphQL query: {str(e)}")
            print(f"Request timed out: {str(e)}")
            raise


def print_help():
    """Print comprehensive help information for the script."""
    help_text = """
Wiz Sensor Version Inventory Tool

DESCRIPTION:
    This tool queries the Wiz API to retrieve information about all Wiz Sensor 
    deployments across your cloud infrastructure. It shows container names, host 
    names, current versions, end-of-life dates, and other version lifecycle information.

USAGE:
    python get-data.py [OPTIONS]

OPTIONS:
    --help, -h              Show this help message and exit
    --eol-only              Show only problematic sensors (EOL or non-latest versions)
    --format FORMAT         Output format: 'table' (default) or 'csv'
    --verbose, -v           Enable verbose logging for troubleshooting
    --token TOKEN           Use bearer token for authentication (instead of OAuth2)

AUTHENTICATION METHODS:
    1. OAuth2 Client Credentials (default):
       Set WIZ_CLIENT_ID and WIZ_CLIENT_SECRET environment variables
       
    2. Bearer Token (alternative):
       Use --token option with a token extracted from browser

EXAMPLES:
    # Show all sensors using OAuth2 authentication
    python get-data.py
    
    # Show only problematic sensors that need attention
    python get-data.py --eol-only
    
    # Export all sensor data to CSV format
    python get-data.py --format csv
    
    # Use bearer token from browser (with or without "Bearer " prefix)
    python get-data.py --token "eyJraWQiOiI5Y3dldTZu..."
    python get-data.py --token "Bearer eyJraWQiOiI5Y3dldTZu..."
    
    # Combine bearer token with other options
    python get-data.py --token "eyJraWQiOiI5Y3dldTZu..." --eol-only --verbose
    
    # Redirect CSV output to a file
    python get-data.py --format csv > wiz-sensors.csv
    
    # Enable verbose logging to see detailed progress
    python get-data.py --verbose
    
    # Combine options for detailed logging of filtered data
    python get-data.py --eol-only --verbose

EXTRACTING BEARER TOKEN FROM BROWSER:
    1. Open Wiz Console in browser and log in
    2. Open Developer Tools (F12)
    3. Go to Network tab
    4. Perform any action in Wiz (navigate, view issues, etc.)
    5. Look for GraphQL requests to api.*.app.wiz.io/graphql
    6. Click on a request → Headers → Request Headers
    7. Copy the Authorization header value (starts with "Bearer ")
    8. Use with --token option (with or without "Bearer " prefix)

ENVIRONMENT VARIABLES:
    WIZ_CLIENT_ID           OAuth2 client ID (not needed with --token)
    WIZ_CLIENT_SECRET       OAuth2 client secret (not needed with --token)

OUTPUT COLUMNS:
    Container Name          Name of the container running Wiz Sensor
    Host Name              Name of the host/VM where container is running
    Technology             Technology name (should always be "Wiz Sensor")
    Current Version        Currently deployed sensor version
    EOL Date               End of life date for current version
    Latest Version         Latest available sensor version
    Is Latest              True if current version is the latest available
    Is EOL                 True if current version is end of life
    Cloud Platform         Cloud platform (AWS, Azure, GCP, Kubernetes, etc.)

FILTERING:
    By default, all Wiz Sensor deployments are shown. Use --eol-only to focus
    on sensors that need immediate attention (either end-of-life or not running
    the latest version).

OUTPUT FORMATS:
    table                  Human-readable formatted table (default)
    csv                    Comma-separated values for spreadsheet/analysis tools

LOGGING:
    Use --verbose to enable detailed logging that shows:
    - Authentication progress (OAuth2 or bearer token validation)
    - GraphQL query execution details
    - Data processing steps
    - Pagination progress
    - Error details and troubleshooting information

AUTHENTICATION:
    The tool supports two authentication methods:
    1. OAuth2 client credentials flow (default) - requires service account
    2. Bearer token (--token) - uses token extracted from browser
    
    Bearer token method is useful for:
    - Testing and development
    - One-off queries without setting up service accounts
    - Using your existing browser session credentials

EXIT CODES:
    0                      Success
    1                      Error (authentication, network, or argument parsing)
"""
    print(help_text)


def main():
    """
    Main function to authenticate and query Wiz API with automatic pagination.
    
    This function:
    1. Parses command line arguments for filtering, output format, and authentication
    2. Sets up logging based on verbose flag
    3. Authenticates to Wiz API using OAuth2 client credentials or bearer token
    4. Executes GraphQL queries with automatic pagination to get all results
    5. Processes and displays results in the requested format
    
    Command Line Options:
        --eol-only: Show only problematic sensors (EOL or non-latest versions)
        --format csv: Output in CSV format instead of table format
        --verbose: Enable detailed logging
        --token: Use bearer token for authentication instead of OAuth2
        
    Returns:
        0 on success, 1 on error
    """
    import sys
    
    # Check for help option first
    if '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        return 0
    
    # Parse command line arguments
    show_only_eol = '--eol-only' in sys.argv  # Filter to show only problematic sensors
    verbose = '--verbose' in sys.argv or '-v' in sys.argv  # Enable verbose logging
    
    # Parse bearer token option
    bearer_token = None
    for i, arg in enumerate(sys.argv):
        if arg == '--token' and i + 1 < len(sys.argv):
            bearer_token = sys.argv[i + 1]
            break
    
    # Set up logging based on verbose flag
    setup_logging(verbose)
    logger.info("Starting Wiz Sensor Version Inventory Tool")
    
    if verbose:
        logger.info("Verbose mode enabled - detailed logging will be shown")
    
    if bearer_token:
        logger.info("Bearer token authentication mode enabled")
        logger.debug(f"Bearer token (first 20 chars): {bearer_token[:20]}...")
    else:
        logger.info("OAuth2 client credentials authentication mode enabled")
    
    # Parse output format option (table or csv)
    output_format = 'table'  # default to table format
    for i, arg in enumerate(sys.argv):
        if arg == '--format' and i + 1 < len(sys.argv):
            format_arg = sys.argv[i + 1].lower()
            if format_arg in ['table', 'csv']:
                output_format = format_arg
                logger.info(f"Output format set to: {output_format}")
            else:
                logger.error(f"Invalid format option: {format_arg}")
                print("Error: --format must be 'table' or 'csv'", file=sys.stderr)
                return 1
    
    if show_only_eol:
        logger.info("EOL-only filter enabled - will show only problematic sensors")
    
    try:
        # Initialize Wiz client with bearer token (if provided) or OAuth2 credentials
        logger.info("Initializing Wiz API client")
        wiz_client = WizClient(bearer_token=bearer_token)
        wiz_client.authenticate()
        
        logger.info("Starting data collection with pagination")
        
        # Collect all sensor data across multiple pages (pagination)
        all_nodes = []
        variables = VARIABLES.copy()  # Copy base variables for pagination
        page_number = 1
        
        # Execute queries with automatic pagination until all results are retrieved
        while True:
            logger.info(f"Fetching page {page_number} of sensor data")
            result = wiz_client.query_graphql(QUERY, variables)
            
            # Check if we received valid data
            if 'data' in result and 'graphSearch' in result['data']:
                search_data = result['data']['graphSearch']
                nodes = search_data.get('nodes', [])
                all_nodes.extend(nodes)  # Accumulate results from all pages
                
                logger.info(f"Page {page_number}: Retrieved {len(nodes)} nodes (Total so far: {len(all_nodes)})")
                
                # Check if there are more pages to fetch
                page_info = search_data.get('pageInfo', {})
                if page_info.get('hasNextPage'):
                    # Set up pagination for next request
                    variables['after'] = page_info.get('endCursor')
                    variables['quick'] = False  # Required for pagination
                    page_number += 1
                    logger.debug(f"More pages available, continuing to page {page_number}")
                else:
                    logger.info(f"Pagination complete - collected {len(all_nodes)} total nodes across {page_number} pages")
                    break  # No more pages, we have all results
            else:
                logger.warning("No valid data received from GraphQL query")
                break  # No valid data received, exit pagination loop
        
        # Combine all results and display in requested format
        logger.info("Processing collected data for display")
        combined_result = {"data": {"graphSearch": {"nodes": all_nodes}}}
        print_summary_table(combined_result, show_only_eol, output_format)
        
        logger.info("Wiz Sensor Version Inventory Tool completed successfully")
        
    except Exception as e:
        logger.error(f"Fatal error occurred: {e}", exc_info=verbose)
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
