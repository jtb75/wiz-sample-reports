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

Usage Examples:
    python get-data.py                           # Show all sensors in table format
    python get-data.py --eol-only               # Show only problematic sensors
    python get-data.py --format csv             # Export all to CSV
    python get-data.py --format csv --eol-only  # Export problematic sensors to CSV

Environment Variables Required:
    WIZ_CLIENT_ID     - Your Wiz OAuth2 client ID
    WIZ_CLIENT_SECRET - Your Wiz OAuth2 client secret
"""

import os
import requests
import json
import base64
from typing import Optional, Dict, Any
from tabulate import tabulate

# Headers for different types of HTTP requests to Wiz API
HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded"}  # OAuth2 token requests
HEADERS = {"Content-Type": "application/json"}                        # GraphQL API requests


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
    table_data = []
    
    def safe_get(value, default='N/A'):
        """Safely convert values to strings, handling None cases"""
        return str(value) if value is not None else default
    
    if 'data' in result and 'graphSearch' in result['data']:
        nodes = result['data']['graphSearch'].get('nodes', [])
        
        # Process each relationship path (node) from the GraphQL response
        for node in nodes:
            entities = node.get('entities', [])
            
            # Group entities by type for this relationship path
            # Each node contains a path: HOSTED_TECHNOLOGY -> CONTAINER -> VIRTUAL_MACHINE
            hosted_tech = None  # The Wiz Sensor technology
            container = None    # The container running the sensor
            vm = None          # The host (VM) running the container
            
            # Categorize entities by their type
            for entity in entities:
                entity_type = entity.get('type')
                if entity_type == 'HOSTED_TECHNOLOGY':
                    hosted_tech = entity
                elif entity_type == 'CONTAINER':
                    container = entity
                elif entity_type == 'VIRTUAL_MACHINE':
                    vm = entity
            
            # Only process complete relationship paths (all three entities present)
            if hosted_tech and container and vm:
                # Extract container information
                container_name = safe_get(container.get('name'))
                
                # Extract host (Virtual Machine) information
                host_name = safe_get(vm.get('name'))
                vm_properties = vm.get('properties', {}) or {}
                cloud_platform = safe_get(vm_properties.get('cloudPlatform'))
                
                # Extract technology (Wiz Sensor) information
                tech_properties = hosted_tech.get('properties', {}) or {}
                tech_name = safe_get(tech_properties.get('techName'))
                current_version = safe_get(tech_properties.get('version'))
                
                # Extract version lifecycle information
                version_eol_date = safe_get(tech_properties.get('versionEndOfLifeDate'))
                latest_version = safe_get(tech_properties.get('latestVersion'))
                is_latest = safe_get(tech_properties.get('isLatestVersion'))
                is_eol = safe_get(tech_properties.get('isVersionEndOfLife'))
                
                # Truncate long names for better table display
                container_display = container_name[:40] + '...' if len(container_name) > 40 else container_name
                host_display = host_name[:40] + '...' if len(host_name) > 40 else host_name
                
                # Add flattened row combining data from all three entities
                table_data.append([
                    container_display,    # Container name
                    host_display,         # Host/VM name
                    tech_name,           # Technology name (Wiz Sensor)
                    current_version,     # Current sensor version
                    version_eol_date,    # End of life date
                    latest_version,      # Latest available version
                    is_latest,          # Boolean: is current version the latest?
                    is_eol,             # Boolean: is current version end of life?
                    cloud_platform      # Cloud platform (AWS, Azure, GCP, etc.)
                ])
    
    return table_data


def print_summary_table(result, show_only_eol=False, output_format='table'):
    """
    Print formatted output of Wiz Sensor data.
    
    Args:
        result: GraphQL response containing sensor data
        show_only_eol: If True, show only problematic sensors (EOL or non-latest)
        output_format: Either 'table' for formatted table or 'csv' for CSV output
    """
    table_data = extract_table_data(result)
    
    # Apply filtering if requested - show only sensors that need attention
    if show_only_eol:
        # Filter for sensors that are either not latest (row[6] == 'False') or EOL (row[7] == 'True')
        table_data = [row for row in table_data if row[6] == 'False' or row[7] == 'True']
    
    # Define column headers for output
    headers = [
        'Container Name',    # Name of the container running Wiz Sensor
        'Host Name',         # Name of the host/VM
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
        if output_format == 'csv':
            # Output as CSV for spreadsheet/analysis tools
            import csv
            import sys
            writer = csv.writer(sys.stdout)
            writer.writerow(headers)
            writer.writerows(table_data)
        else:  # table format (default)
            # Output as formatted table for terminal viewing
            print(tabulate(table_data, headers=headers, tablefmt='grid'))
            print(f"\nTotal Wiz Sensors: {len(table_data)}")
    else:
        # Handle case where no data was found
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
    - JWT token parsing to extract datacenter (DC) information  
    - Authenticated GraphQL API requests with proper headers
    - Error handling for network and authentication issues
    """
    
    def __init__(self):
        """
        Initialize the Wiz client with credentials from environment variables.
        
        Required Environment Variables:
            WIZ_CLIENT_ID: OAuth2 client ID for your Wiz service account
            WIZ_CLIENT_SECRET: OAuth2 client secret for your Wiz service account
        """
        self.client_id = os.getenv('WIZ_CLIENT_ID')
        self.client_secret = os.getenv('WIZ_CLIENT_SECRET')
        self.auth_url = 'https://auth.app.wiz.io/oauth/token'
        self.token = None  # Will store the JWT access token
        self.dc = None     # Will store the datacenter identifier from token
        
        if not self.client_id or not self.client_secret:
            raise ValueError("WIZ_CLIENT_ID and WIZ_CLIENT_SECRET environment variables must be set")
    
    def authenticate(self) -> Dict[str, Any]:
        """
        Authenticate to Wiz API and retrieve access token and DC value.
        
        Returns:
            Dict containing the full response from the authentication endpoint
            
        Raises:
            requests.RequestException: If the authentication request fails
            ValueError: If the response doesn't contain expected fields
        """
        auth_payload = {
            'grant_type': 'client_credentials',
            'audience': 'wiz-api',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        try:
            response = requests.post(
                url=self.auth_url,
                headers=HEADERS_AUTH,
                data=auth_payload,
                timeout=180
            )
            response.raise_for_status()
            
        except requests.exceptions.HTTPError as e:
            print(f"Error authenticating to Wiz (4xx/5xx): {str(e)}")
            raise
        except requests.exceptions.ConnectionError as e:
            print(f"Network problem (DNS failure, refused connection, etc): {str(e)}")
            raise
        except requests.exceptions.Timeout as e:
            print(f"Request timed out: {str(e)}")
            raise
        
        try:
            response_json = response.json()
            token = response_json.get('access_token')
            if not token:
                message = f"Could not retrieve token from Wiz: {response_json.get('message')}"
                raise ValueError(message)
                
            # Extract DC value from JWT token payload
            token_payload = token.split(".")[1]
            response_json_decoded = json.loads(
                base64.standard_b64decode(pad_base64(token_payload))
            )
            dc = response_json_decoded["dc"]
            
            # Store token and dc value
            self.token = token
            self.dc = dc
            
            return response_json
            
        except ValueError as exception:
            message = f"Could not parse API response {exception}. Check Service Account details and variables"
            raise ValueError(message) from exception
        except (json.JSONDecodeError, KeyError) as e:
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
            raise ValueError("Not authenticated. Call authenticate() first.")
        
        # Prepare headers with authentication
        headers = self.get_auth_headers()
        
        # Prepare the GraphQL request data
        data = {
            "variables": variables,
            "query": query
        }
        
        # Build the API URL using the DC value
        api_url = f"https://api.{self.dc}.app.wiz.io/graphql"
        
        try:
            result = requests.post(
                url=api_url,
                json=data,
                headers=headers,
                timeout=180
            )
            result.raise_for_status()
            
            return result.json()
            
        except requests.exceptions.HTTPError as e:
            print(f"Wiz-API-Error (4xx/5xx): {str(e)}")
            raise
        except requests.exceptions.ConnectionError as e:
            print(f"Network problem (DNS failure, refused connection, etc): {str(e)}")
            raise
        except requests.exceptions.Timeout as e:
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

EXAMPLES:
    # Show all sensors in table format (default)
    python get-data.py
    
    # Show only problematic sensors that need attention
    python get-data.py --eol-only
    
    # Export all sensor data to CSV format
    python get-data.py --format csv
    
    # Export only problematic sensors to CSV
    python get-data.py --format csv --eol-only
    
    # Redirect CSV output to a file
    python get-data.py --format csv > wiz-sensors.csv

ENVIRONMENT VARIABLES:
    WIZ_CLIENT_ID           OAuth2 client ID for your Wiz service account
    WIZ_CLIENT_SECRET       OAuth2 client secret for your Wiz service account

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

AUTHENTICATION:
    The tool uses OAuth2 client credentials flow to authenticate with Wiz API.
    Ensure your service account has the necessary permissions to read hosted
    technologies and infrastructure data.

EXIT CODES:
    0                      Success
    1                      Error (authentication, network, or argument parsing)
"""
    print(help_text)


def main():
    """
    Main function to authenticate and query Wiz API with automatic pagination.
    
    This function:
    1. Parses command line arguments for filtering and output format
    2. Authenticates to Wiz API using OAuth2 client credentials
    3. Executes GraphQL queries with automatic pagination to get all results
    4. Processes and displays results in the requested format
    
    Command Line Options:
        --eol-only: Show only problematic sensors (EOL or non-latest versions)
        --format csv: Output in CSV format instead of table format
        
    Returns:
        0 on success, 1 on error
    """
    import sys
    
    # Check for help option first
    if '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        return 0
    
    # Parse command line arguments for filtering and output options
    show_only_eol = '--eol-only' in sys.argv  # Filter to show only problematic sensors
    
    # Parse output format option (table or csv)
    output_format = 'table'  # default to table format
    for i, arg in enumerate(sys.argv):
        if arg == '--format' and i + 1 < len(sys.argv):
            format_arg = sys.argv[i + 1].lower()
            if format_arg in ['table', 'csv']:
                output_format = format_arg
            else:
                print("Error: --format must be 'table' or 'csv'", file=sys.stderr)
                return 1
    
    try:
        # Initialize Wiz client and authenticate using OAuth2 client credentials
        wiz_client = WizClient()
        wiz_client.authenticate()
        
        # Collect all sensor data across multiple pages (pagination)
        all_nodes = []
        variables = VARIABLES.copy()  # Copy base variables for pagination
        
        # Execute queries with automatic pagination until all results are retrieved
        while True:
            result = wiz_client.query_graphql(QUERY, variables)
            
            # Check if we received valid data
            if 'data' in result and 'graphSearch' in result['data']:
                search_data = result['data']['graphSearch']
                nodes = search_data.get('nodes', [])
                all_nodes.extend(nodes)  # Accumulate results from all pages
                
                # Check if there are more pages to fetch
                page_info = search_data.get('pageInfo', {})
                if page_info.get('hasNextPage'):
                    # Set up pagination for next request
                    variables['after'] = page_info.get('endCursor')
                    variables['quick'] = False  # Required for pagination
                else:
                    break  # No more pages, we have all results
            else:
                break  # No valid data received, exit pagination loop
        
        # Combine all results and display in requested format
        combined_result = {"data": {"graphSearch": {"nodes": all_nodes}}}
        print_summary_table(combined_result, show_only_eol, output_format)
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
