import logging
import os
import signal
import sys
import time

import requests

# HTTP defaults
HEADERS = {'Content-Type': 'application/json'}
PROXIES = {}

# Credentials and endpoints
CLIENT_ID = os.environ.get('WIZ_CLIENT_ID', '')
CLIENT_SECRET = os.environ.get('WIZ_CLIENT_SECRET', '')
API_URL = os.environ.get('WIZ_API_URL', '')
AUTH_URL = 'https://auth.app.wiz.io/oauth/token'

# GraphQL query tuned for name, status, sensors, and cloud account
wiz_query = """
query ClustersPage($first: Int, $after: String, $fetchDeployments: Boolean!, $fetchSensorGroup: Boolean!) {
  kubernetesClusters(first: $first, after: $after) {
    nodes {
      name
      status
      cloudAccount {
        name
        externalId
      }
      admissionController @include(if: $fetchDeployments) { id }
      kubernetesAuditLogCollector @include(if: $fetchDeployments) { id }
      sensorGroup @include(if: $fetchSensorGroup) { id }
    }
    pageInfo { endCursor, hasNextPage }
  }
}
"""

variables = {
    "first": 40,
    "fetchDeployments": True,
    "fetchSensorGroup": True
}

# Graceful exit handler

def signal_handler(_sig, _frame):
    print("\nExiting")
    sys.exit(0)

# Determine if a status code is retryable

def retryable_response_status_code(code):
    return int(code) in {425, 429, 500, 502, 503, 504}

# Authenticate and set bearer token

def request_wiz_api_token():
    data = {
        'audience': 'wiz-api',
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    resp = requests.post(
        AUTH_URL,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
        data=data, proxies=PROXIES, timeout=60
    )
    resp.raise_for_status()
    json_resp = resp.json()
    token = json_resp.get('access_token')
    if not token:
        raise Exception('Failed to retrieve access token')
    HEADERS['Authorization'] = f'Bearer {token}'
    return token

# Page through the API

def query_wiz_api(query, vars):
    result = {}
    page_info = {'hasNextPage': True}
    while page_info['hasNextPage']:
        payload = {'query': query, 'variables': vars}
        resp = requests.post(
            API_URL, headers=HEADERS, json=payload,
            proxies=PROXIES, timeout=300
        )
        if retryable_response_status_code(resp.status_code):
            time.sleep(1)
            continue
        resp.raise_for_status()
        data = resp.json()
        key = next(iter(data['data']))
        if result:
            result['data'][key]['nodes'].extend(data['data'][key]['nodes'])
        else:
            result = data
        info = data['data'][key]['pageInfo']
        page_info = info
        vars['after'] = info.get('endCursor')
    return result

# Main routine: print cluster name, cloud account name, connection, and sensor status

def main():
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    signal.signal(signal.SIGINT, signal_handler)

    logging.info('Authenticating to Wiz API...')
    request_wiz_api_token()

    logging.info('Fetching Kubernetes clusters...')
    response = query_wiz_api(wiz_query, variables)
    clusters = response['data']['kubernetesClusters']['nodes']

    for cluster in clusters:
        name = cluster.get('name', 'UNKNOWN')
        # cloud account info
        acct = cluster.get('cloudAccount') or {}
        cloud_name = acct.get('name', 'N/A')
        cloud_id = acct.get('externalId', 'N/A')
        # connection status
        conn_status = cluster.get('status', 'UNKNOWN')
        # sensor deployment status
        has_sensor = any(
            cluster.get(field) for field in (
                'admissionController',
                'kubernetesAuditLogCollector',
                'sensorGroup'
            )
        )
        sensor_status = 'Sensors deployed' if has_sensor else 'No sensors'

        # print details on separate lines
        print(f"Cluster Name: {name}")
        print(f"Cloud Account Name: {cloud_name}")
        print(f"Connection Status: {conn_status}")
        print(f"Sensor Status: {sensor_status}\n")

if __name__ == '__main__':
    main()
