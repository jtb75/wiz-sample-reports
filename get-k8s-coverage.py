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

# GraphQL query tuning only the fields we need
wiz_query = """
query ClustersPage($first: Int, $after: String, $fetchDeployments: Boolean!, $fetchSensorGroup: Boolean!) {
  kubernetesClusters(first: $first, after: $after) {
    nodes {
      name
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
    resp = requests.post(AUTH_URL,
                         headers={'Content-Type': 'application/x-www-form-urlencoded'},
                         data=data, proxies=PROXIES, timeout=60)
    resp.raise_for_status()
    token = resp.json().get('access_token')
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
        resp = requests.post(API_URL, headers=HEADERS, json=payload,
                             proxies=PROXIES, timeout=300)
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

# Main routine: print cluster name and sensor deployment status
def main():
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    signal.signal(signal.SIGINT, signal_handler)

    logging.info('Authenticating to Wiz API...')
    request_wiz_api_token()

    logging.info('Fetching Kubernetes clusters...')
    data = query_wiz_api(wiz_query, variables)
    clusters = data['data']['kubernetesClusters']['nodes']

    for cluster in clusters:
        name = cluster.get('name')
        has_sensor = bool(cluster.get('sensorGroup'))
        print(f"{name}: {'Sensors deployed' if has_sensor else 'No sensors'}")

if __name__ == '__main__':
    main()
