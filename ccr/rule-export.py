import os
import json
import csv

from wiz_sdk import WizAPIClient

# Wiz API Configuration
WIZ_ENV = os.getenv('WIZ_ENV')           # Set to "gov" or "fedramp", if applicable
WIZ_CLIENT_ID = os.getenv('WIZ_CLIENT_ID')
WIZ_CLIENT_SECRET = os.getenv('WIZ_CLIENT_SECRET')
WIZ_API_PROXY = os.getenv('WIZ_API_PROXY')  # Optional proxy configuration



QUERY = """
    query CloudConfigurationSettingsTable($first: Int, $after: String, $filterBy: CloudConfigurationRuleFilters, $orderBy: CloudConfigurationRuleOrder, $projectId: [String!]) {
      cloudConfigurationRules(
        first: $first
        after: $after
        filterBy: $filterBy
        orderBy: $orderBy
      ) {
        analyticsUpdatedAt
        nodes {
          name
          severity
          cloudProvider
          subjectEntityType
          functionAsControl
          targetNativeTypes
          matcherTypes
          iacAnalytics(selection: {projectId: $projectId}) {
            analytics {
              platform
              totalFindingsCount
            }
          }
          tags {
            key
            value
          }
        }
        pageInfo {
          endCursor
          hasNextPage
        }
      }
    }
"""

# The variables sent along with the above query
VARIABLES = {
  "first": 40,
  "filterBy": {
    "serviceType": [
      "AWS"
    ],
    "createdByType": [
      "BUILT_IN"
    ]
  },
  "orderBy": {
    "field": "FAILED_CHECK_COUNT",
    "direction": "DESC"
  }
}


def main():
    """Main function using Wiz Python SDK"""

    # Configuration for a WizAPIClient, using script configuration.
    # The SDK also supports configuration via file and/or environment variables.
    # Refer to <https://docs.wiz.io/wiz-docs/docs/python-sdk> for details.
    conf = {
        'wiz_client_id':     WIZ_CLIENT_ID,
        'wiz_client_secret': WIZ_CLIENT_SECRET
    }

    # Initialize a WizAPIClient.
    client = WizAPIClient(conf=conf)

    results = client.query(QUERY, VARIABLES)
    #print(results.page)  # Your data is here!

    # For queries supporting pagination, the above prints the first <x> items
    # as defined by <'first'> in the query variables.
    # To retrieve all items, add <"quick": False> to the query variables,
    # and uncomment the following to iterate over all of the items.
    #
    #for result in results:
    #    line = [result['name'], result['severity'], result['cloudProvider'], result['targetNativeTypes'], result['matcherTypes']]
    #    print(line)

    with open('security_findings.csv', 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['name', 'severity', 'cloudProvider', 'targetNativeTypes', 'matcherTypes']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for result in results:
            # Convert list fields to strings for CSV
            row = {
                'name': result['name'],
                'severity': result['severity'],
                'cloudProvider': result['cloudProvider'],
                'targetNativeTypes': ', '.join(result['targetNativeTypes']) if result['targetNativeTypes'] else '',
                'matcherTypes': ', '.join(result['matcherTypes']) if result['matcherTypes'] else ''
            }
            writer.writerow(row)

    print("CSV file created successfully.")


if __name__ == '__main__':
    main()
