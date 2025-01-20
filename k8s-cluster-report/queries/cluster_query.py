CLUSTER_QUERY = """
query ClustersPage($filterBy: KubernetesClusterFilters, $first: Int, $after: String, $fetchDeployments: Boolean!, $fetchSensorGroup: Boolean!) {
  kubernetesClusters(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      externalId
      name
      kind
      status
      cloudAccount {
        id
        name
        cloudProvider
        externalId
      }
      lastScannedAt
      isPrivate
      projects {
        id
        name
        slug
        isFolder
        riskProfile {
          businessImpact
        }
      }
      connectors {
        id
        name
        errorCode
        status
        connectorIssues {
          connectorIssue {
            issueIdentifier
            description
            severity
            impact
            remediation
            context
          }
        }
      }
      admissionController @include(if: $fetchDeployments) {
        id
        lastSeen
        healthStatus
      }
      kubernetesAuditLogCollector @include(if: $fetchDeployments) {
        id
        lastSeen
        healthStatus
      }
      sensorGroup @include(if: $fetchSensorGroup) {
        id
      }
      isConnectedUsingBroker
      criticalSystemHealthIssueCount
      highSystemHealthIssueCount
      mediumSystemHealthIssueCount
      lowSystemHealthIssueCount
    }
    pageInfo {
      endCursor
      hasNextPage
    }
    totalCount
  }
}
"""

CLUSTER_VARIABLES = {
    "first": 20,
    "filterBy": {},
    "fetchDeployments": True,
    "fetchSensorGroup": True,
    "fetchTotalCount": False
} 