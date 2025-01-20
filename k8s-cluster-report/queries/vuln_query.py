VULN_QUERY = """
query GroupedVulnerabilityFindingsTable($filterBy: VulnerabilityFindingFilters, $groupBy: [VulnerabilityFindingGroupBy!]!, $orderBy: VulnerabilityFindingsGroupedByValuesOrder, $fetchTotalCount: Boolean = true, $first: Int, $after: String, $groupByParameters: VulnerabilityFindingGroupByParameters) {
  vulnerabilityFindingsGroupedByValues(
    filterBy: $filterBy
    groupBy: $groupBy
    orderBy: $orderBy
    first: $first
    after: $after
    groupByParameters: $groupByParameters
  ) {
    nodes {
      id
      kubernetesCluster {
        id
        name
      }
      analytics {
        vulnerableAssetCount
        totalFindingCount
        criticalSeverityFindingCount
        highSeverityFindingCount
        mediumSeverityFindingCount
        lowSeverityFindingCount
        informationalSeverityFindingCount
      }
    }
    totalCount @include(if: $fetchTotalCount)
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

VULN_VARIABLES = {
    "fetchTotalCount": True,
    "first": 20,
    "groupBy": [
        "KUBERNETES_CLUSTER"
    ],
    "orderBy": {
        "field": "SEVERITY",
        "direction": "DESC"
    },
    "filterBy": {}
} 