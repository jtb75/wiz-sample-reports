# wiz-sample-reports

A collection of sample reports generated using the Wiz API.

## K8s Cluster Report

This report provides a comprehensive overview of your Kubernetes clusters security posture and configuration using data from Wiz.

### Prerequisites

- Python 3.7 or higher
- Wiz API credentials (Client ID and Client Secret)
- Required Python packages (install using `pip install -r requirements.txt`)

### Setup

1. Clone this repository:
```bash
git clone https://github.com/wiz-sec/wiz-sample-reports.git
cd wiz-sample-reports
```

2. Install the required dependencies:
```bash
# Create and activate a virtual environment (if not already done)
python -m venv env
source env/bin/activate  # On Windows, use: env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

3. Set up your Wiz API credentials as environment variables:
```bash
export WIZ_CLIENT_ID='your_client_id'
export WIZ_CLIENT_SECRET='your_client_secret'
```

### Running the K8s Cluster Report

To generate the Kubernetes cluster report:

```bash
python k8s_cluster_report/run_app.py
```

#### Output Options

You can specify the output format and destination using command line arguments:

```bash
# Generate HTML report (default)
python k8s_cluster_report/run_app.py --format html

# Generate JSON output
python k8s_cluster_report/run_app.py --format json

# Save to a specific file
python k8s_cluster_report/run_app.py --output /path/to/report.html

# Combine format and output options
python k8s_cluster_report/run_app.py --format json --output /path/to/report.json
```

By default, the report will be generated in table format and printed to `stdout`.

### Report Contents

The K8s cluster report includes:
- Cluster inventory and connection details
- Security vulnerabilities

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.