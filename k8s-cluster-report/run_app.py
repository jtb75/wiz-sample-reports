import warnings
import urllib3
import pandas as pd
import logging
import logging.handlers
import os
import argparse
from datetime import datetime
from typing import Dict, List, Optional
from wiz_sdk import WizAPIClient

# Move configuration to a separate config.py file
from config import (
    WIZ_ENV, 
    WIZ_CLIENT_ID, 
    WIZ_CLIENT_SECRET, 
    WIZ_API_PROXY,
)

# Import queries from query files
from queries.cluster_query import CLUSTER_QUERY, CLUSTER_VARIABLES
from queries.vuln_query import VULN_QUERY, VULN_VARIABLES

# Add SSL warning suppressions
urllib3.disable_warnings()
warnings.filterwarnings('ignore', category=urllib3.exceptions.NotOpenSSLWarning)
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)

class WizReportGenerator:
    """Class to handle Wiz API interactions and report generation"""
    
    def __init__(self, client: WizAPIClient, logger: logging.Logger):
        self.client = client
        self.logger = logger

    def get_vulnerability_data(self) -> Dict:
        """Fetch and process vulnerability data from Wiz API"""
        try:
            self.logger.info("Querying Kubernetes cluster vulnerabilities")
            vuln_result = self.client.query(VULN_QUERY, VULN_VARIABLES)
            return self._process_vulnerability_data(vuln_result)
        except Exception as e:
            self.logger.error(f"Failed to fetch vulnerability data: {str(e)}")
            raise

    def get_cluster_data(self, cluster_vulns: Dict) -> List[Dict]:
        """Fetch and process cluster data from Wiz API"""
        try:
            self.logger.info("Querying Kubernetes cluster connection status")
            cluster_result = self.client.query(CLUSTER_QUERY, CLUSTER_VARIABLES)
            
            self.logger.info("Processing Kubernetes cluster data")
            return [self._process_cluster_node(node, cluster_vulns) for node in cluster_result]
        except Exception as e:
            self.logger.error(f"Failed to fetch cluster data: {str(e)}")
            raise

    @staticmethod
    def _process_vulnerability_data(vuln_result: List) -> Dict:
        """Process vulnerability data from Wiz API response"""
        try:
            cluster_vulns = {}
            for node in vuln_result:
                if node.get('kubernetesCluster'):
                    cluster_id = node['kubernetesCluster']['id']
                    cluster_vulns[cluster_id] = {
                        'Critical Vulns': node['analytics']['criticalSeverityFindingCount'],
                        'High Vulns': node['analytics']['highSeverityFindingCount'],
                        'Medium Vulns': node['analytics']['mediumSeverityFindingCount'],
                        'Low Vulns': node['analytics']['lowSeverityFindingCount'],
                        'Info Vulns': node['analytics']['informationalSeverityFindingCount']
                    }
            return cluster_vulns
        except KeyError as e:
            raise ValueError(f"Invalid vulnerability data format: missing key {str(e)}")
        except Exception as e:
            raise ValueError(f"Failed to process vulnerability data: {str(e)}")

    @staticmethod
    def _process_cluster_node(node: Dict, cluster_vulns: Dict) -> Dict:
        """Process individual cluster node data"""
        try:
            row = {
                "ID": node['id'],
                "Name": node['name'],
                "Connection Status": node['status'],
                "Admission Controller": "CONNECTED" if node['admissionController'] else "DISCONNECTED",
                "Sensor Group": "CONNECTED" if node['sensorGroup'] else "DISCONNECTED",
                "Kubernetes Audit Log Collector": "CONNECTED" if node['kubernetesAuditLogCollector'] else "DISCONNECTED"
            }

            if node['id'] in cluster_vulns:
                row.update(cluster_vulns[node['id']])
            
            return row
        except KeyError as e:
            raise ValueError(f"Invalid cluster node data format: missing key {str(e)}")
        except Exception as e:
            raise ValueError(f"Failed to process cluster node: {str(e)}")

class ReportFormatter:
    """Class to handle report formatting and output"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def output_report(self, df: pd.DataFrame, output_type: str = 'table', output_file: Optional[str] = None) -> None:
        """Format and output the report"""
        format_methods = {
            'table': df.to_string,
            'csv': lambda: df.to_csv(index=False),
            'html': lambda: df.to_html(index=False)
        }
        
        formatted_output = format_methods[output_type]()
        
        if output_file:
            self._save_to_file(df, formatted_output, output_type, output_file)
        else:
            print(formatted_output)

    def _save_to_file(self, df: pd.DataFrame, formatted_output: str, output_type: str, output_file: str) -> None:
        """Save report to file"""
        try:
            if output_type == 'csv':
                df.to_csv(output_file, index=False)
            elif output_type == 'html':
                df.to_html(output_file, index=False)
            else:  # table format
                with open(output_file, 'w') as f:
                    f.write(formatted_output)
            self.logger.info(f"Report saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Failed to write to file {output_file}: {str(e)}")
            raise

def parse_args():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description='Generate Kubernetes cluster report with vulnerability data from Wiz.'
    )
    
    parser.add_argument(
        '-l', '--loglevel',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set the logging level'
    )
    
    parser.add_argument(
        '--logfile',
        help='Specify custom log file location'
    )

    parser.add_argument(
        '--type',
        choices=['table', 'csv', 'html'],
        default='table',
        help='Specify output format (table, csv, or html)'
    )

    parser.add_argument(
        '--file',
        help='Output file location (if not specified, output goes to stdout)'
    )
    
    return parser.parse_args()

def setup_logging(log_level='INFO', log_file=None):
    """Configure logging with file and/or console handlers."""
    try:
        logger = logging.getLogger()
        logger.setLevel(log_level)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        if log_file:
            try:
                log_dir = os.path.dirname(log_file)
                if log_dir and not os.path.exists(log_dir):
                    os.makedirs(log_dir)
                
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file,
                    maxBytes=10485760,
                    backupCount=5
                )
                file_handler.setFormatter(formatter)
                logger.addHandler(file_handler)
            except OSError as e:
                raise ValueError(f"Failed to setup log file: {str(e)}")

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger
    except Exception as e:
        raise RuntimeError(f"Failed to setup logging: {str(e)}")

def validate_credentials(conf: Dict) -> None:
    """Validate required credentials are present"""
    try:
        required = ['wiz_client_id', 'wiz_client_secret']
        missing = [key for key in required if not conf.get(key)]
        if missing:
            raise ValueError(f"Missing required credentials: {', '.join(missing)}")
    except Exception as e:
        raise ValueError(f"Failed to validate credentials: {str(e)}")

def cleanup_logging(logger: logging.Logger) -> None:
    """Remove handlers to prevent duplicate logging"""
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

def main():
    """Main function to generate Kubernetes cluster report"""
    args = parse_args()
    logger = setup_logging(args.loglevel, args.logfile)
    
    logger.info("Starting K8s Cluster Report Application")
    
    try:
        conf = {
            'wiz_env': os.getenv('WIZ_ENV', WIZ_ENV),
            'wiz_client_id': os.getenv('WIZ_CLIENT_ID', WIZ_CLIENT_ID),
            'wiz_client_secret': os.getenv('WIZ_CLIENT_SECRET', WIZ_CLIENT_SECRET),
            'wiz_api_proxy': os.getenv('WIZ_API_PROXY', WIZ_API_PROXY)
        }
        validate_credentials(conf)
        client = WizAPIClient(conf=conf)

        # Initialize report generator and formatter
        generator = WizReportGenerator(client, logger)
        formatter = ReportFormatter(logger)

        # Generate report data
        cluster_vulns = generator.get_vulnerability_data()
        rows = generator.get_cluster_data(cluster_vulns)

        # Create and output report
        df = pd.DataFrame(rows)
        formatter.output_report(df, args.type, args.file)

        logger.info("Application completed successfully")
    except Exception as e:
        logger.error(f"Application failed with error: {str(e)}", exc_info=True)
        raise
    finally:
        cleanup_logging(logger)

if __name__ == "__main__":
    main()
