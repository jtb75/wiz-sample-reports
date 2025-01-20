"""
Configuration settings for the Kubernetes cluster report generator.
"""

import os

# Wiz API Configuration
WIZ_ENV = os.getenv('WIZ_ENV')           # Set to "gov" or "fedramp", if applicable
WIZ_CLIENT_ID = os.getenv('WIZ_CLIENT_ID')
WIZ_CLIENT_SECRET = os.getenv('WIZ_CLIENT_SECRET')
WIZ_API_PROXY = os.getenv('WIZ_API_PROXY')  # Optional proxy configuration