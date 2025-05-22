"""
Configuration file for the server
"""

# Server configuration
HOST = 'localhost'
PORT = 8443
SERVER_CERT = 'server.crt'
SERVER_KEY = 'server.key'

# SSL configuration
SSL_MIN_VERSION = 'TLSv1_3'
SSL_MAX_VERSION = 'TLSv1_3'

# File paths
MESSAGES_FILE = "messages.json" 