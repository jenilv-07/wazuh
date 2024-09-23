#!/usr/bin/env python

import argparse
import asyncio
import os
import pwd
import grp
import logging
import sys
import signal
from wazuh.core import pyDaemonModule

# Define the logger
logger = logging.getLogger('stream-broker')

log_file = '/var/ossec/logs/stream-broker.log'
file_handler = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Path for the Unix socket file
SOCKET_PATH = '/var/ossec/queue/alerts/ar_stream.sock'
PID_FILE = '/var/run/stream_broker.pid'

# Remove the socket file if it already exists
if os.path.exists(SOCKET_PATH):
    os.remove(SOCKET_PATH)

def exit_handler(signum, frame):
    """Handle exit signals and remove PID file."""
    logger.info("Caught signal, exiting and cleaning up.")
    pyDaemonModule.delete_pid('stream_broker', os.getpid())  # Remove PID file on exit
    sys.exit(0)

async def handle_client(reader, writer):
    address = writer.get_extra_info('peername')
    logger.info(f"Client connected: {address}")

    try:
        while True:
            data = await reader.read(1024)
            if not data:
                break
            decoded_data = data.decode()
            logger.debug(f"Received data: {decoded_data}")
            writer.write(decoded_data.encode())
            await writer.drain()

    except asyncio.CancelledError as e:
        logger.error(f"handle_client() error: {e}")
    finally:
        logger.info("Closing connection")
        writer.close()
        await writer.wait_closed()

async def start_server():
    # Create a Unix socket stream broker
    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)

    # Set the ownership of the socket file to root:wazuh and permissions to 660
    try:
        uid = pwd.getpwnam('root').pw_uid
        gid = grp.getgrnam('wazuh').gr_gid
        os.chown(SOCKET_PATH, uid, gid)
        os.chmod(SOCKET_PATH, 0o660)
        logger.info(f"Socket ownership set to root:wazuh and permissions to 660 for {SOCKET_PATH}")
    except Exception as e:
        logger.error(f"Failed to set socket ownership/permissions: {e}")

    async with server:
        logger.info(f"Server listening on {SOCKET_PATH}")
        await server.serve_forever()

def run_in_foreground():
    """Run the service in the foreground."""
    pyDaemonModule.create_pid('stream_broker', os.getpid())  # Create PID file for foreground mode
    asyncio.run(start_server())

def run_in_background():
    """Daemonize the process and run it in the background."""
    pyDaemonModule.pyDaemon()  # Use pyDaemonModule for background daemonization
    pyDaemonModule.create_pid('stream_broker', os.getpid())  # Create PID file for background mode
    run_in_foreground()  # Run the service after daemonizing

def main():
    # Setup argparse for handling the CLI arguments
    parser = argparse.ArgumentParser(description="Stream Broker Service. Runs in the background by default or foreground with -f option.",usage="%(prog)s [options]",formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-f', '--foreground', action='store_true',help="Run the service in the foreground.")
    parser.add_argument('-d', '--debug', action='store_true',help="Enable debug mode to get more verbose output.")
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    parser.add_argument('-t', '--test-config', action='store_true', dest='test_config', help="Test configuration.")
    parser.add_argument('-r', '--root', action='store_true', dest='root', help="Run as root.")
    parser.add_argument('-c', '--config-file', type=str, metavar='config', dest='config_file', help="Configuration file to use.")

    args = parser.parse_args()
    
        # Handle version print
    if args.version:
        pass
    # Handle test configuration
    if args.test_config:
        pass
        

    # Handle running as root (optional)
    if args.root:
        if os.geteuid() != 0:
            pass

    # Handle configuration file loading (optional)
    if args.config_file:
        pass

    # Set logging level based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled.")
    else:
        logger.setLevel(logging.INFO)

    # Handle process termination signals
    signal.signal(signal.SIGTERM, exit_handler)
    signal.signal(signal.SIGINT, exit_handler)

    # Determine whether to run in the foreground or background
    if args.foreground:
        logger.info("Starting in foreground")
        run_in_foreground()
    else:
        logger.info("Starting as daemon (background by default)")
        run_in_background()

if __name__ == "__main__":
    main()
