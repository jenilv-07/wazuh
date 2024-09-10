#!/usr/bin/env python

import argparse
import asyncio
import os
import pwd
import grp
import logging
import sys

# Define the logger
logger = logging.getLogger('stream-broker')

log_file = '/var/ossec/logs/stream-broker.log'
file_handler = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levellevel)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Path for the Unix socket file
SOCKET_PATH = '/var/ossec/queue/alerts/ar_stream.sock'

# Remove the socket file if it already exists
if os.path.exists(SOCKET_PATH):
    os.remove(SOCKET_PATH)

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

def daemonize():
    """Daemonize the process using double fork."""
    try:
        # First fork
        pid = os.fork()
        if pid > 0:
            # Exit the parent process
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Fork #1 failed: {e.errno} ({e.strerror})\n")
        sys.exit(1)

    # Decouple from the parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)

    try:
        # Second fork
        pid = os.fork()
        if pid > 0:
            # Exit the second parent process
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Fork #2 failed: {e.errno} ({e.strerror})\n")
        sys.exit(1)

    # Redirect standard file descriptors to /dev/null
    sys.stdout.flush()
    sys.stderr.flush()
    with open('/dev/null', 'w') as dev_null:
        os.dup2(dev_null.fileno(), sys.stdin.fileno())
        os.dup2(dev_null.fileno(), sys.stdout.fileno())
        os.dup2(dev_null.fileno(), sys.stderr.fileno())

def run_in_foreground():
    asyncio.run(start_server())

def run_in_background():
    daemonize()
    run_in_foreground()

def main():
    # Setup argparse for handling the CLI arguments
    parser = argparse.ArgumentParser(
        description="Stream Broker Service. Runs in the background by default or foreground with -f option.",
        usage="%(prog)s [options]",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Option for running in the foreground
    parser.add_argument(
        '-f', '--foreground', action='store_true',
        help="Run the service in the foreground."
    )

    # Option for debug mode
    parser.add_argument(
        '-d', '--debug', action='store_true',
        help="Enable debug mode to get more verbose output."
    )

    # Help is automatically added by argparse, but we can call it explicitly for completeness
    parser.add_argument(
        '-h', '--help', action='help',
        help="Show this help message and exit."
    )

    args = parser.parse_args()

    # Set logging level based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled.")
    else:
        logger.setLevel(logging.INFO)

    # Determine whether to run in the foreground or background
    if args.foreground:
        logger.info("Starting in foreground")
        run_in_foreground()
    else:
        logger.info("Starting as daemon (background by default)")
        run_in_background()

if __name__ == "__main__":
    main()