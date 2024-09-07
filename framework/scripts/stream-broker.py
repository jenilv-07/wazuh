import asyncio
import os
import pwd
import grp
import json
import logging

# Define the logger
logger = logging.getLogger('stream-broker')
logger.setLevel(logging.INFO)

log_file = '/var/ossec/logs/stream-broker.log'
file_handler = logging.FileHandler(log_file)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

# Path for the Unix socket file
SOCKET_PATH = '/var/ossec/queue/alerts/ar_stream.sock'
logger.debug(f"Socket file path: {SOCKET_PATH}")

# Remove the socket file if it already exists
if os.path.exists(SOCKET_PATH):
    logger.debug("Removing the existing socket file")
    os.remove(SOCKET_PATH)

async def handle_client(reader, writer):
    address = writer.get_extra_info('peername')
    logger.info(f"Client connected: {address}")
    
    try:
        while True:
            data = await reader.read(1024)  # Receive data from the client
            if not data:
                break  # Exit if no data is received
            decoded_data = data.decode()
            logger.debug(f"Received data: {decoded_data}")
            
            # intigreate the you own funtion call hear
                
            # Send the response back to the client
            writer.write(decoded_data.encode())
            await writer.drain()  # Wait for acknowledgment

    except asyncio.CancelledError as e:
        logger.error(f"handle_client() error: {e}")
    finally:
        logger.info("Closing connection")
        writer.close()
        await writer.wait_closed()

async def main():
    # Create a Unix socket stream broker
    server = await asyncio.start_unix_server(handle_client, path=SOCKET_PATH)

    # Set the ownership of the socket file to root:wazuh and permissions to 660
    try:
        uid = pwd.getpwnam('root').pw_uid  # Get UID of root
        gid = grp.getgrnam('wazuh').gr_gid  # Get GID of wazuh
        os.chown(SOCKET_PATH, uid, gid)
        os.chmod(SOCKET_PATH, 0o660)  # Set permissions to 660 (srw-rw----)
        logger.info(f"Socket ownership set to root:wazuh and permissions to 660 for {SOCKET_PATH}")
    except Exception as e:
        logger.error(f"Failed to set socket ownership/permissions: {e}")
    
    async with server:
        logger.info(f"Server listening on {SOCKET_PATH}")
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())