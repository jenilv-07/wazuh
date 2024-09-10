import socket
import asyncio
import logging
import argparse
import os
import sys
import signal
from wazuh.core.common import AR_SOCKET #, AR_TRIGGERED_LOG
# from wazuh.core.customUtils import XDR_STREAM_BASE_URL
from wazuh.core import pyDaemonModule
from nats.aio.client import Client as NATS
from nats.js import JetStreamContext

# Define constants
XDR_STREAM_BASE_URL = 'nats://172.17.14.119:5222'
PID_FILE = "/var/run/ar_trigger.pid"
SOCKET_COMMUNICATION_PROTOCOL_VERSION = 1

# Define the logger
logger = logging.getLogger("ar-trigger")
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('/var/ossec/logs/ar_trigger.log')
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Signal handler for proper cleanup
def exit_handler(signum, frame):
    """Handle exit signals and remove PID file."""
    logger.info("Caught signal, exiting and cleaning up.")
    pyDaemonModule.delete_pid("ar-trigger", os.getpid())  # Remove PID file on exit
    sys.exit(0)

class UnixSocketClient:
    OS_MAXSTR = 6144
    MAX_MSG_SIZE = OS_MAXSTR + 256

    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.client_socket = None
        self.setup_socket()
        logger.debug(f"socket connection initialized {self.socket_path}")

    def setup_socket(self):
        try:
            self.client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.client_socket.connect(self.socket_path)
            logger.debug(f"connected with socket: {self.socket_path}")
            length_send_buffer = self.client_socket.getsockopt(
                socket.SOL_SOCKET, socket.SO_SNDBUF
            )
            if length_send_buffer < self.MAX_MSG_SIZE:
                self.client_socket.setsockopt(
                    socket.SOL_SOCKET, socket.SO_SNDBUF, self.MAX_MSG_SIZE
                )
        except Exception as e:
            logger.error(f"setup socket error: {e}")

    def send_message(self, msg):
        try:
            sent = self.client_socket.send(msg)
            if sent == 0:
                raise Exception("No bytes were sent")
            logger.info("The message was sent successfully to socket...")
            logger.debug(f"socket msg: {msg}")
        except socket.error as e:
            logger.error(f"send message error: {e}")

    def close_socket(self):
        if self.client_socket:
            logger.debug(f"close the socket connection: {self.socket_path}")
            self.client_socket.close()

def create_ar_socket_message(agent_id):
    if not isinstance(agent_id, str):
        raise ValueError("Agent ID must be a string.")
    if not agent_id.isdigit():
        raise ValueError("Agent ID must contain only numeric characters.")
    if agent_id == "000":
        raise ValueError("Couldn't send msg to Manager")

    ar_msg_str = f'(msg_to_agent) [] NNS {agent_id} {{"version": 1, "origin": {{"name": null, "module": "API"}}, "command": "ar-trigger0", "parameters": {{"extra_args": [], "alert": {{"data": {{}}}}}}}}'
    ar_msg = ar_msg_str.encode()
    logger.debug(f"ar_socket_message: {ar_msg_str}")
    return ar_msg

class JetStreamConsumer:
    def __init__(self, subject, stream_name, durable_name):
        self.subject = subject
        self.stream_name = stream_name
        self.durable_name = durable_name
        self.js = None

    async def connect(self):
        self.nc = NATS()
        await self.nc.connect(servers=[XDR_STREAM_BASE_URL])
        logger.info(f"Stream connection established with: {XDR_STREAM_BASE_URL}")
        self.js = JetStreamContext(self.nc)

    async def consume(self):
        try:
            sub = await self.js.subscribe(self.subject, durable=self.durable_name)
            logger.info(f"Listening for messages on subject: {self.subject}")

            async for msg in sub.messages:
                logger.info(f"Message received from {sub}")
                await self.process_message(msg)

        except Exception as e:
            logger.error(f"Error while consuming messages: {e}")

    async def process_message(self, msg):
        try:
            msg_data = create_ar_socket_message(msg.data.decode())
            client = UnixSocketClient(AR_SOCKET)
            client.send_message(msg_data)
            client.close_socket()
            await msg.ack()
        except Exception as e:
            logger.error(f"Error processing message: {e}")

    async def close(self):
        await self.nc.drain()
        logger.info("Closed the connection to Stream...")

async def main():
    subject = "art.d"
    stream_name = "xdr_ar_t"
    durable_name = "art_consumer_worker"

    consumer = JetStreamConsumer(subject, stream_name, durable_name)
    await consumer.connect()
    await consumer.consume()

def run_in_foreground():
    pyDaemonModule.create_pid("ar-trigger", os.getpid())
    asyncio.run(main())

def run_in_background():
    pyDaemonModule.pyDaemon()
    pyDaemonModule.create_pid("ar-trigger", os.getpid())
    run_in_foreground()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AR Trigger Service with foreground and debug modes.")
    parser.add_argument('-f', '--foreground', action='store_true', help="Run in foreground mode.")
    parser.add_argument('-d', '--debug', action='store_true', help="Enable debug mode.")

    args = parser.parse_args()

    # Configure logging for debug mode
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled.")

    # Handle termination signals for cleanup
    signal.signal(signal.SIGTERM, exit_handler)
    signal.signal(signal.SIGINT, exit_handler)

    if args.foreground:
        logger.info("Starting in foreground mode...")
        run_in_foreground()
    else:
        logger.info("Starting as a daemon (background mode)...")
        run_in_background()
