# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import socket
import uuid

from wazuh.core import active_response, common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhException, WazuhError, WazuhResourceNotFound
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources
from wazuh.core.framework_logger import log_debug, log_error, log_info

@expose_resources(actions=['active-response:command'], resources=['agent:id:{agent_list}'],
                  post_proc_kwargs={'exclude_codes': [1701, 1703]})
def run_command(agent_list: list = None, trigger_by: str = "", command: str = '', arguments: list = None,
                alert: dict = None) -> AffectedItemsWazuhResult:
    """Run AR command in a specific agent.

    Parameters
    ----------
    agent_list : list
        Agents list that will run the AR command.
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a
        command name.
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : list
        Command arguments.
    alert : dict
        Alert information depending on the AR executed.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    
    # logger
    log_debug(f"trigger_by : {trigger_by}")
    
    result = AffectedItemsWazuhResult(all_msg='AR command was sent to all agents',
                                      some_msg='AR command was not sent to some agents',
                                      none_msg='AR command was not sent to any agent'
                                      )
    if agent_list:
        with WazuhQueue(common.AR_SOCKET) as wq:
            system_agents = get_agents_info()
            for agent_id in agent_list:
                try:
                    if agent_id not in system_agents:
                        raise WazuhResourceNotFound(1701)
                    if agent_id == "000":
                        raise WazuhError(1703)

                    # Generate a new UUID for each iteration
                    new_uuid = str(uuid.uuid4())

                    # Append the UUID to the arguments list
                    current_arguments = arguments.copy() if arguments else []
                    current_arguments.append(f"id={new_uuid}")

                    # Send the active response message with the updated arguments
                    active_response.send_ar_message(agent_id, wq, command, current_arguments, alert)

                    result.affected_items.append(agent_id)
                    result.total_affected_items += 1
                    log_debug(f"MSG SEND SUCCESSFULLY : {trigger_by}, UUID: {new_uuid}")
                    ar_log_forwoder(trigger_by)

                except WazuhException as e:
                    result.add_failed_item(id_=agent_id, error=e)
                    log_error(f"MSG SEND FAIL : {trigger_by}, ERROR: {e}")
            result.affected_items.sort(key=int)

    return result

def ar_log_forwoder(log):
    SOCKET_PATH = '/var/ossec/queue/alerts/ar_stream.sock'
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_socket:
        # Connect to the server socket
        try:
            client_socket.connect(SOCKET_PATH)
            log_info(f"connected with stream-broker {SOCKET_PATH}")
        except Exception as e:
            log_error(f"connection error: {e}")
            
        try:
            client_socket.sendall(log.encode())  # Send data to the server
            log_info(f"Msg sent to the stream-broker")
            
        except Exception as e:
            log_error(f"send error: {e}")
            
        data = client_socket.recv(1024)  # Receive response from the server
        log_info(f"Received response from the server: {data}")
