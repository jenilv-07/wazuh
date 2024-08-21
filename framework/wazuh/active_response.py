# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import active_response, common
from wazuh.core.agent import get_agents_info
from wazuh.core.exception import WazuhException, WazuhError, WazuhResourceNotFound
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources
import multiprocessing
from typing import List, Dict

def send_command_to_agent(agent_id: str, command: str, arguments: List[str], custom: bool, alert: Dict) -> str:
    """Send command to a single agent and handle response."""
    try:
        with WazuhQueue(common.AR_SOCKET) as wq:
            system_agents = get_agents_info()
            if agent_id not in system_agents:
                raise WazuhResourceNotFound(1701)
            if agent_id == "000":
                raise WazuhError(1703)
            active_response.send_ar_message(agent_id, wq, command, arguments, custom, alert)
            return agent_id, 'Completed'
    except WazuhException as e:
        return agent_id, str(e)

def worker(agent_id: str, command: str, arguments: List[str], custom: bool, alert: Dict, result_queue: multiprocessing.Queue):
    """Worker function to handle sending commands."""
    result = send_command_to_agent(agent_id, command, arguments, custom, alert)
    result_queue.put(result)

@expose_resources(actions=['active-response:command'], resources=['agent:id:{agent_list}'],
                  post_proc_kwargs={'exclude_codes': [1701, 1703]})
def run_command(agent_list: List[str] = None, command: str = '', arguments: List[str] = None, custom: bool = False,
                alert: Dict = None) -> AffectedItemsWazuhResult:
    """Run AR command in specific agents with timeout handling.

    Parameters
    ----------
    agent_list : List[str]
        Agents list that will run the AR command.
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a
        command name.
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : List[str]
        Command arguments.
    alert : Dict
        Alert information depending on the AR executed.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(all_msg='AR command was sent to all agents',
                                      some_msg='AR command was not sent to some agents',
                                      none_msg='AR command was not sent to any agent')
    if agent_list:
        timeout = 5  # Timeout for each process

        result_queue = multiprocessing.Queue()
        processes = []

        for agent_id in agent_list:
            process = multiprocessing.Process(target=worker, args=(agent_id, command, arguments, custom, alert, result_queue))
            process.start()
            processes.append((process, agent_id))

        # Wait for processes to complete or timeout
        for process, agent_id in processes:
            process.join(timeout)
            if process.is_alive():
                process.terminate()  # Terminate process if still running
                process.join()  # Ensure process has terminated
                result_queue.put((agent_id, 'Timeout'))
            else:
                # Collect result from queue
                while not result_queue.empty():
                    agent_id, status = result_queue.get()
                    if status == 'Completed':
                        result.affected_items.append(agent_id)
                        result.total_affected_items += 1
                    else:
                        result.add_failed_item(id_=agent_id, error=status)
        
        result.affected_items.sort(key=int)

    return result
