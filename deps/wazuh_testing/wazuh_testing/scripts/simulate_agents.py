import argparse
import logging
import os
import wazuh_testing.tools.agent_simulator as ag

from multiprocessing import Process
from time import sleep
from wazuh_testing.modules.syscollector import SYSCOLLECTOR_DELTA_EVENT_TYPES
from wazuh_testing import TCP


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(f"P{os.getpid()}")


def parse_custom_labels(labels):
    """Parse the wazuh labels from string list to dict.
    Args:
        labels (list): Labels in format ["key1:value1", "key2:value2"]
    Returns:
        dict: Labels dictionary. {key1:value1, key2:value2}
    """
    custom_labels = labels

    # Parse the custom labels from list format to dict
    if labels is not None:
        custom_labels = {}

        for item in labels:
            label = item.split(':')
            custom_labels[label[0]] = label[1]

    return custom_labels


def process_script_parameters(args):
    """Process script parameters and edit them if necessary.
    Args:
        args (argparse.Namespace): Script args.
    """
    # Add keepalive and receive_message modules if they are not specified in script parameters
    if not args.disable_keepalive:
        if 'keepalive' not in args.modules:
            args.modules.append('keepalive')
            args.modules_eps.append('0')

    if not args.disable_receive:
        if 'receive_messages' not in args.modules:
            args.modules.append('receive_messages')
            args.modules_eps.append('0')

    if not args.version.startswith('v'):
        args.version = 'v' + args.version

    if args.syscollector_event_types:
        args.syscollector_event_types = args.syscollector_event_types.split(' ')
        if any(event_type not in SYSCOLLECTOR_DELTA_EVENT_TYPES for event_type in args.syscollector_event_types):
            raise ValueError(f'Invalid syscollector event type. Valid values are: {SYSCOLLECTOR_DELTA_EVENT_TYPES}')

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)


def set_agent_modules_and_eps(agent, active_modules, modules_eps):
    """Set active modules and EPS to an agent.
    Args:
        agent (Agent): agent object.
        active_modules (list): List of active modules.
        modules_eps (list): List of EPS for each active module.
    Raises:
        ValueError: If number of active_modules items is not the same than the modules_eps.
        ValueError: If a module does not exist on the agent simulator.
    """
    if len(active_modules) != len(modules_eps):
        raise ValueError('Number of modules must be the same than modules EPS items')

    available_modules = agent.modules.keys()

    for module in active_modules:
        if module not in available_modules:
            raise ValueError(f"Selected module: '{module}' doesn't exist on agent simulator!")

    for module in available_modules:
        if module in active_modules:
            index = list(active_modules).index(module)
            agent.modules[module]['status'] = 'enabled'
            if module in ['keepalive', 'receive_messages']:
                continue

            agent.modules[module]['eps'] = int(modules_eps[index])
        else:
            agent.modules[module]['status'] = 'disabled'
            agent.modules[module]['eps'] = 0

    logger.info(agent.modules)


def create_agent(args, custom_labels):
    agent_args = {
        'manager_address': args.manager_address,
        'os': args.os,
        'registration_address': args.manager_registration_address,
        'version': args.version,
        'fixed_message_size': args.fixed_message_size,
        'labels': custom_labels,
        'logcollector_msg_number': args.enable_logcollector_message_number,
        'custom_logcollector_message': args.custom_logcollector_message,
        'syscollector_frequency': args.syscollector_frequency,
        'syscollector_event_types': args.syscollector_event_types,
        'syscollector_legacy_messages': args.syscollector_legacy_messages,
        'vulnerability_events': args.vulnerability_events,
        'vulnerability_packages_vuln_content': args.vulnerability_packages_list_file,
        'vulnerability_frequency': args.vulnerability_frequency
    }

    agent = ag.Agent(**agent_args)

    return agent


def create_agents(args):
    """Create a list of agents according to script parameters like the mode, EPS...
    Args:
        args (list): List of script parameters.
    Returns:
        list: List of agents to run.
    """
    agents = []
    custom_labels = parse_custom_labels(args.labels)

    if args.balance_mode:
        modules_eps_data = []

        for module, eps in zip(args.modules, args.modules_eps):
            modules_eps_data.append({
                'remaining': int(eps),
                'module': module
            })

        distribution_list = calculate_eps_distribution(modules_eps_data, args.balance_ratio)

        logger.info(f"Agents-EPS distributon = {distribution_list}")

        for item in distribution_list:  # item[0] = modules - item[1] = eps
            agent = create_agent(args, custom_labels)
            set_agent_modules_and_eps(agent, item[0].split(' ') + ['keepalive', 'receive_messages'],
                                      item[1].split(' ') + ['0', '0'])
            agents.append(agent)
    else:
        for _ in range(args.agents_number):
            agent = create_agent(args, custom_labels)

            set_agent_modules_and_eps(agent, args.modules, args.modules_eps)
            agents.append(agent)

    return agents


def create_injectors(agents, manager_address, protocol, limit_msg=None):
    """Create injectos objects from list of agents and connection parameters.
    Args:
        agents (list): List of agents to create the injectors (1 injector/agent).
        manager_address (str): Manager IP address to connect the agents.
        protocol (str): TCP or UDP protocol to connect the agents to the manager.
        limit_msg (int): Maximum amount of message to be sent.
    Returns:
        list: List of injector objects.
    """
    injectors = []

    logger.info(f"Starting {len(agents)} agents.")

    for agent in agents:
        sender = ag.Sender(manager_address, protocol=protocol)
        injectors.append(ag.Injector(sender, agent, limit_msg))

    return injectors


def start(injector, time_alive, limit_msg_enable=None):
    """Start the injector process for a specified time.
    Args:
        injector (Injector): Injector object.
        time_alive (int): Period of time in seconds during the injector will be running.
        limit_msg_enable (int): Amount of message to be sent.
    """
    try:
        injector.run()
        if limit_msg_enable is None:
            sleep(time_alive)
        else:
            injector.wait()
    finally:
        stop(injector)


def stop(injector):
    """Stop the injector process.
    Args:
        injector (Injector): Injector object.
    """
    injector.stop_receive()


def run(injectors, time_alive, limit_msg_enable=None):
    """Run each injector in a separated process.
    Args:
        injectors (list): List of injector objects.
        time_alive (int): Period of time in seconds during the injector will be running.
        limit_msg_enable (int): Amount of message to be sent.
    """
    processes = []

    for injector in injectors:
        processes.append(Process(target=start, args=(injector, time_alive, limit_msg_enable)))

    for agent_process in processes:
        agent_process.start()

    for agent_process in processes:
        agent_process.join()


def calculate_eps_distribution(data, max_eps_per_agent):
    """Calculate the distribution of agents and EPS according to the input ratio.
    Args:
        data (list): List of dictionaries containing information about the module and the remaining EPS to be
                     distributed.
        max_eps_per_agent (int): Maximum EPS load to be distributed to an agent.
    Returns:
        list: List of tuples, containing in the first position the modules to be launched by that agent, and in the
              second position the EPS distribution for each module of that agent.
    Example:
        Input:
            data =[
                {'remaining': 0, 'module': 'receive_messages'},
                {'remaining': 0, 'module': 'keepalive'},
                {'remaining': 100, 'module': 'fim'},
                {'remaining': 30, 'module': 'logcollector'},
                {'remaining': 80, 'module': 'syscollector'}
            ],
            max_eps_per_agent = 50
        Output:
            [('fim', '50'), ('fim', '50'), ('logcollector syscollector', '30 20'), ('syscollector', '50'),
            ('syscollector', '10')]
    """

    # If there are no more items in the queue list then stop
    if len(data) == 0:
        return []

    # If there are no more EPS to distribute from the current queue, then move on to the next item.
    if data[0]['remaining'] == 0:
        data.pop(0)
        return calculate_eps_distribution(data, max_eps_per_agent)

    # If there are enough EPS in the current queue to fill the EPS of an agent, then it is filled.
    if data[0]['remaining'] >= max_eps_per_agent:
        data[0]['remaining'] -= max_eps_per_agent

        agent_parameters = (data[0]['module'], str(max_eps_per_agent))

        return [agent_parameters] + calculate_eps_distribution(data, max_eps_per_agent)
    # If the agent instance supports higher eps than the remaining eps to be distributed from the current queue
    else:
        # Add the remaining EPS from the current queue
        modules = data[0]['module']
        current_load = data[0]['remaining']
        eps = f"{current_load}"

        # Remove the queue as all its eps have been distributed.
        data.pop(0)

        # As long as the maximum EPS load of the agent has not been supported.
        while current_load < max_eps_per_agent:

            # Exit the loop if there are no more queue items in the list.
            if len(data) == 0:
                break

            # Remove the queue if there are no more EPS to distribute and check the next eps.
            if data[0]['remaining'] == 0:
                data.pop(0)
            # If with the elements of the new queue we can fill the instance-agent eps.
            elif data[0]['remaining'] > (max_eps_per_agent - current_load):
                modules += f" {data[0]['module']}"
                eps += f" {(max_eps_per_agent - current_load)}"
                data[0]['remaining'] -= (max_eps_per_agent - current_load)
                current_load = max_eps_per_agent
            # Otherwise, take all EPS from the current queue and keep checking for the same agent.
            else:
                modules += f" {data[0]['module']}"
                eps += f" {data[0]['remaining']}"
                current_load += data[0]['remaining']
                data[0]['remaining'] = 0

        agent_parameters = (modules, eps)

        return [agent_parameters] + calculate_eps_distribution(data, max_eps_per_agent)


def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-a', '--manager', metavar='<manager_ip_address>', type=str, required=True,
                            default='localhost', help='Manager IP address', dest='manager_address')

    arg_parser.add_argument('-n', '--agents', metavar='<agents_number>', type=int, default=1, required=False,
                            help='Number of agents to create and run', dest='agents_number')

    arg_parser.add_argument('-o', '--os', metavar='<os>', dest='os',
                            type=str, required=False, default='debian8', help='Agent operating system')

    arg_parser.add_argument('-p', '--protocol', metavar='<protocol>', dest='agent_protocol',
                            type=str, required=False, default=TCP, help='Communication protocol')

    arg_parser.add_argument('-r', '--registration-address', metavar='<manager_registration_ip_address>', type=str,
                            required=False, default=None, help='Manager IP address where the agent will be registered',
                            dest='manager_registration_address')

    arg_parser.add_argument('-t', '--time', metavar='<simulation_time>', dest='simulation_time',
                            type=int, required=False, default=60, help='Time in seconds for the simulation')

    arg_parser.add_argument('-v', '--version', metavar='<version>', dest='version',
                            type=str, required=False, default='4.2.0', help='Agent wazuh version')

    arg_parser.add_argument('-m', '--modules', dest='modules', required=False, type=str, nargs='+', action='store',
                            default=['keepalive', 'receive_messages'], help='Active module separated by whitespace.')

    arg_parser.add_argument('-l', '--labels', dest='labels', required=False, type=str, nargs='+',
                            action='store', default=None, help='Wazuh agent labels.')

    arg_parser.add_argument('-s', '--modules-eps', dest='modules_eps', required=False, type=str, nargs='+',
                            action='store', default=['0', '0'], help='Active module EPS separated by whitespace.')

    arg_parser.add_argument('-f', '--fixed-message-size', metavar='<fixed_message_size>', type=int, required=False,
                            default=None, help='Size of all the agent modules messages (KB)', dest='fixed_message_size')

    arg_parser.add_argument('-b', '--balance-mode', action='store_true', required=False,
                            help='Activate the balance mode. EPS will be distributed throughout all agents.')

    arg_parser.add_argument('-i', '--balance-ratio', metavar='<balance_ratio>', type=int, required=False,
                            default=1000, help='EPS/agent ratio. Can only be used if the parameter -b was specified',
                            dest='balance_ratio')

    arg_parser.add_argument('-w', '--waiting-connection-time', metavar='<waiting_connection_time>', type=int,
                            help='Waiting time in seconds between agent registration and the sending of events.',
                            required=False, default=0, dest='waiting_connection_time')

    arg_parser.add_argument('-e', '--limit-msg', metavar='<limit_msg>', type=int,
                            help='Limit the amount of message to send to the manager for each module.',
                            required=False, default=None, dest='limit_msg')

    arg_parser.add_argument('-k', '--disable-keepalive', metavar='<disable_keepalive>', type=bool,
                            help='Disable keepalive module',
                            required=False, default=False, dest='disable_keepalive')

    arg_parser.add_argument('--debug',
                            help='Enable debug mode',
                            required=False,
                            action='store_true',
                            default=False,
                            dest='debug')

    arg_parser.add_argument('-d', '--disable-receive', metavar='<disable_receive>', type=bool,
                            help='Disable receive message module',
                            required=False, default=False, dest='disable_receive')

    arg_parser.add_argument('-c', '--enable-logcollector-message-number',
                            metavar='<enable_logcollector_message_number>', type=bool,
                            help='Enable logcollector message number',
                            required=False, default=False, dest='enable_logcollector_message_number')

    arg_parser.add_argument('-g', '--custom-logcollector-message',
                            metavar='<custom_logcollector_message>', type=str,
                            help='Custom logcollector message',
                            required=False, default='', dest='custom_logcollector_message')

    arg_parser.add_argument('--syscollector-frequency',
                            metavar='<syscollector_frequency>',
                            type=int,
                            help='Frequency of Syscollector scans. Set to 1 for constant message sending.',
                            required=False,
                            default=60,
                            dest='syscollector_frequency')

    arg_parser.add_argument('--syscollector-event-types',
                            metavar='<syscollector_event_types>',
                            type=str,
                            help='''Space-separated list of event types for syscollector messages.
                            By default all are chosen. Available types are "packages", "process", "ports",
                            "network", "hotfix", "hwinfo", "osinfo"''',
                            required=False,
                            default='packages hotfix hwinfo ports osinfo network process',
                            dest='syscollector_event_types')

    arg_parser.add_argument('--syscollector-legacy-messages',
                            help='Enable prior 4.2 agents syscollector format. Default is False.',
                            required=False,
                            action='store_true',
                            default=False,
                            dest='syscollector_legacy_messages')

    arg_parser.add_argument('--vulnerability-events',
                            type=int,
                            help='Number of vulnerabilities per agent',
                            required=False,
                            default=10,
                            dest='vulnerability_events')

    arg_parser.add_argument('--vulnerability-packages-list-file',
                            metavar='<vulnerability_packages_list_file>',
                            type=str,
                            help='File containing a list of packages to be sent by syscollector. One package per line.',
                            required=False,
                            default=None,
                            dest='vulnerability_packages_list_file')

    arg_parser.add_argument('--vulnerability-frequency',
                            metavar='<vulnerability_frequency>',
                            type=int,
                            help='Frequency of Vulnerability scans. Set to 1 for constant message sending.',
                            required=False,
                            default=60,
                            dest='vulnerability_frequency')

    args = arg_parser.parse_args()

    process_script_parameters(args)

    agents = create_agents(args)

    logger.info(f"Waiting {args.waiting_connection_time} seconds before sending EPS and keep-alive events")

    # Waiting time to prevent CPU overload when registering many agents (registration + event generation).
    sleep(args.waiting_connection_time)

    injectors = create_injectors(agents, args.manager_address, args.agent_protocol, args.limit_msg)

    run(injectors, args.simulation_time, args.limit_msg)


if __name__ == "__main__":
    main()
