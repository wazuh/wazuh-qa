import ssl
import time

from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.security import CertificateController


class AuthdSimulator:
    """
    Create an SSL server socket for simulating authd connection
    """

    def __init__(self, server_address='127.0.0.1', enrollment_port=1515, key_path='/etc/manager.key',
                 cert_path='/etc/manager.cert', initial_mode='ACCEPT'):
        self.mitm_enrollment = ManInTheMiddle(address=(server_address, enrollment_port), family='AF_INET',
                                              connection_protocol='SSL', func=self._process_enrollment_message)
        self.key_path = key_path
        self.cert_path = cert_path
        self.id_count = 1
        self.secret = 'TopSecret'
        self.controller = CertificateController()
        self.mode = initial_mode

    def start(self):
        """
        Generates certificate for the SSL server and starts server sockets
        """
        self._generate_certificates()
        self.mitm_enrollment.start()
        self.mitm_enrollment.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLSv1_2,
                                                            certificate=self.cert_path, keyfile=self.key_path)

    def shutdown(self):
        """
        Shutdown sockets
        """
        self.mitm_enrollment.shutdown()

    def clear(self):
        """
        Clear sockets after each response. By default, they stop handling connections
        after one successful connection, and they need to be cleared afterwards
        """
        while not self.mitm_enrollment.queue.empty():
            self.mitm_enrollment.queue.get_nowait()
        self.mitm_enrollment.event.clear()

    @property
    def queue(self):
        return self.mitm_enrollment.queue

    @property
    def cert_controller(self):
        return self.controller

    @property
    def agent_id(self):
        return self.id_count

    @agent_id.setter
    def agent_id(self, value):
        self.id_count = value

    def set_mode(self, mode):
        """
        Sets a mode:

            ACCEPT: Accepts connection and produces enrollment
            REJECT: Waits 2 seconds and anwsers with an empty message
        """
        self.mode = mode

    def _process_enrollment_message(self, received):
        """ 
        Reads a message received at the SSL socket, and parses to emulate a authd response
        
        Expected message:
            OSSEC A:'{name}' G:'{groups}' IP:'{ip}'\n

        Key response:
            OSSEC K: {id} {name} {ip} {key:64}
        """
        if self.mode == 'REJECT':
            time.sleep(2)
            self.mitm_enrollment.event.set()
            return b'ERROR'

        agent_info = {
            'id': self.id_count,
            'name': None,
            'ip': None
        }
        if len(received) == 0:
            # Empty message
            raise
        parts = received.decode().split(' ')
        for part in parts:
            if part.startswith('A:'):
                agent_info['name'] = part.split("'")[1]
            if part.startswith('IP:'):
                agent_info['ip'] = part.split("'")[1]
        if agent_info['ip'] is None:
            agent_info['ip'] = 'any'
        if agent_info['ip'] == 'src':
            agent_info['ip'] = self.mitm_enrollment.listener.last_address[0]
        self.id_count += 1
        self.mitm_enrollment.event.set()
        return f'OSSEC K:\'{agent_info.get("id"):03d} {agent_info.get("name")} {agent_info["ip"]} {self.secret}\'\n'.encode()

    def _generate_certificates(self):
        # Generate root key and certificate
        self.controller.get_root_ca_cert().sign(self.controller.get_root_key(), self.controller.digest)
        self.controller.store_private_key(self.controller.get_root_key(), self.key_path)
        self.controller.store_ca_certificate(self.controller.get_root_ca_cert(), self.cert_path)
