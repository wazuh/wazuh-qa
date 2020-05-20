from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.security import CertificateController
import ssl

class EnrollmentSimulator:
    """
    Creates two server sockets, one SSL for simulting authd connection
    and another TCP server for simulating remoted service.
    """
    def __init__(self, 
        server_address='127.0.0.1', enorllment_port=1515, remoted_port=1514, key_path='/etc/manager.key', cert_path='/etc/manager.cert'):
        self.mitm_enrollment = ManInTheMiddle(address=(server_address, enorllment_port), family='AF_INET', connection_protocol='SSL', func=self._process_enrollment_message)
        self.mitm_remoted = ManInTheMiddle(address=(server_address, remoted_port), family='AF_INET', connection_protocol='TCP')
        self.key_path = key_path
        self.cert_path = cert_path
        self.id_count = 0
        self.secret = 'TopSecret'
        self.controller = CertificateController()

    def start(self):
        """
        Generates certificate for the SSL server and starts server sockets
        """
        self._generate_certificates()
        self.mitm_enrollment.start()
        self.mitm_enrollment.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLSv1_2, certificate=self.cert_path, keyfile=self.key_path)
        self.mitm_remoted.start()

    def shutdown(self):
        """
        Shutdown sockets
        """
        self.mitm_enrollment.shutdown()
        self.mitm_remoted.shutdown()

    def clear(self):
        """
        Sockets need to be clear after each response since by the default the stops handling connection
        after one successfull connection, and needs to be cleared afterwards
        """
        self.mitm_enrollment.event.clear()
        self.mitm_remoted.event.clear()

    @property
    def queues(self):
        return [self.mitm_enrollment.queue, self.mitm_remoted.queue]

    @property
    def cert_controller(self):
        return self.controller

    @property
    def agent_id(self):
        return self.id_count

    @agent_id.setter
    def agent_id(self, value):
        self.id_count = value

    def _process_enrollment_message(self, received):
        """ 
        Reads a message received at the SSL socket, and parses to emulate a authd response
        Expected message:
        OSSEC A:'{name}' G:'{groups}' IP:'{ip}'\n

        Key response:
        OSSEC K: {id} {name} {ip} {key:64}
        """
        agent_info = {
            'id' : self.id_count,
            'name': None,
            'ip': None
        }
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
        return f'OSSEC K:\'{agent_info.get("id")} {agent_info.get("name")} {agent_info["ip"]} {self.secret}\'\n'.encode()

    def _generate_certificates(self):
        # Generate root key and certificate
        self.controller.get_root_ca_cert().sign(self.controller.get_root_key(), self.controller.digest)
        self.controller.store_private_key(self.controller.get_root_key(), self.key_path)
        self.controller.store_ca_certificate(self.controller.get_root_ca_cert(), self.cert_path)