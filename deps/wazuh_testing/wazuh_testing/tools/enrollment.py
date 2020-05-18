from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.security import CertificateController
import ssl

class EnrollmentSimulator:

    def __init__(self, server_address='127.0.0.1', enorllment_port=1515, remoted_port=1514, key_path='/etc/manager.key', cert_path='/etc/manager.cert'):
        self.mitm_enrollment = ManInTheMiddle(address=(server_address, enorllment_port), family='AF_INET', connection_protocol='SSL', func=self._process_enrollment_message)
        self.mitm_remoted = ManInTheMiddle(address=(server_address, remoted_port), family='AF_INET', connection_protocol='TCP')
        self.key_path = key_path
        self.cert_path = cert_path
        self.id_count = 0
        self.secret = 'TopSecret'

    def start(self):
        self._generate_certificates()
        self.mitm_enrollment.start()
        self.mitm_enrollment.listener.set_ssl_configuration(connection_protocol=ssl.PROTOCOL_TLSv1_2, certificate=self.cert_path, keyfile=self.key_path)
        self.mitm_remoted.start()

    def shutdown(self):
        self.mitm_enrollment.shutdown()
        self.mitm_remoted.shutdown()

    def _process_enrollment_message(self, received):
        """ 
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
            agent_info['ip'] = self.mitm_enrollment.listener.last_address[0]
        self.id_count += 1
        return f'OSSEC K: {agent_info.get("id")} {agent_info.get("name")} {agent_info["ip"]} {self.secret}'.encode()

    def _generate_certificates(self):
        # Generate root key and certificate
        controller = CertificateController()
        controller.get_root_ca_cert().sign(controller.get_root_key(), controller.digest)
        controller.store_private_key(controller.get_root_key(), self.key_path)
        controller.store_ca_certificate(controller.get_root_ca_cert(), self.cert_path)