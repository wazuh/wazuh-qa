import os
import platform
import random
import stat

from OpenSSL import crypto

if platform.system() == 'Windows':  # Windows
    import win32api, win32con


class CertificateController(object):

    def __init__(self):
        # Generates key pair .
        self.ca_key = crypto.PKey()
        self.ca_key.generate_key(crypto.TYPE_RSA, 4096)
        self.ca_cert = self._create_ca_cert(self.ca_key)
        self.digest = 'sha256WithRSAEncryption'

    def get_root_ca_cert(self):
        return self.ca_cert

    def get_root_key(self):
        return self.ca_key

    def generate_agent_certificates(self, agent_key_path, agent_cert_path, agentname, signed=True):
        """
        Generates and stores all required certificate for an agent

        Args:
            signed (boolean): Whetever the CA certificate will be signed by the agent key or not
            agentname (string): String to be set for common name to agent certificate
            agent_key_path (string): Path to store agent private key
            agent_cert_path (string): Path to store agent certificate
        """
        # Generate agent keys
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)
        self._add_key_to_certificate(key)
        # Generate and sign agent cert with root key
        cert = self._create_ca_cert(key, subject=agentname)
        if signed:
            cert.sign(self.ca_key, self.digest)
        else:
            # We sign the cert ourself
            cert.sign(key, self.digest)
        self.store_private_key(key, agent_key_path)
        self.store_ca_certificate(cert, agent_cert_path)
        return

    def _create_ca_cert(self, pub_key, issuer="Manger", subject=None):
        """
        Create a CA Certificate that will be signed with each agent key

        Args:
            pub_key (PKey): Key to be set in certificate
            issuer (str): Name or hostname for the certificate issuer
            subject (str): Name or hostname for the ceritifcate subject. If none will be same as issuer

        Returns:
            ca_cert : X509 Object. Created ca certificate
        """

        ca_cert = crypto.X509()
        ca_cert.set_serial_number(random.randint(50000000, 100000000))

        xt = crypto.X509Extension(b"basicConstraints", 1, b"CA:TRUE")
        ca_cert.add_extensions((xt,))

        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

        ca_cert.set_version(2)

        ca_issuer = ca_cert.get_issuer()
        ca_issuer.commonName = issuer

        ca_cert.set_issuer(ca_issuer)

        if subject:
            ca_subj = ca_cert.get_subject()
            ca_subj.commonName = subject
            ca_cert.set_subject(ca_subj)
        else:
            ca_subj = ca_cert.get_subject()
            ca_subj.commonName = issuer
            ca_cert.set_subject(ca_subj)

        ca_cert.set_pubkey(pub_key)
        return ca_cert

    def _add_key_to_certificate(self, key, digest='sha256WithRSAEncryption'):
        """
        Signs ca certificate with the input key

        Args:
            key (Pkey Object): Key that will sign the certificate
            algorithm (str): Name of the message digest to use
        """
        self.ca_cert.sign(key, digest)
        return

    def store_ca_certificate(self, ca_cert, ca_path):
        """
        Saves a certificate in the stored path in PEM format
        Args:
            ca_cert (X509 Object):  Certifiate to store
            ca_path (str): Path to store the ca certificate
        """
        if os.path.exists(ca_path):
            os.remove(ca_path)
        with open(ca_path, "wb+") as f:
            if isinstance(ca_cert, crypto.X509Req):
                data = crypto.dump_certificate_request(crypto.FILETYPE_PEM, ca_cert)
            else:
                data = crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert)
            f.write(data)
        os.chmod(ca_path, 644)
        return

    def store_private_key(self, key, private_key_path):
        """
        Stores a private key pair into the specified paths

        Args:
            key (PKey): Keys to be stored
            private_key_path (str): Path to store the private key
        """
        if os.path.exists(private_key_path):
            if platform.system() == 'Windows':
                win32api.SetFileAttributes(private_key_path, win32con.FILE_ATTRIBUTE_NORMAL)
            os.remove(private_key_path)
        with open(private_key_path, "wb+") as f:
            data = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
            f.write(data)
        os.chmod(private_key_path, stat.S_IREAD | stat.S_IROTH)
        return

    def store_public_key(self, key, public_key_path):
        """
        Stores a private key pair into the specified paths

        Args:
            key (PKey): Keys to be stored
            public_key_path (str) : Path to store the private key
        """
        if os.path.exists(public_key_path):
            os.remove(public_key_path)
        with open(public_key_path, "wb+") as f:
            data = crypto.dump_publickey(crypto.FILETYPE_PEM, key)
            f.write(data)
        os.chmod(public_key_path, stat.S_IREAD | stat.S_IROTH)
        return
