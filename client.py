"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError


def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        location = username + "my key"

        self.key = self.storage_server.get(location)

        if not self.key:
            self.key = self.crypto.get_random_bytes(32)

            encrypted_key = self.crypto.asymmetric_encrypt(self.key, self.pks.get_encryption_key(self.username))
            encrypted_key += self.crypto.asymmetric_sign(encrypted_key, self.rsa.rsa_priv_key)

            self.storage_server.put(location, encrypted_key)
        else:
            self.key = self.crypto.asymmetric_decrypt(self.key, self.elg_priv_key)
            if slef.crypto.asymmetric_verify(encrypted_key, sign????, self.pks.get_encryption_key(self.username))


    def resolve(self, uid):
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("[DATA]"):
                return uid
            elif res.startswith("[POINTER]"):
                uid = res[10:]
            else:
                raise IntegrityError()

    def upload(self, name, value):
        uid = self.resolve(path_join(self.username, name))

        self.storage_server.put(uid, "[DATA] " + value)
        raise NotImplementedError

    def download(self, name):
        # Replace with your implementation
        raise NotImplementedError

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
