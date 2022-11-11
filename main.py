import getpass
import json
import pickle
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

REALM_NAME = "@KERBEROS"

AS_TGS_SHARED_KEY = get_random_bytes(32)
TGS_FS_SHARED_KEY = get_random_bytes(32)
tag_nonce={}

def derive_secret_key(username: str, password: str) -> bytes:


    salt = username + REALM_NAME
    hash = SHA256.new((salt + password).encode()).hexdigest().encode()

    """
    Derives the given user's secret key from the username and password.
    This one-way derivation function uses SHA256 as the hashing algorithm.
    The salt (combined username and realm name) is prepended to the given
    password so that two different encryption keys are generated for users
    with the same password.
    """
    return hash


def encrypt(key: bytes, data: Any) -> bytes :
    """Encrypts the given data using AES."""
    cipher = AES.new(key ,AES.MODE_EAX)
    str_data = pickle.dumps(data)
    global tag_nonce
    nonce_data = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(str_data)
    tag_nonce[ciphertext] = {}
    tag_nonce[ciphertext]['tag_data'] = tag
    tag_nonce[ciphertext]['nonce_data'] = nonce_data

    return ciphertext
def decrypt(key: bytes, data: bytes) -> Any:


    # Decrypt and verify
    cipher = AES.new(key, AES.MODE_EAX, nonce=tag_nonce[data]['nonce_data'])
    original_data = cipher.decrypt(data)
    try:
        cipher.verify(tag_nonce[data]['tag_data'])
        # print("data:", original_data.decode())
        parsed_data = pickle.loads(original_data)
        return parsed_data

    except ValueError:
        print("Key incorrect or message corrupted")
    # cipher = AES.new(key, AES.MODE_EAX, nonce = nonce_data)
    # original_data = cipher.decrypt_and_verify(data, tag_data) # Decrypt and verify with the tag


class AuthenticationServer:
    """The authentication server in Kerberos."""

    def __init__(self) -> None:
        with open("users.json", "rb") as file:
            self.users = {k: bytes.fromhex(v) for k, v in json.load(file).items()}

    def request_authentication(self, username: str) -> Optional[Tuple[bytes, bytes]]:
        """Requests authentication for the given user from the authentication server."""
        tgt_ticket = Ticket(username , tgs_sessionKey)
        encrypted_tgt_key = encrypt(AS_TGS_SHARED_KEY ,tgt_ticket)
        encrypted_session_key = encrypt(self.users[username], tgs_sessionKey)

        return  encrypted_session_key, encrypted_tgt_key
        # Message 1: client/TGS session key encrypted using client secret key
        # Message 2: TGT encrypted using shared key between AS and TGS
        pass


class TicketGrantingServer:
    """The ticket-granting server in Kerberos."""

    def request_authorization(
        self,
        tgt_encrypted: bytes,
        authenticator_encrypted: bytes,
    ) -> Optional[Tuple[bytes, bytes]]:
        """Requests service authorization from the ticket-granting server by using the given TGT and authenticator."""
        decrypted_tgt = decrypt(AS_TGS_SHARED_KEY ,tgt_encrypted)
        decrypted_authenticator = decrypt(decrypted_tgt.session_key ,authenticator_encrypted)
        if decrypted_tgt.username == decrypted_authenticator.username:
            service_ticket = Ticket(decrypted_tgt.username , fs_sessionKey)
            encrypted_service_ticket = encrypt(TGS_FS_SHARED_KEY ,service_ticket)
            encrypted_fs_key = encrypt(tgs_sessionKey ,fs_sessionKey)
            return  encrypted_fs_key, encrypted_service_ticket
        else:
            print('Username not match form tgt and authenticator')

        # Message 5: client/FS session key encrypted using client/TGS session key
        # Message 6: service ticket encrypted using shared key between TGS and FS
        pass


class FileServer:
    """The file server in Kerberos."""

    def request_file(
        self,
        filename: str,
        ticket_encrypted: bytes,
        authenticator_encrypted: bytes,
    ) -> Optional[bytes]:
        """Requests the given file from the file server by using the given service ticket and authenticator as authorization."""
        decrypted_service_ticket = decrypt(TGS_FS_SHARED_KEY ,ticket_encrypted)
        decrypted_authenticator = decrypt(decrypted_service_ticket.session_key ,authenticator_encrypted)
        if decrypted_service_ticket.username == decrypted_authenticator.username:
            
            file = open(filename , 'r')
            data = str(file.readlines())
            file.close()
            file_response = FileResponse(data ,decrypted_authenticator.timestamp)
            encrypted_fileresponse = encrypt(fs_sessionKey, file_response)
            return encrypted_fileresponse

        else:
            print('Username not match form Service Ticket and authenticator')

        # Message 9: the file request response encrypted using the client/FS session key
        pass


class Client:
    """The client in Kerberos."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.secret_key = derive_secret_key(username, password)

    @classmethod
    def from_terminal(cls):
        """Creates a client object using user input from the terminal."""

        username = input("Username: ")
        password = getpass.getpass("Password: ")
        return cls(username, password)

    def get_file(self, filename: str):
        """Gets the given file from the file server."""
        byte_hash = bytes.fromhex(self.secret_key.decode())
        ASResponse = AuthenticationServer().request_authentication(self.username)
        decrypted_tgs_key = decrypt(byte_hash, ASResponse[0])
        if decrypted_tgs_key == tgs_sessionKey :
            authenticator = Authenticator(self.username)
            encrypted_authenticator = encrypt(tgs_sessionKey ,authenticator)
            tgs_response = TicketGrantingServer().request_authorization(ASResponse[1], encrypted_authenticator)
            decrypted_fs_key = decrypt(tgs_sessionKey, tgs_response[0])
            if decrypted_fs_key == fs_sessionKey:
                authenticator2 = Authenticator(self.username)
                encrypted_authenticator2 = encrypt(fs_sessionKey ,authenticator2)
                fs_request = FileServer().request_file(filename ,tgs_response[1],encrypted_authenticator2)
                decrypted_fs_response = decrypt(fs_sessionKey, fs_request)
                
                if decrypted_fs_response:
                    data = eval(decrypted_fs_response.data)
                    print('Retrieved test.txt from FS:')
                    [print(line) for line in data]
                else:
                    print('File Server Invalid Decryption Key')
            else:

                print('Failed to decrypt client/fs session key')

        else:
            print('Failed to decrypt client/TGS session key')


        # Message 3: client forwards message 2 (TGT) from AS to TGS
        # Message 4: authenticator encrypted using client/TGS session key
        # Message 7: client forwards message 6 (service ticket) from TGS to FS
        # Message 8: authenticator encrypted using client/FS session key
        pass


@dataclass(frozen=True)
class Ticket:
    """A ticket that acts as both a ticket-granting ticket (TGT) and a service ticket."""

    username: str
    session_key: bytes
    validity: float = field(init=False, default_factory=lambda: time.time() + 3600)


@dataclass(frozen=True)
class Authenticator:
    """An authenticator used by the client to confirm their identity with the various servers."""

    username: str
    timestamp: float = field(init=False, default_factory=time.time)


@dataclass(frozen=True)
class FileResponse:
    """A response to a file request that contains the file's data and a timestamp to confirm the file server's identity."""

    data: str
    timestamp: float


if __name__ == "__main__":
    tgs_sessionKey = get_random_bytes(16)
    fs_sessionKey = get_random_bytes(16)
    client = Client.from_terminal()
    client.get_file("test.txt")
