import struct
from enum import Enum


class MessageType(Enum):
    SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1
    SSH_AGENT_RSA_IDENTITIES_ANSWER = 2
    SSH_AGENTC_RSA_CHALLENGE = 3
    SSH_AGENT_RSA_RESPONSE = 4
    SSH_AGENT_FAILURE = 5
    SSH_AGENT_SUCCESS = 6
    SSH_AGENTC_ADD_RSA_IDENTITY = 7
    SSH_AGENTC_REMOVE_RSA_IDENTITY = 8
    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9
    SSH2_AGENTC_REQUEST_IDENTITIES = 11
    SSH2_AGENT_IDENTITIES_ANSWER = 12
    SSH2_AGENTC_SIGN_REQUEST = 13
    SSH2_AGENT_SIGN_RESPONSE = 14
    SSH2_AGENTC_ADD_IDENTITY = 17
    SSH2_AGENTC_REMOVE_IDENTITY = 18
    SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19
    SSH_AGENTC_ADD_SMARTCARD_KEY = 20
    SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21
    SSH_AGENTC_LOCK = 22
    SSH_AGENTC_UNLOCK = 23
    SSH_AGENTC_ADD_RSA_ID_CONSTRAINED = 24
    SSH2_AGENTC_ADD_ID_CONSTRAINED = 25
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26


class MessageInvalid(Exception):
    pass


class SSHMessage:
    def __init__(self, bytes):
        "bytes may include more than one SSH message; in which case this will parse the first message"
        self._data = bytes
        if len(self._data) < 1:
            raise MessageInvalid()
        self._decode()

    def get_data(self):
        return self._data

    def _decode(self):
        code, = struct.unpack('B', self._data[:1])
        try:
            self._code = MessageType(code)
        except ValueError:
            raise MessageInvalid()

    def get_code(self):
        return self._code
