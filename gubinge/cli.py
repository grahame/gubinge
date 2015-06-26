import asyncio
import argparse
import struct
import os.path
from socket import gethostname
from enum import Enum


class MessageType(Enum):
    SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1
    SSH_AGENTC_RSA_CHALLENGE = 3
    SSH_AGENTC_ADD_RSA_IDENTITY = 7
    SSH_AGENTC_REMOVE_RSA_IDENTITY = 8
    SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9
    SSH_AGENTC_ADD_RSA_ID_CONSTRAINED = 24
    SSH2_AGENTC_REQUEST_IDENTITIES = 11
    SSH2_AGENTC_SIGN_REQUEST = 13
    SSH2_AGENTC_ADD_IDENTITY = 17
    SSH2_AGENTC_REMOVE_IDENTITY = 18
    SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19
    SSH2_AGENTC_ADD_ID_CONSTRAINED = 25
    SSH_AGENTC_ADD_SMARTCARD_KEY = 20
    SSH_AGENTC_REMOVE_SMARTCARD_KEY = 21
    SSH_AGENTC_LOCK = 22
    SSH_AGENTC_UNLOCK = 23
    SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED = 26
    SSH_AGENT_FAILURE = 5
    SSH_AGENT_SUCCESS = 6
    SSH_AGENT_RSA_IDENTITIES_ANSWER = 2
    SSH_AGENT_RSA_RESPONSE = 4
    SSH2_AGENT_IDENTITIES_ANSWER = 12
    SSH2_AGENT_SIGN_RESPONSE = 14
    SSH_AGENT_CONSTRAIN_LIFETIME = 1
    SSH_AGENT_CONSTRAIN_CONFIRM = 2


class MessageTruncated(Exception):
    pass


class MessageInvalid(Exception):
    pass


class SSHMessage:
    def __init__(self, bytes):
        "bytes may include more than one SSH message; in which case this will parse the first message"
        if len(bytes) < 4:
            raise MessageTruncated()
        self._length, = struct.unpack('>I', bytes[:4])
        if len(bytes) < self._length:
            raise MessageTruncated()
        if self._length < 1:
            raise MessageInvalid()
        self._data = bytes[:4+self._length]
        self._parse()

    def __len__(self):
        "length of this message, including the length uint at the front"
        return 4 + self._length

    def get_data(self):
        return self._data

    def _parse(self):
        code, = struct.unpack('B', self._data[4:5])
        try:
            self.code = MessageType(code)
        except ValueError:
            raise MessageInvalid()
        print("woot, we have a complete message, len=%d, code=%s" % (len(self), self.code))


class SSHAgentConnection:
    def __init__(self, proxy_path, connection_id, client_reader, client_writer):
        self._proxy_path = proxy_path
        self._client_reader = client_reader
        self._client_writer = client_writer
        self._id = connection_id
        self._buf = b''

    def log(self, *args, **kwargs):
        print("[%d]" % self._id, *args, **kwargs)

    @asyncio.coroutine
    def handle(self):
        self.log("connected")
        proxy_reader, proxy_writer = yield from asyncio.open_unix_connection(path=self._proxy_path)
        try:
            self.log("proxy connection opened", proxy_reader, proxy_writer)
            while True:
                data = yield from self._client_reader.read(8192)
                if not data:
                    break
                self.log(">> got data", data)
                self._buf += data
                for mesg in self._parse():
                    proxy_writer.write(mesg.get_data())
                    response = yield from proxy_reader.read(8192)
                    self._client_writer.write(response)
                    #self._respond(mesg)
            self.log("disconnected")
        finally:
            proxy_writer.close()

    def _parse(self):
        while self._buf:
            try:
                mesg = SSHMessage(self._buf)
            except MessageTruncated:
                break
            self._buf = self._buf[len(mesg):]
            yield mesg

    def _respond(self, mesg):
        if mesg.code is MessageType.SSH_AGENTC_REQUEST_RSA_IDENTITIES:
            self._client_writer.write(struct.pack('>IBI', 5, MessageType.SSH_AGENT_RSA_IDENTITIES_ANSWER.value, 0))
        elif mesg.code == MessageType.SSH2_AGENTC_REQUEST_IDENTITIES:
            self._client_writer.write(struct.pack('>IBI', 5, MessageType.SSH2_AGENT_IDENTITIES_ANSWER.value, 0))


class SSHAgentProxy:
    def __init__(self, bind_path, proxy_path):
        self._bind_path = bind_path
        self._proxy_path = proxy_path
        self._loop = asyncio.get_event_loop()
        self._id = 0

    def get_id(self):
        issue = self._id
        self._id += 1
        return issue

    @asyncio.coroutine
    def _client_connected(self, client_reader, client_writer):
        conn = SSHAgentConnection(self._proxy_path, self.get_id(), client_reader, client_writer)
        yield from conn.handle()

    @asyncio.coroutine
    def serve(self):
        yield from asyncio.start_unix_server(self._client_connected, path=self._bind_path)


def main():
    parser = argparse.ArgumentParser()
    args = parser.parse_args()  # noqa

    loop = asyncio.get_event_loop()
    socket_path = os.path.expanduser("~/.gubinge/sock-%s" % (gethostname()))  # , os.getpid()))
    try:
        os.unlink(socket_path)
    except OSError:
        pass
    proxy = SSHAgentProxy(socket_path, os.getenv("SSH_AUTH_SOCK"))
    os.environ["SSH_AUTH_SOCK"] = socket_path

    print(socket_path)
    loop.run_until_complete(proxy.serve())
    try:
        loop.run_forever()
    finally:
        loop.close()
