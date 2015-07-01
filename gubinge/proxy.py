import asyncio
import os.path
import struct
from socket import gethostname
from collections import deque
from .proto import SSHMessage, SSHKeyList, MessageType


class StreamException(Exception):
    pass


loop = asyncio.get_event_loop()


class ResponderFixed:
    upstream = False

    def __init__(self, response_bytes):
        self._response_bytes = response_bytes

    def handle(self, writer):
        SSHAgentConnection.send_message(writer, self._response_bytes)


class ResponderProxy:
    upstream = True

    def handle(self, writer, mesg):
        SSHAgentConnection.send_message(writer, mesg)


class ResponderFilterIdentities:
    upstream = True

    def handle(self, writer, mesg):
        print("TODO filter identities", mesg)
        keylist = SSHKeyList.from_bytes(mesg.get_data())
        print(keylist)
        SSHAgentConnection.send_message(writer, mesg)


class MessageActionSSH1EmptyIdentities:
    def process(self, writer):
        return ResponderFixed(SSHMessage(
            struct.pack(
                '>BI',
                MessageType.SSH_AGENT_RSA_IDENTITIES_ANSWER.value, 0)))


class MessageActionFilterIdentities:
    def __init__(self, mesg):
        self._mesg = mesg

    def process(self, writer):
        SSHAgentConnection.send_message(writer, self._mesg)
        return ResponderFilterIdentities()


class MessageActionCheckSign:
    def __init__(self, mesg):
        self._mesg = mesg

    def process(self, writer):
        print("TODO check we want to sign:", self._mesg)
        SSHAgentConnection.send_message(writer, self._mesg)
        return ResponderProxy()


class MessageActionDrop:
    def process(self, writer):
        return None


class MessageActionProxy:
    def __init__(self, mesg):
        self._mesg = mesg

    def process(self, writer):
        SSHAgentConnection.send_message(writer, self._mesg)
        return ResponderProxy()


class MessageActionFailure:
    def process(self, writer):
        return ResponderFixed(SSHMessage(
            struct.pack(
                '>B',
                MessageType.SSH_AGENT_FAILURE.value)))


class SSHAgentConnection:
    message_buffer_size = 256
    read_size = 8192
    # arbitrary limit - taken from ssh-agent.c in OpenSSH
    max_message_size = 256 * 1024

    def __init__(self, proxy_path, connection_id, client_reader, client_writer):
        self._proxy_path = proxy_path
        self._client_reader = client_reader
        self._client_writer = client_writer
        self._id = connection_id
        # pending responders
        self._pending_queue = deque(maxlen=SSHAgentConnection.message_buffer_size)
        # responses in from the client
        self._response_queue = deque(maxlen=SSHAgentConnection.message_buffer_size)

    def log(self, *args, **kwargs):
        print("[%d]" % self._id, *args, **kwargs)

    @classmethod
    @asyncio.coroutine
    def read_messages_from_stream(cls, stream, callback):
        buffer = b''
        while True:
            data = yield from stream.read(SSHAgentConnection.read_size)
            if not data:
                break
            buffer += data
            while True:
                buffer, mesg = cls.read_one_message(buffer)
                if mesg is None:
                    break
                callback(mesg)

    @classmethod
    def read_one_message(cls, buffer):
        if len(buffer) < 4:
            return buffer, None
        mesg_length, = struct.unpack('>I', buffer[:4])
        remainder = buffer[4:]
        if len(remainder) < mesg_length:
            return buffer, None
        if mesg_length > SSHAgentConnection.max_message_size:
            raise StreamException()
        mesg = SSHMessage(remainder[:mesg_length])
        return remainder[mesg_length:], mesg

    @classmethod
    def send_message(cls, writer, mesg):
        data = mesg.get_data()
        writer.write(struct.pack('>I', len(data)))
        writer.write(data)

    @asyncio.coroutine
    def go(self):
        self.log("connection received")
        upstream_reader, upstream_writer = yield from asyncio.open_unix_connection(path=self._proxy_path)
        self.log("connected to upstream")
        loop.create_task(self.read_from_upstream(upstream_reader))
        try:
            yield from SSHAgentConnection.read_messages_from_stream(
                self._client_reader,
                lambda mesg: self.message_from_client(upstream_writer, mesg))
            self.log("disconnected")
        finally:
            upstream_writer.close()

    @asyncio.coroutine
    def read_from_upstream(self, upstream_reader):
        yield from SSHAgentConnection.read_messages_from_stream(upstream_reader, self.message_from_upstream)
        self.log("disconnected from upstream")

    def get_mesg_action(self, mesg):
        code = mesg.get_code()
        if code == MessageType.SSH_AGENTC_REQUEST_RSA_IDENTITIES:
            return MessageActionSSH1EmptyIdentities()
        if code == MessageType.SSH2_AGENTC_REQUEST_IDENTITIES:
            return MessageActionFilterIdentities(mesg)
        if code == MessageType.SSH2_AGENTC_SIGN_REQUEST:
            return MessageActionCheckSign(mesg)
        if code in [MessageType.SSH_AGENT_FAILURE, MessageType.SSH_AGENT_SUCCESS]:
            return MessageActionDrop()
        if code in [
                MessageType.SSH2_AGENTC_ADD_IDENTITY,
                MessageType.SSH2_AGENTC_REMOVE_IDENTITY,
                MessageType.SSH2_AGENTC_REMOVE_ALL_IDENTITIES,
                MessageType.SSH2_AGENTC_ADD_ID_CONSTRAINED]:
            return MessageActionProxy(mesg)
        return MessageActionFailure()

    def _run_queue(self):
        while len(self._pending_queue) > 0:
            responder = self._pending_queue.popleft()
            # simple, baked message waiting in the queue;
            # can be sent whenever we get up to it
            if not responder.upstream:
                responder.handle(self._client_writer)
                continue
            # responder requires a message from upstream
            # if we don't have one, requeue it and end run
            if len(self._response_queue) == 0:
                self._pending_queue.appendleft(responder)
                break
            else:
                mesg = self._response_queue.popleft()
                responder.handle(self._client_writer, mesg)

    def message_from_client(self, upstream_writer, mesg):
        self.log("from client", mesg.get_code())
        action = self.get_mesg_action(mesg)
        responder = action.process(upstream_writer)
        if responder:
            self._pending_queue.append(responder)
            self._run_queue()

    def message_from_upstream(self, mesg):
        self.log("from upstream", mesg.get_code())
        self._response_queue.append(mesg)
        self._run_queue()


class SSHAgentProxy:
    def __init__(self, bind_path, proxy_path):
        self._bind_path = bind_path
        self._proxy_path = proxy_path
        self._id = 0

    def get_id(self):
        issue = self._id
        self._id += 1
        return issue

    @asyncio.coroutine
    def _client_connected(self, client_reader, client_writer):
        conn = SSHAgentConnection(self._proxy_path, self.get_id(), client_reader, client_writer)
        yield from conn.go()

    @asyncio.coroutine
    def serve(self):
        yield from asyncio.start_unix_server(self._client_connected, path=self._bind_path)


def proxy():
    socket_path = os.path.expanduser("~/.gubinge/sock-%s" % (gethostname()))  # , os.getpid()))
    try:
        os.unlink(socket_path)
    except OSError:
        pass
    proxy = SSHAgentProxy(socket_path, os.getenv("SSH_AUTH_SOCK"))
    os.environ["SSH_AUTH_SOCK"] = socket_path

    loop.run_until_complete(proxy.serve())
    try:
        loop.run_forever()
    finally:
        loop.close()
