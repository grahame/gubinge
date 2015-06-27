
import asyncio
import struct
import os.path
from socket import gethostname
from .proto import MessageType, SSHMessage, MessageTruncated


loop = asyncio.get_event_loop()


class SSHAgentConnection:
    def __init__(self, proxy_path, connection_id, client_reader, client_writer):
        self._proxy_path = proxy_path
        self._client_reader = client_reader
        self._client_writer = client_writer
        self._id = connection_id

    def log(self, *args, **kwargs):
        print("[%d]" % self._id, *args, **kwargs)

    @classmethod
    @asyncio.coroutine
    def read_messages_from_stream(cls, stream, callback):
        buffer = b''
        while True:
            data = yield from stream.read(8192)
            if not data:
                break
            buffer += data
            while True:
                buffer, mesg = cls._parse(buffer)
                if mesg is None:
                    break
                callback(mesg)

    @asyncio.coroutine
    def handle(self):
        def respond(mesg):
            self.log("from client", mesg.get_code())
            upstream_writer.write(mesg.get_data())

        self.log("connection received")
        upstream_reader, upstream_writer = yield from asyncio.open_unix_connection(path=self._proxy_path)
        self.log("connected to upstream")
        loop.create_task(self.read_from_upstream(upstream_reader))
        try:
            yield from SSHAgentConnection.read_messages_from_stream(self._client_reader, respond)
            self.log("disconnected")
        finally:
            upstream_writer.close()

    @asyncio.coroutine
    def read_from_upstream(self, upstream_reader):
        def respond(mesg):
            self.log("from real agent", mesg.get_code())
            self._client_writer.write(mesg.get_data())

        yield from SSHAgentConnection.read_messages_from_stream(upstream_reader, respond)
        self.log("disconnected from upstream")

    @classmethod
    def _parse(cls, buffer):
        try:
            mesg = SSHMessage(buffer)
        except MessageTruncated:
            return buffer, None
        return buffer[len(mesg):], mesg


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
        yield from conn.handle()

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

    print(socket_path)
    loop.run_until_complete(proxy.serve())
    try:
        loop.run_forever()
    finally:
        loop.close()
