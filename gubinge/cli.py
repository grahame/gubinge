import asyncio
import argparse
import os.path
from socket import gethostname


class SSHAgentConnection:
    def __init__(self, connection_id, client_reader, client_writer):
        self._client_reader = client_reader
        self._client_writer = client_writer
        self._id = connection_id

    def log(self, *args, **kwargs):
        print("[%d]" % self._id, *args, **kwargs)

    @asyncio.coroutine
    def handle(self):
        self.log("connected")
        while True:
            data = yield from self._client_reader.read(8192)
            if not data:
                break
            self.log(">> got data", data)
            self._client_writer.write(data)
        self.log("disconnected")


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
        conn = SSHAgentConnection(self.get_id(), client_reader, client_writer)
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
