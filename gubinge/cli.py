import asyncio
import argparse
import os.path
from socket import gethostname


class SSHAgentProxy:
    def __init__(self, bind_path, proxy_path):
        self._bind_path = bind_path
        self._proxy_path = proxy_path
        self._loop = asyncio.get_event_loop()

    @asyncio.coroutine
    def _client_connected(self, client_reader, client_writer):
        print(">> client_connected", client_reader, client_writer)
        while True:
            data = yield from client_reader.read(8192)
            if not data:
                break
            print(">> got data", data)
            client_writer.write(data)

    @asyncio.coroutine
    def serve(self):
        yield from asyncio.start_unix_server(self._client_connected, path=self._bind_path)


def main():
    parser = argparse.ArgumentParser()
    args = parser.parse_args()  # noqa

    loop = asyncio.get_event_loop()
    socket_path = os.path.expanduser("~/.gubinge/sock-%s-%d" % (gethostname(), os.getpid()))
    proxy = SSHAgentProxy(socket_path, os.getenv("SSH_AUTH_SOCK"))
    os.environ["SSH_AUTH_SOCK"] = socket_path

    print(socket_path)
    loop.run_until_complete(proxy.serve())
    try:
        loop.run_forever()
    finally:
        loop.close()
