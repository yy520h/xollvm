import http.client
import http.server
import os
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path


RELAY_TOKEN = "relay-secret"
ADMIN_TOKEN = "admin-secret"


class BackendHandler(http.server.BaseHTTPRequestHandler):
    requests = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.__class__.requests.append((self.path, self.headers.get("Authorization"), body))
        if self.path == "/v2/relay" and self.headers.get("Authorization") == "Bearer " + RELAY_TOKEN:
            self.send_response(200)
        elif self.path == "/v2/admin/builds/import" and self.headers.get("Authorization") == "Bearer " + ADMIN_TOKEN:
            self.send_response(200)
        else:
            self.send_response(401)
        self.end_headers()

    def do_GET(self):
        self.__class__.requests.append((self.path, self.headers.get("Authorization"), b""))
        if self.path == "/v2/trust/test.software":
            self.send_response(200)
        else:
            self.send_response(404)
        self.end_headers()

    def log_message(self, *_):
        pass


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_proxy(backend_port, certificate, key):
    script = r'''
import http.server, socket, ssl, sys
target_port = int(sys.argv[1])
class Proxy(http.server.BaseHTTPRequestHandler):
    def handle_request(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path not in ("/v2/relay", "/v2/admin/builds/import", "/v2/trust/test.software"):
            self.send_response(404); self.end_headers(); return
        with socket.create_connection(("127.0.0.1", target_port)) as upstream:
            request = f"{self.command} {self.path} HTTP/1.1\r\nHost: backend\r\n"
            for name, value in self.headers.items():
                request += f"{name}: {value}\r\n"
            request += f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            upstream.sendall(request.encode() + body)
            response = b""
            while True:
                chunk = upstream.recv(4096)
                if not chunk: break
                response += chunk
        self.wfile.write(response)
    do_GET = handle_request
    do_POST = handle_request
    def log_message(self, *_): pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[2], sys.argv[3])
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()
'''
    return subprocess.Popen(
        [os.environ.get("PYTHON", "python3"), "-c", script,
         str(backend_port), str(certificate), str(key)],
        stdout=subprocess.PIPE, text=True)


def request(port, method, path, token=None, body=b"{}"):
    context = ssl._create_unverified_context()
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=3)
    headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    connection.request(method, path, body, headers)
    response = connection.getresponse()
    status = response.status
    response.read()
    connection.close()
    return status


def main():
    with tempfile.TemporaryDirectory(prefix="xovm-tls-fixture-") as temporary:
        certificate = Path(temporary) / "cert.pem"
        key = Path(temporary) / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "1",
            "-subj", "/CN=localhost",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BackendHandler)
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        proxy = None
        try:
            proxy = start_proxy(backend.server_port, certificate, key)
            proxy_port = int(proxy.stdout.readline().strip())
            assert request(proxy_port, "POST", "/v2/relay", RELAY_TOKEN) == 200
            assert request(proxy_port, "POST", "/v2/admin/builds/import", ADMIN_TOKEN) == 200
            assert request(proxy_port, "POST", "/v2/relay", ADMIN_TOKEN) == 401
            assert request(proxy_port, "POST", "/v2/admin/builds/import", RELAY_TOKEN) == 401
            assert request(proxy_port, "GET", "/v2/trust/test.software") == 200
            assert request(proxy_port, "POST", "/unknown", RELAY_TOKEN) == 404
            assert [item[0] for item in BackendHandler.requests] == [
                "/v2/relay", "/v2/admin/builds/import", "/v2/relay",
                "/v2/admin/builds/import", "/v2/trust/test.software"]
        finally:
            backend.shutdown()
            backend.server_close()
            if proxy is not None:
                proxy.terminate()
                proxy.wait(timeout=3)


if __name__ == "__main__":
    main()
