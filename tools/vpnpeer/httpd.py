from http.server import BaseHTTPRequestHandler, HTTPServer
import socket, subprocess
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        ip = subprocess.run(["hostname","-i"],capture_output=True,text=True).stdout.strip()
        body = (f"OK - you reached the VPS container behind Docker NAT,\n"
                f"over a DIRECT libp2p QUIC hole-punch + WireGuard.\n"
                f"container-hostname={socket.gethostname()} container-ip={ip}\n"
                f"path={self.path}\n").encode()
        self.send_response(200)
        self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self,*a): pass
print("httpd on 0.0.0.0:8080", flush=True)
HTTPServer(("0.0.0.0",8080), H).serve_forever()
