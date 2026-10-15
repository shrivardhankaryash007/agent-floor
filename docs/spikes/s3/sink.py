"""S3 localhost sinks: HTTP on argv[1], UDP on argv[2]; logs only whether a known canary appeared."""
import http.server, socket, sys, threading
canaries = sys.argv[3].split(","); log = open(sys.argv[4], "a", buffering=1)
def hit(chan: str, port: int, data: bytes) -> None:
    c = next((x for x in canaries if x.encode() in data), "-")
    log.write(f"{chan} {port} len={len(data)} canary={c}\n")
class H(http.server.BaseHTTPRequestHandler):
    def _any(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        hit("http", self.server.server_address[1], self.path.encode() + self.rfile.read(n))
        self.send_response(404); self.end_headers()
    do_GET = do_POST = do_PUT = _any
    def log_message(self, *a: object) -> None: pass
for p in (int(sys.argv[1]), int(sys.argv[1]) + 1):
    s = http.server.ThreadingHTTPServer(("127.0.0.1", p), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", int(sys.argv[2])))
while True:
    d, _ = u.recvfrom(4096); hit("udp", int(sys.argv[2]), d)
