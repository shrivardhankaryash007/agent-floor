"""S2: a parent proxy that records the request line of each allowed connection, then refuses it (no real egress)."""
import socketserver, sys
log = open(sys.argv[2], "a", buffering=1)
class H(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        line = self.rfile.readline(512).decode("latin-1").strip()
        method, target = (line.split(" ") + ["", ""])[:2]
        log.write(f"{method} {target}\n")
        self.wfile.write(b"HTTP/1.1 502 agent-floor-s2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
socketserver.ThreadingTCPServer.allow_reuse_address = True
with socketserver.ThreadingTCPServer(("127.0.0.1", int(sys.argv[1])), H) as s:
    s.serve_forever()
