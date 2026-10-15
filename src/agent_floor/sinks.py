"""Localhost-only canary sinks that record metadata, never payloads."""

import socket
import threading
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import NamedTuple, Self


class SinkHit(NamedTuple):
    """Metadata for one request a sink received."""

    method: str
    path_len: int
    body_len: int
    canary_hit: bool


class HttpSink:
    """Context manager running an http.server thread on 127.0.0.1:0."""

    def __init__(self) -> None:
        """Prepare the sink without binding a socket."""
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._records: list[tuple[str, int, bytes]] = []
        self._lock = threading.Lock()

    def __enter__(self) -> Self:
        """Bind 127.0.0.1:0 and start serving."""
        records = self._records
        lock = self._lock

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                with lock:
                    records.append((self.command, len(self.path), body))
                self.send_response(204)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Stop serving and close the socket."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._server = None
        self._thread = None

    @property
    def port(self) -> int:
        """Return the bound localhost port."""
        if self._server is None:
            raise RuntimeError("HTTP sink is not running")
        return int(self._server.server_address[1])

    def hits(self, canaries: Iterable[str]) -> list[SinkHit]:
        """Return one metadata record per request, flagging any canary in the body."""
        values = tuple(canaries)
        with self._lock:
            records = tuple(self._records)
        return [
            SinkHit(method, path_len, len(body), any(value.encode() in body for value in values))
            for method, path_len, body in records
        ]


class UdpSink:
    """Context manager holding one UDP socket on 127.0.0.1:0; stands in for DNS (S3)."""

    def __init__(self) -> None:
        """Prepare the sink without binding a socket."""
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._records: list[bytes] = []
        self._lock = threading.Lock()
        self._stopping = threading.Event()

    def __enter__(self) -> Self:
        """Bind 127.0.0.1:0 and start receiving."""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.1)
        self._stopping.clear()
        self._thread = threading.Thread(target=self._receive, daemon=True)
        self._thread.start()
        return self

    def _receive(self) -> None:
        """Record datagram bytes in memory for canary checks only."""
        if self._socket is None:
            return
        while not self._stopping.is_set():
            try:
                payload, _ = self._socket.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                return
            with self._lock:
                self._records.append(payload)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Stop receiving and close the socket."""
        self._stopping.set()
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._socket = None
        self._thread = None

    @property
    def port(self) -> int:
        """Return the bound localhost port."""
        if self._socket is None:
            raise RuntimeError("UDP sink is not running")
        return int(self._socket.getsockname()[1])

    def hits(self, canaries: Iterable[str]) -> list[SinkHit]:
        """Return one metadata record per datagram, flagging any canary in it."""
        values = tuple(value.encode() for value in canaries)
        with self._lock:
            records = tuple(self._records)
        return [
            SinkHit("UDP", 0, len(payload), any(value in payload for value in values))
            for payload in records
        ]
