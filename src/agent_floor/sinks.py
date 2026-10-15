"""Localhost-only canary sinks that record metadata, never payloads."""

from collections.abc import Iterable
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
        raise NotImplementedError

    def __enter__(self) -> Self:
        """Bind 127.0.0.1:0 and start serving."""
        raise NotImplementedError

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Stop serving and close the socket."""
        raise NotImplementedError

    @property
    def port(self) -> int:
        """Return the bound localhost port."""
        raise NotImplementedError

    def hits(self, canaries: Iterable[str]) -> list[SinkHit]:
        """Return one metadata record per request, flagging any canary in the body."""
        raise NotImplementedError


class UdpSink:
    """Context manager holding one UDP socket on 127.0.0.1:0; stands in for DNS (S3)."""

    def __init__(self) -> None:
        """Prepare the sink without binding a socket."""
        raise NotImplementedError

    def __enter__(self) -> Self:
        """Bind 127.0.0.1:0 and start receiving."""
        raise NotImplementedError

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Stop receiving and close the socket."""
        raise NotImplementedError

    @property
    def port(self) -> int:
        """Return the bound localhost port."""
        raise NotImplementedError

    def hits(self, canaries: Iterable[str]) -> list[SinkHit]:
        """Return one metadata record per datagram, flagging any canary in it."""
        raise NotImplementedError
