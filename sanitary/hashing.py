"""Support for hashing of sensitive values."""

from __future__ import annotations

import hashlib
from typing import Callable, Optional, Protocol, runtime_checkable, Union

HASHLIB_FUNCTIONS = tuple(
    getattr(hashlib, name) for name in dir(hashlib) if not name.startswith("_")
)


@runtime_checkable
class HashObjectProtocol(Protocol):
    """
    Protocol for objects returned by the `hashlib` library functions.

    See `hashlib` documentation for details:
    https://docs.python.org/3.10/library/hashlib.html
    """

    @property
    def block_size(self) -> int:
        """The internal block size of the hash algorithm in bytes."""

    @property
    def digest_size(self) -> int:
        """The size of the resulting hash in bytes."""

    @property
    def name(self) -> str:
        """
        The canonical name of this hash.

        Always lowercase and always suitable as a parameter to new()
        to create another hash of this type.
        """

    def copy(self) -> HashObjectProtocol:
        """
        Returns an identical copy of the hash object.

        This can be used to efficiently compute the digests of data
        sharing a common initial substring.
        """

    def digest(self, length: Optional[int] = None) -> str:
        """
        Return the digest of the data passed to the update() method so far.

        This is a bytes object of size digest_size which may contain bytes in the
        whole range from 0 to 255.

        The SHAKE algorithms provide variable length digests with
        `length_in_bits//2` up to 128 or 256 bits of security, so their digest
        methods require a length.

        Args:
            length: Optional length in bytes, required of SHAKE algorithms.
        """

    def hexdigest(self, length: Optional[int] = None) -> str:
        """
        Like `digest()`, except containing only hexadecimal digits.

        This may be used to exchange the value safely in email or other
        non-binary environments.

        Args:
            length: Optional length in bytes, required of SHAKE algorithms.
        """

    def update(self, obj: bytes, /) -> None:
        """
        Update the hash object with the bytes-like object.

        Repeated calls are equivalent to a single call with the concatenation of
        all the arguments: m.update(a); m.update(b) is equivalent to m.update(a+b).

        Args:
            obj: The byte-string to concatenate to the previous value.
        """


ReplacementType = Union[str, Callable[[str], str], Callable[[bytes], HashObjectProtocol]]
