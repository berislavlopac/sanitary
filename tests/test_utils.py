import hashlib

import pytest

from sanitary.hashing import HashObjectProtocol


@pytest.mark.parametrize("hash_algo", hashlib.algorithms_guaranteed)
def test_hash_output_is_protocol_instance(hash_algo):
    hash_function = getattr(hashlib, hash_algo)
    hashed = hash_function(b"blabla")
    assert isinstance(hashed, HashObjectProtocol)
