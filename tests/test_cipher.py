import base64
import json

import pytest

from greeclimate.cipher import CipherV1, CipherV2, CipherBase


@pytest.fixture
def cipher_v1_key():
    return b'ThisIsASecretKey'


@pytest.fixture
def cipher_v1(cipher_v1_key):
    return CipherV1(cipher_v1_key)


@pytest.fixture
def cipher_v2_key():
    return b'ThisIsASecretKey'


@pytest.fixture
def cipher_v2(cipher_v2_key):
    return CipherV2(cipher_v2_key)


@pytest.fixture
def plain_text():
    return {"message": "Hello, World!"}


def test_encryption_then_decryption_yields_original(cipher_v1, plain_text):
    encrypted, _ = cipher_v1.encrypt(plain_text)
    decrypted = cipher_v1.decrypt(encrypted)
    assert decrypted == plain_text


def test_decryption_with_modified_data_raises_error(cipher_v1, plain_text):
    _, _ = cipher_v1.encrypt(plain_text)
    modified_data = base64.b64encode(b"modified data   ").decode()
    with pytest.raises(UnicodeDecodeError):
        cipher_v1.decrypt(modified_data)


def test_encryption_then_decryption_yields_original_with_tag(cipher_v2, plain_text):
    encrypted, tag = cipher_v2.encrypt(plain_text)
    decrypted = cipher_v2.decrypt(encrypted, tag)
    assert decrypted == plain_text


@pytest.mark.parametrize("tag", [None, "", "%%%", "YQ==", 1, [], {}])
def test_v2_rejects_missing_or_malformed_tag(cipher_v2, plain_text, tag):
    encrypted, _ = cipher_v2.encrypt(plain_text)
    with pytest.raises((ValueError, TypeError)):
        cipher_v2.decrypt(encrypted, tag)


def test_v2_rejects_modified_tag(cipher_v2, plain_text):
    encrypted, tag = cipher_v2.encrypt(plain_text)
    modified = bytearray(base64.b64decode(tag))
    modified[0] ^= 1
    with pytest.raises(ValueError):
        cipher_v2.decrypt(encrypted, base64.b64encode(modified).decode())
    with pytest.raises(ValueError):
        cipher_v2.decrypt(encrypted, "!" + tag)


def test_v2_rejects_modified_ciphertext_that_remains_valid_json(cipher_v2):
    payload = {"t": "dat", "cols": ["Pow"], "dat": [1]}
    encrypted, tag = cipher_v2.encrypt(payload)
    modified = bytearray(base64.b64decode(encrypted))
    modified[json.dumps(payload).encode().rindex(b"1")] ^= ord("1") ^ ord("0")
    with pytest.raises(ValueError):
        cipher_v2.decrypt(base64.b64encode(modified).decode(), tag)


def test_cipher_base_not_implemented():
    fake_key = b'fake'
    
    with pytest.raises(NotImplementedError):
        CipherBase(fake_key).encrypt(None)
        
    with pytest.raises(NotImplementedError):
        CipherBase(fake_key).decrypt(None)
        
