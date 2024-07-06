import base64
import pytest
from greeclimate.cipher import CipherV1, CipherV2


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
    decrypted = cipher_v2.decrypt(encrypted)
    assert decrypted == plain_text

