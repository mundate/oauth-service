import pytest
from pydantic import SecretStr

from src.util import validate_password


@pytest.mark.parametrize("length", [12, 128])
def test_validate_password_accepts_allowed_lengths(length: int):
    password = SecretStr("a" * length)

    assert validate_password(password) is password


@pytest.mark.parametrize("length", [11, 129])
def test_validate_password_rejects_disallowed_lengths(length: int):
    with pytest.raises(ValueError):
        validate_password(SecretStr("a" * length))
