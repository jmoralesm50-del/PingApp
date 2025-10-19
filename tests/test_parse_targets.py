import pytest
from app.core.scanner import parse_targets

def test_parse_cidr():
    assert parse_targets("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]

def test_parse_range():
    assert parse_targets("192.168.1.10-192.168.1.12") == [
        "192.168.1.10","192.168.1.11","192.168.1.12"
    ]

def test_parse_single():
    assert parse_targets("192.168.1.55") == ["192.168.1.55"]

@pytest.mark.parametrize("text", ["", "   ", "192.168.1.12-192.168.1.10"]) 
def test_parse_invalid(text):
    with pytest.raises(ValueError):
        parse_targets(text)
