"""Basic tests for netmonitor.network."""

from netmonitor.network import detect_vpn, get_adapters, get_connections


def test_get_connections_returns_list():
    result = get_connections()
    assert isinstance(result, list)


def test_get_adapters_returns_list():
    result = get_adapters()
    assert isinstance(result, list)


def test_detect_vpn_returns_list():
    result = detect_vpn()
    assert isinstance(result, list)
