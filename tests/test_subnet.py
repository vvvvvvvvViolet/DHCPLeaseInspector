import pytest

from dhcp_inspector import config, subnet


def test_cidr_excludes_network_and_broadcast():
    ips = subnet.parse_targets("10.20.30.0/24")
    assert len(ips) == 254
    assert ips[0] == "10.20.30.1" and ips[-1] == "10.20.30.254"


@pytest.mark.parametrize("text, expected", [
    ("10.0.0.5/32", ["10.0.0.5"]),
    ("10.0.0.4/31", ["10.0.0.4", "10.0.0.5"]),
    ("10.20.30.7/30", ["10.20.30.5", "10.20.30.6"]),  # host bits tolerated
])
def test_small_prefixes_still_yield_addresses(text, expected):
    assert subnet.parse_targets(text) == expected


def test_ranges_full_and_last_octet_shorthand():
    assert subnet.parse_targets("10.0.0.10-10.0.0.12") == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
    assert subnet.parse_targets("10.0.0.10-12") == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]


def test_mixed_tokens_are_deduped_in_order():
    assert subnet.parse_targets("10.0.0.1-3, 10.0.0.2  10.0.1.0/30") == [
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.1.1", "10.0.1.2",
    ]


def test_ipv6_range():
    assert subnet.parse_targets("2001:db8::1-2001:db8::3") == [
        "2001:db8::1", "2001:db8::2", "2001:db8::3",
    ]


@pytest.mark.parametrize("text, message", [
    ("", "Enter a subnet"),
    ("10.0.0.0/8", "4096-host limit"),
    ("10.0.0.5-10.0.0.1", "ends before"),
    ("nonsense", "does not appear"),
])
def test_bad_input_raises_readable_error(text, message):
    with pytest.raises(ValueError, match=message):
        subnet.parse_targets(text)


def test_host_limit_follows_settings():
    config.save_settings(config.Settings(max_subnet_hosts=16))
    with pytest.raises(ValueError, match="16-host limit"):
        subnet.parse_targets("10.0.0.0/24")


def test_oversized_range_is_rejected_without_expanding_it():
    # Regression: this used to build 16M addresses (~20 s, GUI frozen)
    # before noticing it was over the limit.
    import time

    start = time.time()
    for text in ("10.0.0.0/8", "10.0.0.0-10.255.255.255", "2001:db8::/32"):
        with pytest.raises(ValueError, match="host limit"):
            subnet.parse_targets(text)
    assert time.time() - start < 1.0


def test_many_small_tokens_still_hit_the_limit():
    config.save_settings(config.Settings(max_subnet_hosts=300))
    with pytest.raises(ValueError, match="300-host limit"):
        subnet.parse_targets("10.0.0.0/24 10.0.1.0/24")


def test_range_exactly_at_the_limit_is_allowed():
    config.save_settings(config.Settings(max_subnet_hosts=254))
    assert len(subnet.parse_targets("10.0.0.0/24")) == 254
