import pytest

from greeclimate._protocol import (
    InvalidPacket,
    parse_discovery,
    parse_inventory_page,
    parse_properties,
    validate_inventory_page_bounds,
)


@pytest.mark.parametrize("pack", [None, [], "not-an-object"])
def test_property_parser_rejects_non_object_packets(pack):
    with pytest.raises(InvalidPacket):
        parse_properties(pack, "dat")


def test_property_parser_rejects_non_property_response():
    with pytest.raises(InvalidPacket):
        parse_properties({"t": "bindok", "key": "not-property-data"}, "bindok")


@pytest.mark.parametrize("pack", [None, [], "not-an-object"])
def test_discovery_parser_rejects_non_object_packets(pack):
    with pytest.raises(InvalidPacket):
        parse_discovery(pack, ("192.0.2.1", 7000))


@pytest.mark.parametrize(
    "val, expected",
    [
        (["from-val"], "from-val"),
        ([], "from-p"),
        (None, "from-p"),
    ],
)
def test_result_val_precedence_and_fallback(val, expected):
    assert parse_properties(
        {"opt": ["Pow"], "val": val, "p": ["from-p"]}, "res"
    ) == {"Pow": expected}


@pytest.mark.parametrize("val", ["not-an-array", ["too", "many"]])
def test_malformed_result_val_is_not_rescued_by_p(val):
    with pytest.raises(InvalidPacket):
        parse_properties(
            {"opt": ["Pow"], "val": val, "p": ["from-p"]}, "res"
        )


@pytest.mark.parametrize(
    "kind, columns, values",
    [
        ("dat", "cols", "dat"),
        ("res", "opt", "val"),
    ],
)
def test_parse_properties_retains_unknown_values_and_last_duplicate_wins(
    kind, columns, values
):
    raw = {"vendor-payload": [None, 7]}
    assert parse_properties(
        {
            columns: ["vendor-field", "Pow", "Pow"],
            values: [raw, 0, 1],
        },
        kind,
    ) == {"vendor-field": raw, "Pow": 1}


@pytest.mark.parametrize(
    "pack",
    [
        {"cid": "A1:B2-C3.D4:E5-F6", "name": "device"},
        {"mac": "", "cid": "A1:B2-C3.D4:E5-F6", "name": "device"},
    ],
    ids=["missing-mac", "empty-mac"],
)
def test_discovery_falls_back_to_cid_and_preserves_wire_spelling(pack):
    device = parse_discovery(pack, ("192.0.2.1", 7000))
    assert device.mac == "A1:B2-C3.D4:E5-F6"


def test_discovery_does_not_fall_back_from_nonempty_invalid_mac():
    with pytest.raises(InvalidPacket):
        parse_discovery(
            {"mac": "::", "cid": "001122334455", "name": "device"},
            ("192.0.2.1", 7000),
        )


def test_discovery_preserves_valid_mac_wire_spelling():
    wire_mac = "AA:BB-CC.DD:EE-FF"
    device = parse_discovery(
        {"mac": wire_mac, "cid": "001122334455", "name": "device"},
        ("192.0.2.1", 7000),
    )
    assert device.mac == wire_mac


def test_valid_inventory_page_is_returned_unchanged():
    page = {"r": 200, "c": 255, "i": 0, "list": [{}, {}, {}, {}, {}]}
    parsed = parse_inventory_page(page)
    assert parsed is page
    validate_inventory_page_bounds(parsed)


@pytest.mark.parametrize(
    "page",
    [
        None,
        {"r": 200, "c": 0, "i": 0},
        {"r": 200, "c": 0, "i": 0, "list": ()},
        {"r": 404, "c": 0, "i": 0, "list": []},
    ],
    ids=["not-a-dict", "missing-list", "non-list", "non-200"],
)
def test_invalid_inventory_page_shape_or_result_is_ignored(page):
    assert parse_inventory_page(page) is None


@pytest.mark.parametrize(
    "count, records",
    [
        (-1, []),
        (256, []),
        (0, [{}, {}, {}, {}, {}, {}]),
    ],
    ids=["negative-count", "count-too-large", "page-too-large"],
)
def test_inventory_page_bounds_reject_invalid_count_or_page_size(count, records):
    with pytest.raises(InvalidPacket):
        validate_inventory_page_bounds({"c": count, "list": records})
