"""Explicit appliance models with independently evidenced LAN packet formats."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class Profile:
    id: str
    mids: tuple[str, ...]
    hid: str
    source_sha256: str
    initial_state: Mapping[str, object]
    handler: object
    identity_bytes: int = 6
    parent_profiles: tuple[str, ...] = ()
    max_children: int = 0
    max_request_bytes: int | None = None
    identity_suffix: bytes = b""
    identity_from_parent: bool = False

    def __post_init__(self):
        if type(self.identity_suffix) is not bytes or len(self.identity_suffix) >= self.identity_bytes:
            raise ValueError("identity suffix must be bytes shorter than the complete identity")
        object.__setattr__(self, "initial_state", MappingProxyType(dict(self.initial_state)))


# Families import Profile, so registration follows its definition.
from . import (  # noqa: E402
    atw, catalog_cv, catalog_early_frvr, catalog_early_small, catalog_esp, catalog_esp_alarm,
    catalog_esp_radar, catalog_hydronic, catalog_legacy_direct, catalog_mtk, catalog_realtek_late,
    catalog_realtek_middle, catalog_realtek_third_bl, catalog_realtek_third_companions,
    catalog_realtek_third_numeric, catalog_realtek_third_tables, catalog_realtek_third_w04,
    catalog_tg_apj,
    catalog_early_hybrid, wb_rt13_v104, wb_rt13_v110,
    catalog_late_wb65,
    catalog_late_wb05crt,
    catalog_realtek_middle_ar,
    catalog_realtek_middle_wb,
    catalog_early_scalar, catalog_realtek_middle_wb_mf4,
    catalog_realtek_middle_wb_legacy,
    catalog_zts, central, commercial, controller, gateway, hb, hi3861,
    realtek_controller, voice, w04, w04n, w05z, wb, wb_adr, wb_gateway, wb_remaining, wb_rt13, zones,
)
from . import catalog_early_w05j  # noqa: E402


PROFILES = {
    profile.id: profile
    for family in (
        w04, w04n, w05z, wb, hb, commercial, controller, gateway, zones, atw,
        wb_gateway, wb_rt13, wb_remaining, voice, central, realtek_controller, hi3861, wb_adr,
        catalog_cv, catalog_early_frvr, catalog_early_small, catalog_esp, catalog_hydronic,
        catalog_legacy_direct, catalog_mtk,
        catalog_early_hybrid, wb_rt13_v104, wb_rt13_v110,
        catalog_late_wb65,
        catalog_late_wb05crt,
        catalog_realtek_middle_ar,
        catalog_realtek_middle_wb,
        catalog_early_scalar, catalog_realtek_middle_wb_mf4,
        catalog_realtek_middle_wb_legacy,
        catalog_realtek_late, catalog_realtek_middle, catalog_esp_alarm, catalog_esp_radar,
        catalog_realtek_third_bl, catalog_realtek_third_companions, catalog_realtek_third_numeric,
        catalog_realtek_third_tables, catalog_realtek_third_w04, catalog_tg_apj, catalog_zts,
        catalog_early_w05j,
    )
    for profile in family.PROFILES
}
