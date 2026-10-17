# Gree firmware families with verified cloud-only builds

Findings as of 17 October 2026. SIMCom QMI modules are excluded.

The version columns show the **latest verified LAN-capable build** and **earliest observed cloud-only build**, not guaranteed transition releases. Missing intermediate builds and non-monotonic version labels prevent a universal cutoff.

| MID | Firmware Code | Module Type | Firmware Versions Examined | Device Type | Last Verified LAN Version | First Observed Cloud-Only Version |
|---|---|---|---|---|---|---|
| Unknown | `362001066300` | `4MWB05DF13` | `3.05`, `3.27`, `4.12` | Not established | **3.05** — native UDP/7000 bind and receive polling | **3.27** |
| Unknown | `362001067540` | `WB05WR13` | `2.04`, `2.06` | Not established | **2.06** — native UDP/7000 bind and receive polling | **2.04** — not a monotonic cutoff |
| Unknown | `362001067541` | `WB05WR11` | `2.04`, `2.08`, `2.09`, `2.10` | Air conditioner | **2.04** — native verification and owner-confirmed local control | **2.08** |
| `10001` reported on `2.09`; not recovered from these binaries | `362001068254` | `4MWB65VR` | `2.11`, `2.12` | Air conditioner — Airy / Clivia reports | **2.11** — native verification and owner-confirmed local control | **2.12** |
| Unknown | `362001068295` | `4MWB05UR` | `2.02`, `2.04` — two distinct `2.04` builds | Not established | **2.02** — native UDP/7000 bind and receive polling | **2.04** |
| Unknown | `362001068411` | `WB05HR13` | `1.02`, `2.07`, `4.07` | Not established | **Not found** | **1.02** |
| Unknown | `362001071519` | `4MWB65AR11` | `2.00` binary; `2.04` owner report | Air conditioner reported for `2.04`: Gree Clivia R22; `2.00` appliance unverified | **Not found** | **2.00** |

## Important qualifications

- **WB05WR13 has non-monotonic version labels:** the inspected exact-code `2.06` image has LAN support, while the inspected `2.04` image does not. Do not interpret `2.04` as a numeric threshold above which all builds are cloud-only.
- **Uninspected version gaps:** DF13 `3.06–3.26`, WR11 `2.05–2.07`, and UR `2.03`. The first cloud-only release could be within those gaps.
- **HR13 `1.02` is already affected:** bounded native replay leaves the LAN descriptor at `-1`, polls no LAN descriptor, and follows the outgoing cloud connection path. Its archived metadata explicitly says certification-agency testing only; others must not upgrade.
- **`commProtVer: V3.2.M` alone does not prove cloud-only operation.** Several verified LAN builds also advertise it.
- Unknown MIDs and device types are deliberate: runtime MCU-supplied identities and SDK defaults do not establish the attached appliance.

Verification used native disassembly and bounded instruction replay, supplemented by owner reports for WB05WR11 and WB65VR. Native replay is not a full hardware boot or a physical command test.

No firmware was flashed. These findings are not flashing recommendations: some images are test-only, and matching version labels do not establish hardware compatibility.
