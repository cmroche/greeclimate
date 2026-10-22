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

- `WB05WR13` non-monotonic version change, possibly means local control was added back after being disabled.