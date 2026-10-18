# PC device emulator

`python -m gree_emulator` runs independent simulated Gree-compatible appliances on one IPv4 UDP endpoint. It replaces the old MicroPython `emulator.py`; there is no compatibility launcher.

**These are explicitly simulated appliances, not complete firmware/mainboard emulations.** The `sim-*` prefix distinguishes firmware-evidenced LAN formats from chosen control ranges, initial state, and thermal behavior. Full-firmware profile IDs remain unregistered. Missing cryptography, device-side transport, or executable identity evidence still prevents registration; a catalog entry alone is not support.

## Run

Use Python 3.10 or newer and the repository's existing `venv/`. Runtime dependencies are the standard library and the already declared PyCryptodome. Unicorn, Capstone, vendor binaries, and research exports are not runtime dependencies.

```sh
python -m gree_emulator --list-profiles
python -m gree_emulator --profile sim-w04n-v17 --mid 10001 --count 3 --seed ha-lab --listen 127.0.0.1 --port 7000
venv/bin/python3.14 -m gree_emulator --config examples/emulator-devices.json
```

Select a supported root-venv interpreter, for example `venv/bin/python3.14 -m gree_emulator`; activating an older environment does not upgrade Python. No arguments prints help and exits 2. Invalid configuration exits 2; socket startup failure exits 1; Ctrl-C closes the socket and exits 0. `--list-profiles` opens no socket and cannot be combined with startup options.

| Option | Contract |
| --- | --- |
| `--profile`, `--mid` | Both required for generated devices; exact registered strings, no MID guessing/fallback. |
| `--count` | Positive integer, default 1; generated IDs are `device-1`, `device-2`, etc. |
| `--config PATH` | JSON configuration; mutually exclusive with profile/MID/count. |
| `--seed TEXT` | Overrides configuration seed; omitted seed is fresh for each run. |
| `--listen ADDRESS` | IPv4 literal; overrides configuration; default `0.0.0.0`. |
| `--port NUMBER` | Overrides configuration; default 7000; 0 requests an ephemeral port. |

Startup prints the actual endpoint, followed by each device's ID, name, profile, MID, wire MAC, and parent. It does not print seeds or keys. Only root devices advertise; children are enumerated through their parent.

The CLI logs incoming (`RX`) and outgoing (`TX`) UDP traffic to stderr at INFO level. RX metadata includes the peer IP/port and original byte count, followed by a separate decoded payload line once parsing/decryption succeeds. TX lines include the peer IP/port, encrypted wire byte count and plaintext reply payload. Payloads use Python dictionary notation with control characters escaped; encrypted `pack` strings and undecodable raw input are not logged. Rejected requests still log RX metadata and, if decoding succeeded, their plaintext payload. Network encryption is unchanged. Startup announcements stay on stdout. **Plaintext bind replies include emulator session keys.** Treat logs as sensitive: scrub keys, identities and addresses before sharing. No log file is created automatically.

**Trusted test networks only.** The default listens on every IPv4 interface. Prefer loopback for raw-peer checks or an isolated development VLAN for Home Assistant. This legacy AES-ECB protocol is not authenticated. Deterministic test keys are not credentials. There is no OTA, cloud, Wi-Fi configuration, file access, or PC network reconfiguration through device commands.

## Configuration and identity

The checked-in [representative configuration](../examples/emulator-devices.json) runs from the repository root and covers all eight protocol families: 16 device records, nine advertising roots and seven routed children. It includes two W06AV gateways with two independently controlled indoor units each, plus a commercial host with one AC child and a zone controller with a master and one zone.

The example uses loopback, UDP 7000 and a fixed synthetic seed. Names default to logical IDs; controls start off with 24°C targets and appliance rooms at 26°C. Containers have no room temperature. Use `--port 0` if 7000 is occupied, or `--listen 0.0.0.0` only on an isolated trusted network. Restart resets controls while preserving the seeded identities.

A mixed standalone configuration:

```json
{
  "seed": "ha-lab",
  "listen": "127.0.0.1",
  "port": 7000,
  "devices": [
    {"id": "office", "name": "Emulated Office", "profile": "sim-w04h-v3.55", "mid": "10001", "room_c": 26, "ambient_c": 26},
    {"id": "bedroom", "name": "Emulated Bedroom", "profile": "sim-w04h-v3.55", "mid": "10001", "room_c": 26, "ambient_c": 26},
    {"id": "third", "name": "Emulated Third", "profile": "sim-w04n-v17", "mid": "10001", "state": {"SetTem": 28}}
  ]
}
```

| JSON field | Meaning |
| --- | --- |
| Root `devices` | Required nonempty array. Other root fields are `seed`, `listen`, `port`. |
| Device `id`, `profile`, `mid` | Required strings. IDs and canonical wire MACs must be unique. MID strings preserve leading zeros. |
| `name` | Nonempty UTF-8 name; defaults to ID. Oversized unadvertisable metadata is rejected at startup. |
| `mac` | Optional hexadecimal wire identity, without separators; exactly 12 characters for roots or 14 for these child families. Canonicalized to lowercase. |
| `parent` | Parent logical ID; declaration order is irrelevant. Required for child profiles; unsupported parents, cycles, and excessive child counts are rejected. |
| `room_c`, `ambient_c` | Finite Celsius numbers, default 26. Only appliances have rooms; gateway/container roots reject these fields. |
| `state` | Optional object of modeled writable integer properties. Identity, private keys, derived sensors, unsupported fields, booleans, and out-of-range values are rejected. |

Unknown keys, duplicate JSON keys, nonfinite numbers, and malformed UTF-8 are errors, not silently ignored configuration.

Identity is independent of array order, profile, MID, and name:

* MAC digest: SHA-256 of compact, non-ASCII-escaped UTF-8 JSON `["gree-emulator-mac", seed, id]`; take the profile's six or seven bytes, then set the first byte to `(byte & 0xfc) | 2` (locally administered unicast).
* Bound key: first 16 hexadecimal ASCII characters of SHA-256 over the same JSON encoding of `["gree-emulator-key", seed, id]`.
* An explicit MAC overrides only the wire identity, not key derivation. Children use the parent's bound key.
* Reusing seed and IDs preserves identities/keys across reordering and adding devices. Without a seed, identities change on restart. Operating state and temperature are **not persisted**; restart reloads configuration.

### Gateways and zones

All children use the parent's UDP endpoint and key; their longer identifiers are protocol IDs, not additional NIC addresses. The emulator does not spoof network interfaces.

| Family | Topology and addressing |
| --- | --- |
| W06AV | Root `sim-w06av-v30` / MID `60`; up to 255 `sim-w06av-v30-ac` children. Generated seven-byte child identities are supported. `subDev` pages contain at most five children. Status uses inner `mac=child`; command uses `sub=child`, with optional `mac=parent`. |
| WB04BRT13 | Root `sim-wb04brt13-v1.50-60` / MID `60`; exactly one `-6400`, `-6045`, or `-609d` child with the matching MID. Child MAC must equal parent MAC plus `00`. Root and child address the same appliance cache; root has no separate room. Native command `mac` takes precedence over `sub`. |
| W05SA | Root `sim-w05sa-v1.28` / MID `50` may be empty. With children, master `-master` / MID `5000` is required at slot 0; optional `-zone` / MID `5001` occupies slots 1–8. Child MAC is parent MAC plus `0` plus slot digit. Sparse slots are allowed only with master slot 0; enumeration is slot-sorted, five per page. Commands select with `sub`; status with `mac`. Numbered shared properties such as `StTem1` and `EnWdVlv1` work through the parent or either child role; unnumbered `Pow` and `StTem` retain their master/zone-local mappings. |

Use explicit parent/child MACs for the two parent-derived formats. Validation checks the resolved identities rather than requiring an unnecessary explicit-MAC flag.

A commercial example (`commercial.json`):

```json
{
  "seed": "commercial-lab",
  "listen": "127.0.0.1",
  "port": 0,
  "devices": [
    {"id": "host", "profile": "sim-wb04brt13-v1.50-60", "mid": "60", "mac": "020000000001"},
    {"id": "unit", "profile": "sim-wb04brt13-v1.50-6400", "mid": "6400", "parent": "host", "mac": "02000000000100"}
  ]
}
```

```sh
python -m gree_emulator --config commercial.json
```

## Model behavior and packet differences

Each appliance owns its controls and floating-point room temperature. One monotonic, one-second ticker advances rooms; a command first settles elapsed time under the old controls, then changes controls. A valid batch is applied in order, with the final duplicate value retained. Every field validates before any command mutation or clock advance. Unsupported/read-only/malformed command batches are discarded without a success response.

| Model policy | Behavior |
| --- | --- |
| Ordinary AC controls | `Pow` 0–1, `Mod` 0–4, integer Celsius `SetTem` 16–30, `WdSpd` 0–5, where present in the family's actual namespace. |
| Other controls | Available flags use 0–1; `SlpMod` 0–3, `SwingLfRig` 0–6, `SwUpDn` 0–11, `Quiet` 0–3 (DV restricts Quiet to 0–1). Each family exposes only its evidenced subset. |
| Units and optional features | `TemUn`/`TemRec` store display bits; they do not convert the Celsius model target or change sensor bias. Optional flags are independent, not a recreation of appliance interlocks. `StHt=1` selects 8°C in heat mode where that field exists. |
| Active thermal model | Auto moves toward target; cool/dry move downward only; heat moves upward only. Rate 1°C/minute, clamped at target without overshoot. |
| Idle thermal model | Power off or fan-only drifts toward ambient at 0.1°C/minute, without overshoot. Fan speed and swing do not change the thermal rate. |
| Zones | Target `16 + StTem`, code 0–15. Master power gates every zone; local zone power also gates that zone. Shared Mod 1 cools, 2 heats, other modes idle. Changing shared controls settles all rooms under the old mode first. |
| Reported sensors | Floor physical Celsius, apply the explicit model bias, then clamp to the family's field width/range below. Zero is a valid encoded value, not a universal unavailable sentinel. Sensorless families do not manufacture an ambient field. |

The chosen default is power off, 24°C target and 26°C room/ambient where those controls exist. Metadata and initial values are simulator starting conditions, not claims about hardware boot defaults.

| Family / runnable profile | Exact MIDs and role | Sensor model | LAN distinctions |
| --- | --- | --- | --- |
| `sim-w04h-v3.55` | `10001`, standalone | `TemSen = clamp(floor(C)+40,0,255)` | `bindok`; command `opt/p`, no `val`. Unknown status names are safely dropped with the packet because native lookup can fault. Known unmodeled fields are omitted. Exactly 30 status columns produces empty arrays. |
| `sim-w04n-v17` | `10001`, `10002`, `10014`, `10015`, `10016`, `10017`, `11000`, `11001`, `11002`, `11010`, `11f00`, `11f01`, `11f02`, `11f03`, `13000`; standalone runtime AC routes | `TemSen = clamp(floor(C),0,50)` | `bindok`; mirrors request key selector. Command `p` preserves requested values, `val` reflects final duplicate values. Unknown/unmodeled status omitted. Max 64 property names / 512 aggregate name bytes; replies below `0x7b4` bytes. |
| `sim-wb04a-v1.49` | `10f05`, `10010`, `10011`, `11011`, `11012`; standalone | `TemSen = clamp(floor(C)+40,0,255)` | `bindok`, command `p` only; status account UID 0 is separate from outer request UID. Safe omission replaces native unknown-name faults. Max 32 columns/commands and 1460-byte packet boundary. |
| `sim-w04hb-v1.20` | `302b`, standalone controller | No ambient LAN sensor | `bindok`, command `p` only; native blank version/vendor metadata; 30-column status behavior. |
| `sim-w06dv-v4.01` | `3018`, standalone controller | No ambient LAN sensor | `bindok`; bound-key controls; command `opt/p/val` has no inner `mac`. Do not copy AV response metadata into DV. |
| `sim-wb04brt13-v1.50-{MID}` | Standalone `3019`, `3027`, `4005`; host `60`; children `6400`, `6045`, `609d` | Appliance `InTem = clamp(floor(C),0,65535)`; no `TemSen` alias | `bindok`, command `p` only; status account UID 0; 1460-byte packet boundary. Source aliases `3017`, `3018`, `302c` emit standalone `3019`, not their original input MID. |
| `sim-w06av-v30`, `sim-w06av-v30-ac` | Host `60`; children `6049`, `604a`, `604b`, `604c`, `605c`, `608f`, `6092` | Child `TemBody = clamp(floor(C),0,255)` | Case-sensitive `bindOk`, `subDev/subList`; command receives `p`, replies with `p` and `val`. Unknown status names return empty strings; known unmodeled fields omitted. No invented `TemSen`. |
| `sim-w05sa-v1.28`, `-master`, `-zone` | Host `50`; master `5000`; zones `5001` | No ambient LAN sensor | Case-sensitive `bindOk`; enumeration may arrive generic-key but replies bound-key; bound-key status/commands, `p` only. Shared root aliases and 1024-byte packet boundary. |

All registered families use independently identified AES-ECB with PKCS#7 and strict base64. H/HB/WB use bound-key control replies even for supported generic-key requests; N/commercial retain their own selector rules. There is no inferred GCM support.

Receive limits are checked against the **original UDP byte length**, including whitespace and escaped JSON, before family dispatch: H/HB/AV/DV at most 1024 bytes, WB04A at most 1460, BRT below 1460, and zones below 1024. A scan is filtered per receiving profile, not by the smallest limit on the endpoint. N retains its declared property/reply bounds without inventing an additional receive-buffer limit.

WB04A and WB04BRT13 accept **one optional terminal NUL after JSON, before PKCS#7**. Native complete encrypted command replay required that terminator to avoid an absent-column search overrunning padding. Safe ordinary JSON is also accepted deliberately; multiple NULs, embedded/trailing garbage, bad padding and ambiguous JSON are rejected. Replies do not add a NUL. Memory faults, unsafe native coercions, arbitrary cache writes, and buffer overruns are not reproduced.

## Source and evidence manifest

The conformance fixtures in [`tests/fixtures/emulator`](../tests/fixtures/emulator) separate runnable packet/model vectors from `*_research.json`. Expected packets were obtained independently of the emulator/client; synthetic state expectations are labeled as such. Native execution hooks declared libc/JSON/ROM/I/O boundaries. Substituting the independently identified AES primitive is not execution of a hardware AES engine. Bounded, byte-matched Xtensa translations are not native execution or a full firmware boot.

| Build / source SHA-256 | Trace anchors | Evidence and limits |
| --- | --- | --- |
| W04H V3.55 — `17b1c7812a3f98fa1e800e786b37606d842ebbf0b38a25c0ec5c173fcaaa9f2e` | Envelope `0x080525d0`, dispatch `0x08052234`, status `0x08052ff0`, command `0x08053288`, builder `0x08052914` | Native Thumb paths and ROM AES ABI; `w04h_research.json`. Raw sensor transport plus explicit simulated Celsius policy. |
| W04N V17 — `b0b7f5d428858ca5e5ad29a8afcfaa0da4063fe36e98fae7c447047163112727` | Sensor getter `0x0802d2a4`; per-MID native dispatcher vectors | Native Thumb scan/bind/status/command for every listed MID; `w04n-native_research.json` and related per-MID vectors. Exact runtime routes, not retail-model identification. |
| WB04A V1.49 — `0d5ee6fda1678084e1fa29e6267941afae304090b5b97f7b4264f9cee7fd461b` | Identity `0x9b01ef34`, dispatcher `0x9b0230e8`, command `0x9b021fd0`, status `0x9b0221c0` | Native Thumb full encrypted transactions for all five MIDs; `wb-native_research.json`, `wb-additional-mids_research.json`, sensors and heat-branch captures. SDK AES functions byte-matched independently. |
| W04HB V1.20 — `5a4705122e69dfb99462fdeef1d19e8b7ce7315d6cdad895849c87ef0cfdfea8` | Dispatch `0x0805f564`, builder `0x0805fa20`, status `0x080601fe`, command `0x08060432` | Native Thumb packet construction/encryption and disassembled receive dispatch; `hb-native_research.json`. All 476 table entries inspected; no ambient sensor found. |
| WB04BRT13 V1.50 — `44c79dc1a2dba15123f4ae9cc9a90a14234459ba6aa04df8eee2e98ef406e660` | Router `0x9b02b2b8`, dispatcher `0x9b02dee8`, enumeration `0x9b02c9ac`, command `0x9b02fc8c`, status `0x9b02fe78` | Native Thumb encrypted framing, NUL command replay, shared-cache next status and real child/alias routing; `commercial-*_research.json`. Physical binary-mainboard behavior is not simulated. |
| W06AV V30 — `6b52f31a74a74c5a88f3d8b68f8b4afc89fcd8d59e3d11a287a4ec37825bf79b` | Envelope `0x00a13124`, enumeration `0x00a139fc`, status `0x00a13cf8`, receiving command `0x00a13f24`, result `0x00a13608` | Byte-matched Xtensa translations and independently resolved QCA4010 ROM AES; `gateway_research.json`. TemBody is a proven byte transport, not proven physical Celsius calibration. |
| W06DV V4.01 — `eabd04d49c518699f2800805bd4f6085ff3b2092b8a2394fb1e22c04fb7f7c9f` | Exact exported source/property/reply traces in `controller_research.json` | Byte-matched Xtensa packet paths; no ambient namespace. Not an alias of BRT's input-3018 route. |
| W05SA V1.28 — `aae6c0782b8d2a3d7fd5c071fbd23ab292dc1d42cf864c1307df961d9305e864` | Dispatch `0x0805d9d4`, builder `0x0805e6fc`, status `0x0805f124`, setter `0x0805f3f2`, aliases `0x0805d4ac` | Native Thumb packet/crypto and sparse topology captures in `zone-*_research.json`. Correct extraction is image27, not image26/V1.27. Native setter's trailing out-of-range iteration was boundary-isolated, not claimed fault-free hardware behavior. |

Primary cryptographic references include the [Ameba-Z ROM symbol map](https://github.com/libretiny-eu/libretiny/blob/master/cores/realtek-ambz/misc/export-rom_symbol_v01.txt) and the pinned [RTL8710C crypto API](https://raw.githubusercontent.com/libretiny-eu/framework-realtek-ambz2/5f7b9378a7f226a46e3b13349844a3f5f07565aa/component/common/mbed/targets/hal/rtl8710c/crypto_api.c). Exact SDK/object hashes and resolved addresses are retained with the relevant research vectors.

### Investigated but not registered

| Target / role | Evidence and precise remaining gap |
| --- | --- |
| `cs532ae-v3.35` / MID `10001` | Source `b59faeabd300a96498bd1e07ebd800d79aeb02b07523e027ecb9401bee07ef77`; byte-matched parser/encoder/cache/reply and padding paths recovered. Original ROM security table at `0x435f34` is absent from all extracted segments. Public QCA4010 SDK 2.1 uses a different ABI; SDK 1.1 archive access is authentication-gated. Cryptographic primitive identity remains unproved for this exact image. H/N models do not impersonate it. |
| `0001`, `10f01`, `10f02`, `809032`, `12000`–`12003`, `15000` | Catalog associations do not identify a complete executable AC path. Existing firmware inventory, mobile-app routing and MID documents were searched; no arbitrary default or neighboring MID substitution. |
| `3062` | Full firmware corpus and app resources expose polling metadata but no exact firmware-code/executable route. Numeric firmware code `362001063062` is unrelated 828xxx evidence, not an association. |
| W05RV / `80221` | Exact V2.35/V2.41 images emit `80221`, not `15000`. Recovered surface is IR learning/button storage (`Studied`, `AddButton`, `SendButton`); the actual AC button-code/control contract is missing. No invented Pow/ambient fields. |
| W06KV hosts `80241`/`80242`, routed `6000`, `10f00`, `10f10`, `10003`, `10007`, `11005` | Source `6ac3db6c6b5d72d327171d2bc16223c626301a194511a44931ad86de4135abd8`; `devs` parser `0x00a10270`, relay builders `0x00a0ce5c`/`0x00a0cf34`. Missing downstream appliance identity/session-key negotiation and response contract. An accepted route is not a standalone emitted appliance. |
| ZTS31A / plugin `807002` and associated plugin MIDs | Source `5ba439396454e99496d2de6744cf26769ca2c70a43bb5a0b116925936f5eb0bc`; actual host/plugin dispatch and binary transforms recovered. This is **not cloud-only**: host sends discovery, accepts `UBind` registration, maintains private peer keys/cache, and forwards to a separate UDP appliance. Missing external appliance/bridge executable or complete registration/key/binCmd/ack capture prevents an end-to-end model. Other N/WB profiles supporting some of these MID strings are not ZTS aliases. |
| BRT route `6200` | Native router/enumerator produces a `Filter` child with suffix `01`, unlike `6045`/`609d` ACUnit suffix `00`; classified separately, not registered as an AC. |
| Full-firmware versions of all `sim-*` profiles | Mainboard response/calibration, complete boots, hardware AES execution and physical appliances were not validated. Explicit synthetic models do not close those fidelity gaps. |

## Home Assistant and consumer checks

Keep the seed and logical IDs stable before adding test devices. Home Assistant's Gree integration uses MAC-based device identity; restarting with ephemeral identities can create new entries. Inspecting identity code is not an end-to-end Home Assistant test.

1. Use a development Home Assistant instance on an isolated reachable subnet. Start with three standalone N or H devices, a fixed seed, distinct names, and UDP port 7000. Loopback works only when the consumer shares the host/network namespace.
2. Allow UDP discovery/replies through the test firewall. Let Gree discovery run, then add discovered devices using the integration's discovery flow; do not assume a manual host/key form or gateway support.
3. Check separate names/MACs, binding, current/target temperatures, and command results **after a fresh status poll**, not merely after a successful send.
4. Restart the emulator with the same seed/IDs, reorder configuration, and add a fourth device. Existing identities should remain unchanged. Operating state resets to the configured defaults.
5. Remove test integration entries after the experiment. Never reuse real-device MACs/keys or run controls against production appliances.

Source reference: [Home Assistant Gree integration, 2026.10.2](https://github.com/home-assistant/core/tree/2026.10.2/homeassistant/components/gree), including its MAC-based entity/device identifiers and pinned `greeclimate==2.1.4` dependency. That dependency is not necessarily this checkout. Gateway UI and physical-device interoperability are unverified.

**Observed local-client mismatch:** the unmodified public library discovered, bound and polled three N-model devices correctly. Its `Device.push_state_update()` appended `BuzzerCtrl`, absent from these evidenced namespaces. The emulator rejected the whole command batch; the next status still reported power off and target 24°C. The method returned without an exception, so successful send was not successful control. No fictional property, relaxed command validation, or client patch was added to hide this mismatch. Home Assistant control is not claimed working.

## Verification and extending support

The independent raw-UDP checks exercised real CLI processes: multi-device isolation, malformed-packet recovery, stable identities/keys across restart/reordering, socket release on Ctrl-C, and a 65-second thermal interval. A separate seven-child AV run exercised page sizes 5/2/0, longer child IDs and isolated child controls. Native research and conformance fixtures remain separate from public-library consumption.

`test_example_config_starts_families_and_isolates_gateways` launches the checked-in example through the public CLI and exercises every family, all four parent enumerations, independent AV controls, cross-parent routing/key rejection, and UDP endpoint release.

Run repository checks using the supported root-venv interpreter:

```sh
venv/bin/python3.14 -m pytest tests/test_emulator.py
venv/bin/python3.14 -m pytest --cov-report=xml --cov=greeclimate tests/
venv/bin/python3.14 -m flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
```

For another device/MID, use [the repository authoring skill](../.agents/skills/gree-emulator-device/SKILL.md). Preserve independent expectations, exact source identity, topology and confidence labels. Do not import the client, its ciphers/heuristics, native research tools, or test helpers into runtime code. `setup.py` already discovers the package; no new client exports, plugin loader, runtime firmware data, or packaging wrapper is required.
