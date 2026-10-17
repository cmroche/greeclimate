---
name: gree-emulator-device
description: Add a device, MID, or protocol family to the PC Gree emulator using independently verified firmware LAN behavior and explicitly labeled appliance simulation.
---

# Add an emulator device

Use this when adding a device/MID/profile to `gree_emulator`. Read `docs/EMULATOR.md`, the relevant family and its conformance/research fixtures first. Follow repository guidelines and the firmware-download skill when acquiring a missing source. Do not edit generated `CHANGELOG.md`.

## Contract

The registered `sim-*` profiles are deliberately simulated appliances with firmware-evidenced LAN formats. They are not full firmware boots or calibrated mainboards. Keep source behavior, safe parser deviations, chosen model behavior and unknowns separate. Do not register a full-firmware ID while a physical-fidelity prerequisite is missing.

Runtime remains standard library plus the existing PyCryptodome dependency, Python >=3.10, independent of `greeclimate`, its enums/ciphers/temperature heuristics, test helpers, research tools and vendor binaries. No plugin framework, executable configuration, runtime firmware database or client-side compatibility patch.

## Procedure

1. **Classify the target.** Preserve exact MID strings, including leading zeros. Determine whether evidence shows an emitted appliance, gateway/container, child, routing comparison, normalized alias or fallback. MID is not HID/build identity; filename, polling catalog, `commProtVer`, similar numbers and neighboring MIDs are not implementation equivalence.
2. **Locate and qualify the executable.** Resolve the actual payload from inventory/HIDS/MIDS and the download skill. Recompute original/extracted SHA-256; inspect embedded identity, CPU/ISA, mapped segments and ROM dependencies. Never overwrite prior decompilation projects. Use ignored research directories and the root `venv/` only. Native replay dependencies are research-only.
3. **Describe states/transitions before editing.** Identify startup controls, bind/key state, routing selectors, command validation, requested/effective values, old-controls thermal advance, new-controls state, next status and restart reset. For gateways distinguish root cache, per-child cache, shared fields and child identity lifecycle. Use workflowz workers only for genuine independent research/implementation slices, with explicit file ownership and a shared interface; retain one integration owner.
4. **Trace both directions.** Follow UDP entry → envelope → key/cipher/padding → inner dispatch → property/binary mapping → command mutation → cache → reply. Record scalar/array rules, field order/duplicates, types, masks, clipping, metadata, aliases, unknown/read-only names, batch failure, size limits and reply casing. Check disassembly where decompilation is ambiguous. Resolve crypto independently; never infer GCM or copy the client's trailing-brace stripping.
5. **Run independent source probes.** Prefer actual instructions. Where ISA support is absent, use bounded instruction-matched translations with exact byte/hash assertions and label them accordingly. Declare libc/JSON/ROM/I/O boundaries. Substituting an identified AES primitive is not native hardware AES execution; supplying a serial/cache input is not physical calibration. Do not hook the behavior being proved or turn a native fault into a fictitious successful transaction.
6. **Persist expectations first.** Add sanitized `*_research.json` evidence and runnable JSON vectors under `tests/fixtures/emulator/`. Separate native values from literal model-policy expectations. Never generate expected outputs with emulator/profile/client objects. Preserve malformed/partial requests, ordered duplicates, wrong targets/keys, exact response envelopes and next-status state. Keep binaries, bulk decompiled vendor code, private captures and credentials out of tracked files.
7. **Choose the smallest correct runtime change.** If the same family truly implements the MID, extend its exact `Profile.mids` tuple and independently exercise MID-dependent branches. Otherwise add a concrete family module. Do not duplicate identical handlers per MID or infer a common family from matching sensor names. Use the existing `Profile`, `Reply`, strict wire codec and pure thermal step only where semantics match.
8. **Integrate completely.** Register the family's static `PROFILES`; add necessary config/topology validation, fixtures, focused behavioral regressions, and support/evidence rows in `docs/EMULATOR.md`. `find_packages` already discovers the package. No `greeclimate/__init__.py` export or entry-point wrapper is needed. Update every affected caller/schema/example, not just the handler.
9. **Verify real behavior.** Run independent raw-peer transactions through an actual CLI process, including malformed recovery, command → fresh status, distinct devices/clients, bind/rebind, topology/pagination and clean Ctrl-C socket release. Check temperature direction, monotonic elapsed time, quantization, idle drift and stable seeded IDs across reorder/restart. Run focused regressions, then the existing full suite/lint once integration settles. Report exact commands/interpreter and observed failures. Exercise the public library separately without monkeypatching it; do not change the emulator's evidence contract merely to make that consumer pass.
10. **Document the boundary.** Only after smoke proof, finish the guide and remove temporary smoke scaffolds. A blocked target needs the exact missing source/transport/calibration, sources tried and affected operations—not a stub, silent MID fallback or unsupported “supported” profile. Finish reachable targets. Report physical hardware, full boots, other Python versions and Home Assistant UI as unverified unless actually exercised.

## Runtime interface and invariants

| Interface / field | Requirement |
| --- | --- |
| `advertise(device, outer) -> list[Reply]` | Root discovery only, exact family metadata/envelope. Startup preflights advertisements. |
| `handle(device, outer) -> list[Reply]` | Family-owned key selection and inner routing. Invalid packets raise `InvalidPacket`; unsupported operations produce no fake success. Bound reply size before command mutation. |
| `thermal_target(device) -> tuple[str, float] \| None` | Explicit appliance action/target; `None` for roomless containers. No setpoint-as-ambient inference. |
| `encode_room(device) -> None` | Exact declared synthetic sensor policy for an evidenced field. Sensorless families intentionally expose no ambient LAN field. |
| `validate_state(state)` | Only real modeled writable fields, strict integer/range checks, no identity/private/derived overrides. |
| Optional `validate_topology(root)` | Runs after all links exist. Validate native identity relationships, shared aliases and ordering; do not infer whether a resolved MAC was explicitly configured. |
| `Profile` | Frozen metadata with exact ID/MIDs/HID/source hash, fresh per-device state, handler, identity width, permitted parents, maximum child count and any evidenced `max_request_bytes`. The server checks original UDP bytes, not compact re-serialized JSON; do not invent a receive limit from an unrelated reply buffer. |
| `Reply` | Plain outer/inner dictionaries plus selected key/codec. Shared wire layer performs crypto/framing, not policy guessing. |
| Atomic commands | Validate whole batch before advancing clocks or changing any cache. Preserve native response distinctions and documented synthetic ranges. |
| Multiple devices | No shared mutable appliance state. Children may intentionally share parent controls/key only when their actual topology establishes it. |

## Example 1: another MID in a proven family

`w04n.py` implements one evidenced N dialect for several actual runtime AC branches. Adding `10002`/`13000` was a tuple extension only after native scan/bind/status/command qualification; it did not require a handler copy. The reserved baseline `standard.py` implementation was not fabricated: CS532AE's original ROM crypto ABI remains unresolved, so the real existing family is used instead.

Relevant files: `gree_emulator/profiles/w04n.py`, `w04n-mids-native_research.json`, `w04n-mid-10002.json`, and the guide's support table. A runnable example from the repository root:

```sh
venv/bin/python3.14 -m gree_emulator --profile sim-w04n-v17 --mid 10002 --seed skill-example --listen 127.0.0.1 --port 0
```

Use the printed endpoint for an independent peer. Assert the discovered MID is exactly `10002`, bind using its advertised MAC, command modeled fields, then check fresh ordered status. Keep `TemSen`'s normalized synthetic range and native command `p` versus final-value `val` distinction; do not copy H-family raw bias or p-only acknowledgements.

## Example 2: a genuinely different child topology

W06AV children are not standalone devices. The parent emits MID `60`, has no room, binds with `bindOk`, and enumerates seven-byte child IDs. The child reports `TemBody`, not `TemSen`. Its command receives `p` and emits both `p` and `val`.

Save this as `gateway.json`:

```json
{
  "seed": "skill-gateway",
  "listen": "127.0.0.1",
  "port": 0,
  "devices": [
    {"id": "gateway", "profile": "sim-w06av-v30", "mid": "60", "mac": "020000000010"},
    {"id": "office", "profile": "sim-w06av-v30-ac", "mid": "6049", "parent": "gateway", "mac": "02000000001101"},
    {"id": "bedroom", "profile": "sim-w06av-v30-ac", "mid": "604a", "parent": "gateway", "mac": "02000000001201"}
  ]
}
```

```sh
venv/bin/python3.14 -m gree_emulator --config gateway.json
```

Outer encrypted requests target `tcid=020000000010`. After binding, enumerate with inner `{"t":"subDev","mac":"020000000010","i":0}`. Control only office with `{"t":"cmd","mac":"020000000010","sub":"02000000001101","opt":["Pow","Mod","SetTem"],"p":[1,1,22]}`. Poll each child using its inner `mac`; assert bedroom retains power off and target 24. For pagination, extend to at least six children and independently check pages starting at 0, 5 and the child count. Never truncate child IDs to NIC width or bind them as separate roots.

These examples use only synthetic identities. The unmodified current public client appends unsupported `BuzzerCtrl` to commands; discovery/binding/polling works in the observed N-model probe, but that command batch is rejected. Use independent peer checks to establish emulator behavior and report this consumer mismatch separately. No Home Assistant UI or physical-device compatibility claim follows from these examples.
