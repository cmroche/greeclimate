---
name: gree-emulator-device
description: Integrate complete source-qualified Gree property assessments into accurate client profiles and fixture-driven bounded emulator wire models with explicitly synthetic appliance physics.
---

# Add an emulator device

Use this when adding or correcting a device/MID/profile or protocol family in `gree_emulator`. Pipeline: [discovery](../gree-firmware-discovery/SKILL.md) → [download](../gree-firmware-download/SKILL.md) → [decompile](../gree-firmware-decompile/SKILL.md) → [research](../gree-firmware-research/SKILL.md) → **emulator integration**. Read `docs/MIDS.md#emulator-contracts`, `docs/HIDS.md`, the relevant family, its complete property assessment and conformance fixtures first; detailed source research is preserved in private `https://github.com/cmroche/gree-research/blob/main/docs/EMULATOR.md` and `https://github.com/cmroche/gree-research/tree/main/tests/fixtures/emulator`. Consult `firmware-capabilities/research/SessionScan-verification.json` and `DecoderNext-verification.json` there with their linked qualifications, not as blanket support proof. Derive scope from the current source inventory; historical counts/results are not new acceptance evidence. Do not edit generated `CHANGELOG.md`.

## Contract

The registered `sim-*` profiles are deliberately simulated appliances with firmware-evidenced LAN formats. They are not full firmware boots or calibrated mainboards. Keep source behavior, safe parser deviations, chosen model behavior and unknowns separate. Use source-qualified bounded `sim-*` IDs; do not register a full-firmware ID by implying fidelity beyond the proved boundary.

Runtime remains standard library plus the existing PyCryptodome dependency, Python >=3.10, independent of `greeclimate`, its enums/ciphers/temperature heuristics, test helpers, research tools and vendor binaries. No plugin framework, executable configuration, runtime firmware database or client-side compatibility patch.

## Procedure

1. **Require the complete assessment.** Follow the research skill for every requested source file/build, not only each OTA code. Inventory every reachable getter/setter/raw forwarding route and every existing emulator gap before choosing implementation scope. A trait-empty identity profile or happy-path scan/bind fixture is not a property assessment. Finish all source-reachable behavior in the declared bounded wire namespace; explicitly block unresolved operations rather than silently narrowing the request.
2. **Classify the target.** Preserve exact MID strings, including leading zeros. Distinguish emitted appliance/gateway/child identities, configured/mainboard values, routing comparisons, normalized aliases and fallbacks. Trace alias conversion both ways. MID is not HID/build identity; filename, polling catalog, `commProtVer`, similar numbers and neighboring MIDs are not implementation equivalence. Raw IR/cache controls do not become typed AC devices merely by exposing `Pow`, `Mod` and `SetTem`.
3. **Qualify source and state.** Match original/extracted hashes and canonical runtime mappings to current decompiler evidence; never reuse load-image aliases as additional code or overwrite originals/projects. Use ignored research directories and root `venv/` only; replay dependencies stay research-only. Describe startup/cache initialization, bind/key state, routing, requested/effective values, old-controls thermal advance, command mutation, acknowledgement, next status and restart reset. Separate mainboard-supplied state from source defaults and chosen model defaults. For gateways distinguish root/per-child cache, shared fields and identity lifecycle.
   Before trusting an export's source-hash label, compare its actual mapped bytes at decisive instructions with the original image using the recorded file offset, destination and segment hash. Any mismatch blocks semantic conclusions and profile admission/removal until the export is repaired.
4. **Trace the complete transaction.** Follow socket → envelope/target → decrypt/key/cipher/padding → inner handler → raw property/binary mapping → mutation/cache → acknowledgement → fresh status. Establish the complete dispatched namespace from tables/callbacks/branches, not strings. Resolve opaque forwarding boundaries before making negative support claims. Check original disassembly where C is ambiguous; heuristic C coverage is not verified function coverage.
   Check RAM/literal/constructor initialization before treating a getter as absent; missing replay HID/cache setup is not firmware no-support evidence.
   Require evidenced device-side ingress: a TCP/cloud, MDF mesh or serial-only property handler does not authorize a synthetic UDP façade. Distinguish runtime-configured/mainboard-reported MID presets from fixed source-emitted identities.
5. **Qualify independent source probes.** Prefer actual instructions; where ISA support is absent use bounded instruction-matched translations with exact byte/hash assertions and label them accordingly. Declare libc/JSON/ROM/crypto/I/O hooks, addresses and ABI. Never hook the property/dispatch/mutation being proved. Substituted AES is not native hardware AES; supplied serial/cache input is not physical calibration. Preserve original faults with PC/instruction and their scope. A separately chosen safe atomic model is not a successful native transaction or full boot.
   Require binary-ABI-faithful primitive adapters, including caller-observed residual return registers from nominally void helpers and actual-version cJSON ownership/reference/list behavior. Engine ISA/CPU mode/model must be chosen before register/memory access. Tooling decode/setup and adapter failures are not native faults; resolve them before deriving fixtures or safe-model deviations.
   Reconcile every independent application/RAM bank and reject old blanket-`BL`-skip or forced-store results. Follow raw callback output through its numeric/boolean JSON constructor; raw masks do not determine serialized type.
6. **Persist complete expectations first.** Add sanitized `*_research.json` evidence and runnable JSON vectors under `tests/fixtures/emulator/`, accounting for every assessed property/operation and gap in the coverage matrix below. Use independently derived literal outputs, never emulator/profile/client-generated expectations. Separate native values, translation results and explicit model policies. Keep binaries, bulk decompiled vendor code, private captures and credentials out of tracked files.
7. **Choose the smallest complete implementation.** Extend an existing exact `Profile.mids` tuple only when the family truly implements that MID and every MID-dependent branch is qualified; otherwise add a concrete family module. Do not duplicate identical handlers or infer a common family from matching sensor names. Use existing `Profile`, `Reply`, strict wire codec and pure thermal step only where semantics match. Implement the complete bounded declared namespace, including raw fields and metadata, not just typed client controls.
8. **Integrate client and emulator contracts.** Evaluate every `DeviceProfile` field (`temperature_offset`, `relearn_temperature_offset`, `buzzer_properties`, `cooling_mode_value`, `capabilities`, `gateway_dialect`) with the research skill's evidence rules. Keep traits code-wide, not exact-version admission shims; a real unknown/no-change is preferable to an invented quirk. Assess exact `MidProfile.mid`, ordered `status_columns` and typed `family`, including raw-only roles. Register static `PROFILES`; update all affected callers, schemas, exports only where required, config/topology validation, fixtures, regressions, examples and public/private HIDS/MIDS/support evidence. `find_packages` already discovers the package; no unnecessary `greeclimate/__init__.py` export or entry-point wrapper.
9. **Verify through real entry points when authorized.** The integration owner runs independent raw-peer transactions against an actual CLI process: discovery/binding, wrong keys/targets, malformed recovery, requested/effective command → fresh status, distinct devices/clients, rebind/remate, topology/pagination, LF/UID/key-width cases and clean Ctrl-C/socket release. Check synthetic temperature direction, monotonic elapsed time, quantization, idle drift and seeded identities across reorder/restart. Exercise the unmodified public library separately, including raw and typed consumers where applicable; await command results before polling and account for automatic bind polls. Consumer incompatibility is a finding, not permission to falsify source behavior. Run focused regressions and existing full suite/lint once integration settles, only if authorized.
10. **Deliver evidence and concrete limits.** Report changed paths, per-source/MID property coverage, source/model deviations, exact commands/interpreter and observed results. In edit-only work, author probes/fixtures but run no probes/tests/build/lint/formatters; mark commands not run and hand them to the integration owner. A blocker names exact missing bytes/ISA/ROM/ABI/initialization/transport/calibration, evidence searched and blocked operations—not a blanket hardware excuse, stub or silent MID fallback. Finish reachable work. Complete all affected callers/tests/exports/docs and remove temporary smoke scaffolds. Physical hardware, full boots, other Python versions and Home Assistant UI remain unverified unless actually exercised.

## Complete bounded wire coverage

Keep an evidence-to-fixture matrix for each source/MID and each modeled operation/property. A finite fully traced dispatched LAN namespace can establish no support within that namespace; missing strings or opaque downstream forwarding cannot. “Unavailable value” and “unsupported property” are different outcomes. Each matrix row links original evidence, literal independent vectors, implementation and test, or a concrete unresolved prerequisite.

| Surface | Required source assessment and fixture behavior |
| --- | --- |
| Getters/setters and raw fields | Every name/alias, readable/writable scope, actual scalar/array type and metadata; missing/null/unavailable, unknown/read-only fields, requested versus stored/effective values, and independent fresh status. Include recognized metadata with zero/multiple getter values and preserve ragged `cols`/`dat`; similarly named setter/getter storage need not coincide. Do not omit untyped fields. |
| Conversion and validation | Signedness/width, masks, clipping/ranges, units/fractions and raw temperature encoding versus physical calibration; bool/string/float/null handling, mismatched arrays, empty/partial batches and limits. |
| Ordering and duplicates | Ordered property arrays and duplicate properties, duplicate JSON-member parser policy, native sequential effects versus chosen atomic behavior, ack `p`/`val` distinctions and exact response casing. |
| Wire and identity | Outer/inner metadata, discovery HID/MID/UID types and cache mutation, key/session index widths/masks, crypto/padding, target IDs and bounded original request/reply sizes. Qualify plaintext-object `pack` at `i=2` per source, inner LF before padding separately from outer LF, and fixed reply-port routing versus sender-port echo. |
| Topology and lifecycle | Root/child identities and widths, emitted/configured/alias/route MID roles, enumeration/page boundaries/order, supported maximums, shared versus isolated keys/cache, rebind/remate and seeded reorder/restart stability. Preserve fixed suffix bytes through enumeration and full-width routing comparison; canonicalize generated IDs only and reject incompatible explicit IDs rather than silently rewriting them. |
| Synthetic appliance | Include every known getter whose raw serialization/mutation is established, even without mainboard calibration. Choose and label synthetic cache/readout defaults and lifecycle; keep actual initialization/calibration unknowns separate. Explicit physics, old/new control timing, isolation and reset do not imply calibrated mainboard/peripheral behavior. |

Preserve parser/security boundaries even when firmware is unsafe. Document safe atomic validation, strict parsing and bounded sizing as deliberate model policy if native code partially mutates, accepts malformed input or faults. A native fault remains a fault qualifier; no fixture may relabel a chosen model response as original firmware success. Keep public-client profile quirks faithful to code-wide evidence instead of weakening transport/parser behavior to make that client pass.

A known getter is not optional because its physical sensor or initial mainboard value is unknown. Model its established wire semantics using a declared synthetic cache/readout and fixtures. Only an unestablished callback, output, schema or transport is a blocker to that bounded wire operation; calibration can block a physical-fidelity claim, not this implementation.

## Runtime interface and invariants

| Interface / field | Requirement |
| --- | --- |
| `advertise(device, outer) -> list[Reply]` | Root discovery only, exact family metadata/envelope. Startup preflights advertisements against an isolated root-state copy; validation must not consume live discovery counters or sessions. |
| `handle(device, outer) -> list[Reply]` | Family-owned key selection and inner routing. Invalid packets raise `InvalidPacket`; unsupported operations produce no fake success. Bound reply size before command mutation. |
| Optional handler `plaintext_types` | Declare only source-proved unwrapped request types for per-family `decode_outer` admission; keep the default strict. Preserve named plaintext hooks or route declared types to `handle`; no wildcard/global plaintext acceptance. Isolate each root's `InvalidPacket` rejection. Plaintext outer requests are distinct from an `i=2` plaintext-object `pack`. A source-qualified `decode_pack(number_parser=...)` hook owns numeric-token conversion and bounds without prior float conversion; JSON syntax, constants and Unicode validation stay strict. |
| Optional handler `decode_outer(data)` | Opt in only for source-proven header parsing. Parse original numeric tokens with `_json`, normalize the family's headers, then call `_validate_outer`; keep decoding pure. The server routes that result only to roots sharing this decoder, never to strict families. Verify mixed real-UDP roots for alias acceptance and strict-family rejection/non-mutation. |
| Optional `handle_plaintext_from(device, outer, data, addr)` | Receive original bytes only for the family's admitted plaintext types or builtin `wlan`, after size and peer-port gates. Use `Reply.raw_payload` for source-proven byte echoes; reserializing parsed JSON loses whitespace/order. Verify the real family over UDP, not a mock forwarding test. |
| Optional `handle_from(device, outer, addr)` / `tick(device, now)` | Use only for source-proved peer-addressed lifecycle traffic. `tick` returns `(Reply, addr)` pairs on the existing monotonic ticker; no global retry policy. A positive source-proven `tick_interval` selects that device's cadence (default 1 second); faster devices must not accelerate other models. Empty outer targets require explicit family `accept_empty_target`; `accept_any_target` requires original receiver proof that outer targets are ignored, retaining inner routing and key checks. |
| `encode_room(device) -> None` | Exact declared synthetic sensor policy for an evidenced field. Sensorless families intentionally expose no ambient LAN field. |
| `validate_state(state)` | Only real modeled writable fields, strict integer/range checks, no identity/private/derived overrides. |
| Optional `validate_topology(root)` | Runs after all links exist. Validate native identity relationships, shared aliases and ordering; do not infer whether a resolved MAC was explicitly configured. |
| `Profile` | Frozen metadata with exact ID/MIDs/HID/source hash, fresh per-device state, handler, identity width/`identity_suffix`, source-proved `identity_from_parent`, permitted parents, child count and evidenced `max_request_bytes`. Derive generated child IDs only after parent resolution; validate explicit identities without rewriting them. Check original UDP byte lengths, not compact JSON or unrelated buffers. |
| `Reply` | Selected key/codec, inner versus outer LF and optional source-proven destination IPv4 literal/port. Never derive a destination from an unchecked hostname. A `raw_payload` owns the complete byte frame and cannot also specify JSON/crypto/framing fields. Shared wire code encodes; the family supplies evidenced policy. Verify broadcast targets in isolation or at the transport boundary, not by sending onto a physical LAN; distinguish routing proof from delivery. |
| Optional `datagram_magic` / `handle_datagram_from(device, raw, addr)` | Binary UDP families declare their exact four-byte magic and receive bounded original bytes before JSON decoding. Return `Reply.raw_payload`; preserve per-peer replay state and isolate invalid packets per root. Prove the binary listener independently; cloud/TCP handlers do not authorize it. WB05APJ's pre-activated Joylink profile is not ordinary Gree JSON and its configured product value is not an emitted Gree MID. |
| Optional handler `source_port` | Declare this attribute only when an original listener gates sender ports; omit it for unrestricted peers. Enforce it before scan, plaintext, encrypted or raw dispatch. WB05DRA accepts only sender port 5001; a fixed reply destination alone does not enforce ingress. Check rejected-peer non-mutation and the admitted peer through the CLI. |
| Command failures | Validate malformed or bounds-violating batches before changing clocks or caches. Preserve source-proven partial writes and ACK suppression for otherwise valid sequential operations; do not impose global atomicity. Document safer rollback where native code would fault or corrupt memory, and verify the resulting state through fresh reads. |
| Multiple devices | No shared mutable appliance state. Children may intentionally share parent controls/key only when their actual topology establishes it. |

## Example 1: another MID in a proven family

`w04n.py` implements one evidenced N dialect for several actual runtime AC branches. Adding `10002`/`13000` was a tuple extension only after native scan/bind/status/command qualification; it did not require a handler copy. The reserved baseline `standard.py` implementation was not fabricated: CS532AE's original ROM crypto ABI remains unresolved, so the real existing family is used instead.

Relevant files: `gree_emulator/profiles/w04n.py`, private `https://github.com/cmroche/gree-research/blob/main/tests/fixtures/emulator/w04n-mids-native_research.json`, public `tests/fixtures/emulator/w04n-mid-10002.json`, and `docs/MIDS.md#emulator-contracts`. A runnable example from the repository root:

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

These examples use only synthetic identities. Historical N-model probing observed unsupported `BuzzerCtrl` in a public-client command batch and rejection while discovery/binding/polling worked; that is a source/client-version-qualified observation, not a permanent assertion about every current client/profile. Reassess the actual code-wide buzzer profile and complete namespace before integration. Use independent peer checks to establish emulator behavior and report any current consumer mismatch separately. No Home Assistant UI or physical-device compatibility claim follows from these examples.
