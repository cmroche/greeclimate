# Firmware temperature offsets

For valid ambient readings, **Celsius = network `TemSen` − client offset**. This client correction is separate from removing a bias inside the firmware. Reported firmware `version` remains metadata; its major number does not select the encoding.

The investigation covered 34 loose firmware files representing 29 distinct SHA-256 payloads. Three firmware members in the accompanying ZIP duplicated loose files; they did not add builds to this inventory.

## Evidence levels

- **Confirmed:** calibration and network conversion were established inside the inspected image.
- **Schema-supported:** the firmware forwards UART byte 46 unchanged. Offset 40 follows the independently measured [Gree UART temperature schema](https://github.com/bekmansurov/gree-hvac-protocol#byte-46-indoor-temperature), where `62 − 40 = 22°C`. Physical calibration was not independently established inside each such image.
- **Runtime-dependent:** one image selects different encodings using runtime configuration; no single metadata-only offset was established.
- **N/A:** the inspected status schema has no actual `TemSen` decoder. This does **not** mean offset zero.

Versions below use embedded/generated identities where recoverable, rather than trusting download filenames.

## Inspected builds

| Firmware code / identity | Module | Inspected version | Client offset / evidence |
| --- | --- | --- | --- |
| `362001000748` | CS532Z(LT) | 3.73 | 40, confirmed |
| `362001000748` | CS532Z(LT) | 3.75 (download labelled 3.74) | 40, confirmed |
| `362001000762` | CS532AE(LT) | 2.5 | 40, schema-supported |
| `362001000762` | CS532AE(LT) | 3.33 | 40, confirmed |
| `362001000835` | CS532AX(MTK) | 3 (download labelled 2) | 0, confirmed |
| `362001060200` | CS849A | 10 | 0, confirmed |
| `362001060297` | CS532AF(MTK) | 4 (download labelled 4.0) | 0, confirmed |
| `362001061383` | BL3332_JD | 18 | 0 or 40, runtime-dependent |
| `362001061665` | W05T | 2.07 | 40, schema-supported |
| `362001062107` | W04AC | 1.08 | 40, schema-supported |
| `362001063149` | W05CA | 1.39 | N/A |
| `362001063149` | W05CA | 1.40 | N/A |
| `362001063794` | CS532UZ | 1.02 | 40, schema-supported |
| `362001065736` (fetched under `362001064307`) | QCOM4004C | 3.76 | 40, schema-supported |
| `362001065232` | ESP32_C3F5 | 1.07 | N/A |
| `362001065279` | WB05RT13 | 1.45 | 40, schema-supported |
| `362001065280` | WB05RT11 | 1.44 | 40, schema-supported |
| `362001065634` | WB04BRT13 | 1.38 | N/A |
| `362001065735` | QCOM4004CF | 3.74 | 40, schema-supported |
| `362001065736` | QCOM4004C | 3.77 | 40, schema-supported |
| `362001066763` | W06A(P3) | 6.0 | N/A |
| `362001066763` | W06A(P3) | 6.04 | N/A |
| `362001067012` | W06A gateway | 20 | N/A |
| `362001067012` | W06A gateway | 30 | N/A |
| `362001067541` | WB05WR11 | 2.10 | 40, schema-supported |
| `362001068254` | 4MWB65VR | 2.11 | 40, schema-supported |
| `362001068254` | 4MWB65VR | 2.12 | 40, schema-supported |
| `36300000257` | CS532R | 3.4 (OTA version label) | N/A |
| `36300000257` | CS532R | 4.1 (OTA version label) | N/A |

## Trait selection

The numeric evidence above supplies 14 firmware-code-only defaults in `greeclimate/device_profile.py`. A complete, syntactically valid reported HID is required; a bare firmware code is not accepted. Module names, qualifiers, and literal versions do not constrain these production defaults, so uninspected versions and different module tokens under the same code receive the same offset. This deliberately generalizes the inspected evidence; it does not establish calibration for every version. The generic matcher still supports conjunctive module and literal-version criteria.

The mislabelled QCOM download does not justify a profile under `362001064307`. Debug/burn identifiers are not necessarily generated HIDs. API protocol-version fields and discovery versions are not substitutes for the reported firmware HID. No universal MID-to-offset mapping was established.

The three confirmed zero-offset builds perform `clamp(raw − 40, 0, 50)` before JSON serialization; their paired setters add 40 back. A UART value of 65 therefore arrives as `TemSen=25`. The client must not subtract 40 again.

### Runtime-dependent and unsupported schemas

BL3332_JD V18's getter at `0x0802d368` selects client offset 40 for persisted/detected `startcloud_id == 9` (GREE), otherwise 0. Below encoded 40 it returns zero; above 90 it clamps. No public MID/HID/version field identifying the active selector was established. This build deliberately uses automatic detection instead of a guessed fixed trait.

W05CA 1.39 returns generic zero for an unknown `TemSen` query, while 1.40 omits the unknown property. Neither response establishes a zero-degree sensor reading. Other N/A families expose different schemas, including `binStatus` and ATW/gateway-specific fields. This change does not implement those protocols or assign N/A builds a numeric trait. An initial zero remains unavailable until a zero-offset encoding is known.

## Automatic detection and precedence

The effective offset is the first permanently learned offset, otherwise the current firmware-code trait, otherwise the first ambiguous-sample guess. If none exists, ambient temperature is unavailable (`None`). Trait selection is not cached: before learning, a HID-only response can immediately change interpretation of a cached ambiguous reading.

Learning assumes indoor temperatures in the inclusive **−20°C…50°C** envelope. For a raw integer `r`, the candidates are `r` and `r − 40`. Only incoming `TemSen` samples supply evidence:

| Raw `TemSen` | Action before a permanent lock |
| --- | --- |
| −20…19, excluding zero | Learn offset 0 permanently |
| 20…50 | Keep the first guess: 0 below 40, otherwise 40 |
| 51…90 | Learn offset 40 permanently |
| Zero, noninteger, or outside −20…90 | Do not learn or change the guess |

The first ambiguous guess is retained even while a trait supplies the displayed offset. A later high-confidence sample overrides both the guess and any trait, regardless of metadata arrival order. Once learned, the offset never changes for that `Device` instance, including after contradictory samples, HID replacement, or reconnect. A newly constructed `Device` starts independently. Neither repeated ambiguous readings nor metadata changes confirm or reset a guess.

Missing, noninteger (including boolean), and out-of-union raw samples return `None`, never the target setpoint, without changing offset state. Zero provides no evidence: with an independently selected offset 0 it displays 0°C; with offset 40 or no selected offset it is unavailable. Partial packets preserve the cached sensor; explicit `TemSen=None` makes it unavailable. Local property mutations bypass learning.

The envelope is an inference assumption and a gross raw-value guard, not a decoded-temperature clamp. Learned0 followed by raw65 displays 65°C; learned40 followed by raw19 displays −21°C. Unit conversion follows offset correction; an unrepresentable Fahrenheit conversion returns `None` without changing the lock.

An extreme actual temperature can cause an incorrect first permanent lock. The envelope is not universal hardware calibration, and code-only defaults generalize beyond inspected builds. No manual reset, persistence, voting, or historical-range resolver is provided.

## Investigation provenance and limits

The recorded firmware investigation used bounded native ARM execution/replay with API-edge hooks and byte-matched Xtensa instruction replay. These checks traced acquisition, property getters, and network conversion; they were not full-device emulation or hardware calibration. Schema-supported results remain conditional on the attached mainboard using the documented UART encoding. The table records the inspected inventory snapshot, not every available firmware release.

The original W04N V7 image was not in this inventory. Related-build evidence and owner reports do not justify an unconditional W04N profile; that device continues to use detection. No firmware binaries, private captures, or temporary analysis files are required at runtime.
