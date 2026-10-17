# Multi-unit gateway protocol notes

Sources: [greeclimate PR #148][pr148], its [hardware log][hardware], [issue #101][issue101], and the linked [HACS integration PR #508][hacs508]. Reviewed 2026-10-14 at PR head [`3fec6dd79a056e8173a485ac3cc9fe66b93f3517`][revision]. PR #148 was still open and unmerged: the API and lifecycle behavior below describe that proposal, not a guarantee about an installed greeclimate release.

Device-category identifiers are cataloged in [MIDS.md](MIDS.md); firmware identifiers and the anonymized HID reports are in [HIDS.md](HIDS.md).

## Discovery, identity, and routing

- A scan response with `subCnt > 0` identifies a gateway fronting indoor units; the proposal records this as `DeviceInfo.sub_count`. It is the advertised unit count, not proof that one enumeration response contains every unit.
- The gateway has its own discovery MID and HID. Each `subList` entry has an indoor-unit `mac` identifier and may supply a `mid`; neither the gateway MID nor its HID should be assigned to every child.
- Indoor identifiers are not necessarily ordinary six-byte Ethernet MAC addresses: the W06 captures contain 14 hexadecimal characters. Preserve the complete identifier rather than truncating it or treating it as another network interface.
- The proposal binds to the gateway once; `Device.get_sub_devices()` returns child `DeviceInfo` objects carrying `gateway_key` and `gateway_cipher`. Children use the gateway's IP/UDP port, normally `7000`, without a separate binding handshake; binding a child with the cached session must still open its own transport.
- [Issue #101][issue101] reports successful indoor-unit status, power, and target-temperature requests with the outer packet addressed to the gateway and the indoor identifier in `pack.mac`. The [W06 notes][w06] also show command payloads using `sub` to target an indoor unit. These are observed variants, not proof that one target field works on every module.
- The HACS integration's `subMAC@gatewayMAC` notation is a compound software identifier for routing, not a literal MAC to send unchanged in a protocol field.

## Enumeration forms in PR #148

These forms are present in the [reviewed revision][revision] and the [WB05BR capture][hardware]. The common outer fields are `cid="app"`, `uid=0`, and `tcid=GW`, where `GW` below is a placeholder for the gateway identifier. The `pack` column shows JSON before encryption, not the on-wire Base64 ciphertext.

| Form | Outer `t`, `i` | Decrypted request `pack` | Request encryption |
| --- | --- | --- | --- |
| Plain `subList` | `"subList"`, `0` | No `pack` | None |
| Bound-key `subList` | `"pack"`, `0` | `{"t":"subList","mac":"GW","i":0}` | Gateway's bound key/cipher |
| Generic-key `subList` | `"subList"`, `1` | `{"mac":"GW","i":1}` | Generic key with the gateway's cipher variant |
| Bound-key `subDev` | `"pack"`, `0` | `{"t":"subDev","mac":"GW","cid":"GW","i":0}` | Gateway's bound key/cipher |

The plain query's request is unencrypted, but its response in the WB05BR trace is an encrypted `pack`. The generic-key exchange uses the generic key for its reply; it must not replace the bound gateway cipher used for subsequent state/control traffic. `subDev` also returns a response named `subList`.

Collect every successful form and merge by the complete indoor identifier, rather than stopping at the first success. The proposal normalizes case and colon/dash separators for deduplication. A timed-out form must not erase successful results from another form. Each form waits at most two seconds per attempt and retries once on timeout; if no form answers, the proposal raises `DeviceTimeoutError`. An answered empty list is distinct from no response.

Treat `subCnt` and response `c` as declared counts, not `len(list)`. The WB05BR generic-key reply declares `c=4` but contains only three entries. Do not invent entries to make a count match.

The parser proposed in PR #148 resolves a response type from decrypted `pack.t`, falling back to outer `t`, and normalizes case. Actual binding replies include `bindOk`, not only `bindok`.

## Hardware evidence and limits

These are reported observations from the cited owners, not tests run for this documentation change. “Not reported” means that the source does not supply a result for that form.

| Gateway / source | Plain `subList` | Bound-key `subList` | Generic-key `subList` | `subDev` | Distinct indoor units | Verification scope |
| --- | --- | --- | --- | --- | --- | --- |
| GR-Gcloud / WB05BR ([PR #148 log][hardware]) | 4 | 4 | 3 | 4 | 4 | Library port; CipherV1 |
| Six-unit GR-Gcloud ([owner confirmation][six-unit]) | Not reported | 5 | 5 | Not reported | 6 | HACS integration; complementary subsets |
| Two W06A gateways, discovery `ver="V1.1.0.0"` ([captures][w06], [follow-up][w06-confirmation]) | Not reported | No reply | No reply | 3 per gateway | 3 per gateway | HACS integration; `subDev` recovered enumeration |

The older W06 packet notes use a nonzero outer `uid` for `subDev`; PR #148 instead uses `uid=0`, which its WB05BR log confirms. The author explicitly says the library port has not yet been tested on the other owners' gateways or on a GCM gateway. HACS success is therefore not confirmation that the port's exact packet forms work on W06 hardware. A `subList` timeout alone is not evidence that a gateway lacks local enumeration.

The latest PR #148 capture covers discovery, binding, and the automatic gateway status read; no control commands were sent, and it does not show individual indoor-unit status reads. Separately, the author reports that a custom copy of the official integration on Home Assistant 2026.10.1 eventually showed four indoor units and a standalone AC with status. The standalone appeared on a later periodic scan and bound with CipherV2; that does not validate a GCM gateway.

## State and lifecycle observations

- In the WB05BR gateway-shell status response, every requested AC property is `""` except `hid`. An empty string is not a numeric zero or a usable climate reading; the gateway shell should not be confused with an indoor unit.
- The proposal accepts a present `SetTem` when the optional `TemRec` half-degree rounding bit is missing, `None`, or `""`, treating the absent bit as zero. A missing/empty setpoint remains unknown. It also avoids numeric temperature operations on the gateway's empty readings.
- Proposed discovery hides gateway shells by default (`include_gateways=False`). A nonzero `scan(wait_for=...)` waits for pending gateway enumeration before returning, so it is not a strict total-duration limit. With zero wait, listeners receive later discoveries. Concurrent scans are serialized, and the latest scan's gateway-inclusion policy remains active for late responses.
- Protocol response handlers must be per instance: a shared class-level registry cross-dispatches gateway, child, and standalone callbacks. Cached-key binding requires a cipher and a transport; the proposal rejects a missing cipher before opening a socket. Concurrent enumeration on one gateway is serialized.

The linked HACS work also addresses integration-level behavior: [PR #508][hacs508] holds commanded UI state for up to eight seconds while gateway reads catch up, schedules a refresh after about two seconds, and hides unsupported switches only after a successful initial sync. [PR #454][device-info] gives each indoor unit separate Home Assistant device identity and area assignment. These are separate integration changes, not additional behavior promised by the greeclimate library proposal.

Published captures can contain binding keys and private network identifiers. These notes deliberately omit them; scrub keys, encrypted payloads, IPs, and device identifiers before sharing new logs.

[pr148]: https://github.com/cmroche/greeclimate/pull/148
[revision]: https://github.com/meirlo/greeclimate/commit/3fec6dd79a056e8173a485ac3cc9fe66b93f3517
[hardware]: https://github.com/cmroche/greeclimate/pull/148#issuecomment-6173155943
[issue101]: https://github.com/cmroche/greeclimate/issues/101
[hacs508]: https://github.com/RobHofmann/HomeAssistant-GreeClimateComponent/pull/508
[w06]: https://github.com/RobHofmann/HomeAssistant-GreeClimateComponent/pull/508#issuecomment-5795667844
[w06-confirmation]: https://github.com/RobHofmann/HomeAssistant-GreeClimateComponent/pull/508#issuecomment-5796136621
[six-unit]: https://github.com/RobHofmann/HomeAssistant-GreeClimateComponent/pull/508#issuecomment-5795708129
[device-info]: https://github.com/RobHofmann/HomeAssistant-GreeClimateComponent/pull/454
