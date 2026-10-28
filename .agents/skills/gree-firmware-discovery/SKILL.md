---
name: gree-firmware-discovery
description: >
  Discover previously unknown Gree OTA firmware codes or HIDs in explicit
  numeric ranges using HIDS and existing downloads as a baseline. Use for
  resumable, globally throttled scans with per-attempt evidence and verified
  acquisition of every found firmware; never flash devices or infer features.
---

# Gree firmware discovery

Discover codes; let `gree-firmware-download` handle regional/version selection, historical provenance and binary verification. Read that skill first and inherit its URL, TLS, integrity, naming, no-overwrite and no-flashing safeguards. Use existing HTTP/file tools and simple evidence files, not a new downloader framework, runtime script/config, database or service.

## 1. Freeze scope and baseline

- Read `docs/HIDS.md` and inventory existing `downloads/gree-firmware/` files plus their metadata/headers before scanning. Record baseline paths/time and exact code strings, source references, API versions, reported/embedded HID evidence, existing paths and hashes. A filename alone is not verified identity or a verified download.
- Keep separate sets for documented OTA codes, reported/embedded HID codes, and existing download OTA codes. Their union is the **known-code baseline**, not proof that all entries have a working OTA lookup or a known HID. Do not confuse “unknown HID” with “unknown OTA code”; one OTA code can deliver a different embedded code or several builds.
- State whether the user wants unknown codes, unknown HIDs, refreshes of known codes, or all codes. Default unknown-code discovery queries codes absent from that union **and ambiguous entries lacking an established OTA association**. Only count a code as newly discovered if absent from the frozen union; label known-code/new-build and new-HID findings separately. For unknown-HID work, include known OTA codes whose embedded identity remains unknown; acquisition alone may leave that identity unknown until decompilation.
- Record each known code excluded by scope with its exact baseline evidence and skip reason. Ambiguous identity mappings are candidates to query or explicit unresolved items, never an excuse for an unrecorded hole. Existing files do not silently remove a requested code/version from work; verify them or record why they cannot satisfy it.
- Preserve every original build and regional/API association in the handoff, including older files for an already known code. Deduplicate bytes by hash only; extracted applications, RAM initializers and OTA banks are downstream views of an original, not additional discoveries or permission to discard it.
- Record exact range, host scope and throttle before starting. For range discovery, default to the global `grih.gree.com` endpoint only unless the user specifies regions; name that limit. `gree-firmware-download` handles its full regional/auxiliary availability checks for known-code acquisition. A global result is not worldwide absence.

### Exact `prefixxxxx` boundaries

Treat the prefix as a literal digit string and `xxxx` as **exactly four decimal suffix digits**. Enumerate inclusive suffix `0000` through `9999`, preserving zeros and the prefix unchanged: exactly 10,000 code positions before recorded exclusions. For example, `36200106xxxx` means `362001060000` through `362001069999`, not a larger range or a search around known codes. Code lengths vary; infer no universal width or prefix meaning. For explicit endpoints, retain their stated width and inclusive boundaries; do not coerce full codes to integers and lose zeros. Resolve an unspecified boundary from request/repo evidence before making requests; never guess broader scan scope.

## 2. Pace every actual request globally

Use the shared policy in `gree-firmware-download`, including downloads handed off during the scan:

- Default **one request start per second globally**, not per worker, region or code. Honor and record an explicit user throttle. All metadata, retries, redirects, HTTPS/HTTP alternatives, archive access and binary transfers consume the same gate; disable automatic redirects/retries that bypass it. Serial execution is simplest.
- Use monotonic next-start deadlines and no catch-up bursts. Persist throttle/cooldown state for resume; after restart honor the remaining server cooldown and wait at least one interval before a new start.
- HTTP 429 requires a global pause honoring `Retry-After` (seconds or HTTP-date). Also pause on plausible burst throttling: three transient 5xx/reset/timeout failures in five requests. Before retry/resume apply exponential delay `min(60, 2**failure_streak)` seconds, taking the longer server delay when present. Convert date delays to monotonic deadlines; reset the streak only on a successful response.
- Bound each lookup/transfer to five total attempts per run. Stop the run after five consecutive transient failures; preserve pending work and cooldowns for explicit resume, not immediate counter resets or traffic against other codes/hosts. No hammering, infinite retry or silent holes.

## 3. Record each attempt and resume exactly

Use the evidenced endpoint, with validated digit-only code:

```text
https://<host>/wifiModule/Lastversion?firmwareCode=<code>
```

Apply the download skill's one-hop request examples and inspect every redirect before following it. Never bypass certificate verification; disclose any necessary explicit HTTP fallback. Reject untrusted schemes/credentials and local/private destinations before each request, including resolved addresses and redirects. Do not execute metadata or use server filenames as paths.

Persist an append-only attempt record and raw metadata/headers **before advancing**. Minimal record: run ID, frozen baseline/scope reference, exact code/host/URL, UTC start/end, attempt number, HTTP status, application `r`/`msg`, raw evidence paths, error, redirect chain, retry/backoff/cooldown decision and outcome. Keep raw private evidence intact; redact secrets/signed query tokens from shared reports. Save progress durably; mark interrupted/in-flight attempts unresolved on resume.

| Observation | Outcome and required action |
| --- | --- |
| Successful HTTP response, JSON `r: 200`, nonempty `ver`, validated HTTP(S) `url` | `found`; preserve full response including optional `CreateDate`, `desc`, `forcedUpgrade`, `commProtVer`; queue acquisition, not a support claim. |
| Successful HTTP response, JSON `r: 405`, `msg: "Firmware not found."` | `not_found` for this code/host/time only; not HTTP 405, not proof against historical or other-region releases. |
| HTTP 429/5xx, DNS/TLS/reset/timeout, HTTP 404/405, non-JSON, malformed/incomplete candidate or any other app error | `lookup_failed`, availability unknown; record actual failure and apply bounded retries where transient. Never translate it to not-found. |
| Known code excluded by declared scope | `skipped_known` with baseline evidence/reason, not a successful lookup. |
| Not attempted, interrupted, exhausted retries or unsafe URL | Explicit `pending`/`lookup_failed`/`download_failed` with reason; never silently advance past it. |

Track lookup and acquisition outcomes separately. On resume reconcile **every code/host position** with a completed outcome, explicit known-code exclusion or pending/failed work; a highest-code cursor alone loses holes. Preserve previous attempts and retry budgets/cooldowns. Do not claim range completion until there are no unexplained positions; disclose unresolved failures even when every position is accounted for.

## 4. Acquire every found firmware

Hand each found code/version/region/URL candidate, raw metadata and attempt reference to `gree-firmware-download` under the same global gate. Every found candidate must end as **verified local firmware** or **explicit download failure** with reason/evidence; merely listing advertised versions is incomplete. A stopped run leaves a named pending acquisition queue and must not be reported complete.

Use the established layout:

```text
downloads/gree-firmware/<code>/<code>-apiV<version>-<region>.bin
```

Retain `<file>.json`, `<file>.headers.txt`, source/effective URL, original filename, API/module version evidence, bytes, SHA-256 and checksum/transport result. Validate local components, preserve zeros and literal versions, and use `moduleV` only for module-version-only evidence. Never overwrite originals. Reuse an existing file only after integrity/hash verification and source association; identical labels do not prove identical bytes. Identical hashes may share bytes, but preserve every found source association. Keep incomplete `.part` payloads separate from verified files.

## 5. Report and hand off

- Report frozen baseline counts, exact inclusive bounds and host scope, actual throttle, elapsed time, completed lookup positions, not-found, failed/pending, evidence-backed exclusions, newly discovered codes, known-code/new-build and new-HID findings. Reconcile these with the requested scope; provide evidence/resume paths and exact unresolved positions.
- Include each found candidate's queried OTA code, API version, region/host, source link, verified file/bytes/SHA-256/checksum result or explicit acquisition failure. No live result, counter, hash or timestamp may be fabricated.
- When the user asks for 15-minute progress, give real elapsed-time updates every 15 minutes with those counts, current code/host, verified/failed downloads and cooldowns. Do not substitute “still running” for measured progress or promise unattended updates without an execution channel.
- Hand off original immutable source bytes and acquisition provenance to `gree-firmware-decompile`, then source-backed property/quirk analysis to `gree-firmware-research`, then qualified profile/emulator work to `gree-emulator-device`. Keep queried OTA code, server filename, reported HID, embedded HID and MID as separate evidence-bearing identities or explicit unknowns; **identity is not necessarily OTA code**. Preserve originals and hashes when extracting/decompiling.
- Acquisition cannot establish device compatibility, catalog features, emitted MIDs, LAN properties, code-wide quirks, physical calibration or full firmware emulation. Make no catalog/support claims from a download. Hardware is not required to finish reachable source analysis: name exact missing bytes/schema/initialization rather than a blanket hardware blocker. Never flash, send upgrade packets or modify calibration.
