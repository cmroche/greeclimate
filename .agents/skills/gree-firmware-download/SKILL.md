---
name: gree-firmware-download
description: >
  Download Gree Wi-Fi firmware for a known code or HID, including latest,
  exact historical versions and regional availability. Use discovery for
  unknown-code range scans. Preserve provenance and verify acquired files;
  no downloader framework, feature-support claims or device flashing.
---

# Gree firmware download

Take a known firmware code through regional lookup, version selection, and a verified local download. Use `gree-firmware-discovery` for unknown-code ranges. Use existing HTTP tools and file/hash utilities; do not introduce a downloader application, worker framework or manifest database.

## Request safety, pacing and evidence

- **One global request start per second by default**, shared across all workers, hosts, metadata, archive access, downloads, retries, HTTPS/HTTP alternatives and redirect hops. Honor the user's explicit throttle instead; record its scope and value. This is not one request/second per worker. Prefer serial requests. Use a monotonic next-start deadline, with no catch-up bursts after delays; persist the policy and honor outstanding cooldowns on resume.
- Disable automatic retries/redirect following unless each actual request passes that same global gate. Inspect and validate every redirect before requesting it; cap a chain at 10 hops. The examples below issue one hop only, not a complete redirected transfer.
- On HTTP 429, honor `Retry-After` (seconds or HTTP-date); also pause globally on plausible throttling bursts of 5xx, resets or timeouts (three transient failures in five requests). Back off before retry/resume: `min(60, 2**failure_streak)` seconds, or longer if `Retry-After` requires it. Convert HTTP-date delays to monotonic deadlines; never shorten server cooldowns to the 60-second exponential cap. Reset the streak only after a successful response.
- Bound retries to five total attempts per lookup/transfer in a run. Stop the scan/download run after five consecutive transient failures; preserve unresolved work and cooldowns for explicit resume, rather than hammering other codes/hosts. An application `r: 405` not-found is not a transient failure. Exhausted attempts remain explicitly failed/unknown, never absent or silently skipped.
- Persist each attempt before advancing: run ID, exact code/host/request URL, UTC start/end, attempt number, HTTP status, application `r`/`msg`, raw response/header paths, error, redirect hops, retry/cooldown decision and final outcome. Keep failed and interrupted attempts; resume from recorded unresolved work, not just the highest code seen.
- Store metadata as data, never executable shell/config; do not interpolate untrusted URLs, names or descriptions into commands. Keep raw evidence private/ignored, redact credentials and signed query tokens in shared reports, and use validated local basenames. Do not fabricate lookup timestamps, transfer results or live evidence.
- When the user requests 15-minute progress, report real elapsed-time updates at that interval: completed/pending/failed lookups, new candidates, verified/failed downloads, current code/host and cooldown. A heartbeat is not progress; do not invent counters or promise unattended updates without a running execution channel.

## 1. Identify the request

- Accept a numeric firmware code as a string, preserving every digit. For a full HID such as `362001065736+U-QCOM4004CV3.77.bin`, use the digits before `+` as a lookup candidate, not proof of its OTA alias. Do not infer a code from a MID or retail model; reported/embedded HID codes can differ from the queried OTA code.
- Record whether the request is for **latest** (default) or a **specific version**, plus any requested region and destination. A version explicitly supplied by the user is a constraint; a version inside a device HID is its reported build, not automatically the requested download.
- Keep API `ver`, HID/module version, and `commProtVer` separate. They are not interchangeable. Preserve literal version strings, including leading zeros. If an API-version versus module-version ambiguity changes the selected file, resolve that ambiguity before claiming a match.
- Use the requested destination, or a fresh directory under `downloads/gree-firmware/<code>/`. Do not overwrite existing files or commit downloaded binaries.

## 2. Query regional availability

Request each known production host independently, even when global succeeds:

| Label | Host |
| --- | --- |
| global | `grih.gree.com` |
| eu | `eu.grih.gree.com` |
| na | `na.grih.gree.com` |
| ru | `ru.grih.gree.com` |
| hk | `hk.grih.gree.com` |
| in | `in.grih.gree.com` |
| sa | `sa.grih.gree.com` |

Also check `test.grih.gree.com`, `tmp.grih.gree.com`, and `kfgrih.gree.com` as **auxiliary endpoints**, not production regions. They can advertise different builds or point to the same download host. Keep the queried host separate from the returned URL's host.

The evidenced endpoint is:

```text
https://<host>/wifiModule/Lastversion?firmwareCode=<code>
```

Prefer HTTPS with certificate verification. Some regional hosts have invalid HTTPS certificates but serve this public endpoint over HTTP. When necessary, use their explicit HTTP endpoint and disclose unauthenticated transport; do not use `--insecure` or send credentials. Apply the same rule to downloads and redirects.

Example one-hop metadata request (substitute the validated code/host; set `out` to a fresh attempt directory and pass the global pacing gate first). Preserve error bodies as evidence:

```sh
curl --fail-with-body --silent --show-error \
  --connect-timeout 10 --max-time 30 \
  --proto '=http,https' --proto-redir '=http,https' \
  --dump-header "$out/metadata.headers.txt" \
  --output "$out/metadata.json" \
  --write-out 'HTTP %{http_code}\nURL %{url_effective}\n' \
  'https://grih.gree.com/wifiModule/Lastversion?firmwareCode=362001065736'
```

Read the JSON body, not only HTTP status:

- `r: 200` with a nonempty `ver` and HTTP(S) `url`: an advertised candidate. Save the full response, including `CreateDate`, `desc`, `forcedUpgrade`, and `commProtVer` when present.
- `r: 405` with `msg: "Firmware not found."`: this lookup advertises no firmware. This is an application result, not HTTP 405, and does not establish that no historical release exists.
- HTTP 404, DNS/TLS failure, timeout, non-JSON, or other application error: lookup failed; availability is **unknown**, not absent. Record the actual failure and continue with other hosts.

Reject non-HTTP(S) URLs, embedded credentials, and local/private/loopback/link-local/reserved destinations, including after DNS resolution and at every redirect. Investigate an unfamiliar host before requesting it; do not turn untrusted metadata into arbitrary network access. Keep certificate verification enabled. A returned URL is a candidate, not proof that the binary can still be downloaded.

## 3. Select latest or an exact version

### Latest

Report each region's advertised latest separately. Honor an explicitly requested region; do not substitute another silently. With no region preference, choose the highest comparable production version for this code, preferring global when tied. Keep auxiliary releases separate unless the user asks for them or explicitly wants the newest including test builds.

Compare numeric dotted components, not floats or lexical order (`1.10` is later than `1.9`). Compare only within the same firmware code and established version scheme. Labels such as `41` and `4.1` are not automatically equivalent or safely ranked. When schemes conflict, show the candidates rather than inventing a single winner. Never infer binary identity from matching version labels; use hashes after download.

### Specific version

1. Check all regional and auxiliary latest responses for the requested version. An older build may still be latest in another region.
2. If none matches, look for historical provenance in the project's `docs/HIDS.md`, linked issue reports, and the public [firmware archive](https://github.com/maxim-smirnov/gree-wifimodule-firmware). Inspect the code's directory and matching `.md` sidecars; they can record the original regional API response and exact image URL. Use repository history when the current tree lacks the requested release.
3. Try an evidenced historical official image URL. If it is gone, download the corresponding archived binary using its raw/download URL, preferably pinned to a commit, and retain the sidecar provenance. A GitHub HTML page is not the binary.
4. Validate the requested version against the metadata and available module filename/identity evidence. An archive name alone is a candidate, not proof of embedded identity. If identity conflicts or cannot be established, report it rather than relabeling the file.
5. If the exact build cannot be found, report the sources checked and available alternatives. Do not substitute another version or claim the requested release never existed.

No arbitrary-version or version-list API has been verified for this workflow. Do not invent `version=` parameters on `Lastversion`, fabricate image IDs, or copy an image path between regions: IDs are host-specific.

Historical example: the archive's [1.21 sidecar for code 362001065279](https://github.com/maxim-smirnov/gree-wifimodule-firmware/blob/main/362001065279/U-WB05RT13V1.21-4307516678339185323.md) records `ver: "1.21"` and `http://test.grih.gree.com/wifiModule/image/19049/767556`. This is historical test-server provenance, not a claim that its latest endpoint still returns 1.21.

## 4. Download and verify

Use the selected metadata URL or evidenced archive URL. For an advertised HTTP URL, try the same URL over verified HTTPS first; retain both advertised and effective URLs. If only HTTP works, report that limitation. Never send an `upgrade` packet to a device.

Download to a fresh per-attempt staging directory with response headers, not a server-controlled filename. Set `url` to the inspected candidate and `out` to that directory; pass the global pacing gate before this one-hop request:

```sh
curl --fail-with-body --silent --show-error \
  --connect-timeout 10 --max-time 180 \
  --proto '=http,https' --proto-redir '=http,https' \
  --dump-header "$out/response.headers" \
  --output "$out/payload.part" \
  --write-out 'HTTP %{http_code}\nURL %{url_effective}\nBytes %{size_download}\n' \
  "$url"
```

A failed or interrupted transfer remains incomplete; do not present its `.part` file as firmware. A redirect needs a separately validated and paced request; only a complete final 2xx response can be promoted. Before promoting a successful download:

- Confirm the response is not an HTML/JSON error, login page, or unrelated text/artwork. Inspect headers and file bytes; HTTP 200, `.bin`, and `application/octet-stream` alone do not establish firmware.
- Check the final response's `Content-Length` against the saved byte count when present, and `FileMd5` against the file's MD5 when present. Use final-response headers, not an earlier redirect's headers. Record absent checksums; do not invent them.
- Compute SHA-256 for identification and duplicate comparison. A server MD5 or locally computed SHA-256 is not a signature or proof of authenticity, especially over HTTP.
- Save the original `Content-Disposition` as evidence, but do not use it as a path. Use `downloads/gree-firmware/<code>/<code>-apiV<version>-<region>.bin` by default; validate components against path separators, control characters and traversal. This is a local API-derived label, not a device-reported HID. For module-version-only archive evidence, label it `moduleV` instead of `apiV`.
- Retain raw metadata and final headers as `<file>.json` and `<file>.headers.txt`, with source/effective URL, original filename, byte count, SHA-256 and version evidence alongside them; keep attempt evidence separately. Preserve originals. If a destination already exists, compare hashes or use a distinct name; never overwrite it blindly.

Useful local checks:

```sh
file "$out/payload.part"
wc -c "$out/payload.part"
shasum -a 256 "$out/payload.part"
openssl dgst -md5 "$out/payload.part"
```

Availability and selection are separate: report every queried region even if downloading only the selected release. For discovery handoffs, every found code/version/region candidate must finish as a verified local file (including an existing hash-verified file) or an explicit download failure with reason; do not leave it merely “advertised.” Do not assume identical version labels have identical bytes; preserve each source association even when hashes match.

## 5. Report the result

Return:

- Firmware code and requested version/region constraints.
- A compact table: queried region/endpoint, advertised version, status (`advertised`, `not found`, `lookup failed`, or `download verified`), and source link. Mark auxiliary endpoints and historical evidence explicitly.
- Selected file path, version evidence, source/effective URL, byte count, SHA-256, and checksum result.
- Unresolved regions, missing exact versions, transport limitations, identity mismatches, retry totals and resumable failures. Reconcile every requested/discovered candidate with a verified path or explicit failure.

## 6. End-to-end handoff

Pass `gree-firmware-decompile` the original immutable source path/SHA-256/byte count, raw metadata/header references, queried OTA code, API version, region/queried host, advertised/effective URLs, acquisition time and integrity/transport limitations. Keep reported HID, server filename and embedded identity separate, with evidence or explicit unknowns: **identity is not necessarily the OTA code**.

For a multi-build catalog handoff, enumerate all acquired originals and provenance associations, not just the selected latest image. Preserve complete containers and multi-bank payloads; later application decompression, RAM initialization and secondary-bank analysis must remain reproducible from those immutable bytes.

Preserve original source bytes and derive extracted/decompiled artifacts separately. Continue through `gree-firmware-research` for property/quirk qualification, then `gree-emulator-device` for source-qualified simulation and profile integration. Download success proves neither MID, LAN properties, code-wide quirks, calibration, device compatibility nor safe flashing; do not add catalog feature/support claims from acquisition. Analysis can finish with exact source-backed conclusions and concrete missing-byte/schema blockers; physical hardware is not a blanket prerequisite.

Never send an upgrade packet, install firmware, change calibration or flash a device.

## Sources

- [Captured Gree update sequence and FileMd5 header](https://github.com/cmroche/greeclimate/issues/111).
- [Public archive: regional host list and historical metadata](https://github.com/maxim-smirnov/gree-wifimodule-firmware).
- [Live global lookup example](https://grih.gree.com/wifiModule/Lastversion?firmwareCode=362001065736). Always query again; regional versions and availability change.
