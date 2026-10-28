---
name: gree-firmware-decompile
description: Discover and qualify Gree firmware executables, mappings, ISA decoders and bounded decompilation evidence without confusing C exports with verified LAN behavior.
---

# Qualify firmware executables

Use for extracting, mapping, disassembling or decompiling downloaded firmware, or qualifying a missing ISA. Pipeline: [discovery](../gree-firmware-discovery/SKILL.md) → [download](../gree-firmware-download/SKILL.md) → **decompile** → [research](../gree-firmware-research/SKILL.md) → [emulator](../gree-emulator-device/SKILL.md). Acquisition establishes provenance, not features; decompilation establishes bounded code evidence, not a working appliance.

Read repository instructions and the exact-source research before editing. Private evidence lives in sibling `../gree-research/firmware-capabilities/research/`; consult `SessionScan-verification.json`, `DecoderNext-verification.json` and the source-specific artifacts they reference. Those reports are historical evidence with stated boundaries, not current acceptance results. Derive the requested source-file set from its current inventory; do not freeze historical counts into completion claims. When working on the session assessment, use `SessionQuirks/inventory.json` and the assigned contract/directory.

For catalog-wide work, start with private `CatalogQuirks/Inventory/inventory.json` and its assessment, then follow exact source rows and owning group artifacts. `CatalogQuirks/source-hashes.json` is provenance evidence, not decoder or semantic acceptance.

## Scope and preservation

- Record each source file separately, including regional/API/build variants sharing an OTA code. Separate OTA code/version/filename, embedded identity and actually reported HID/MID.
- Inventory every executable/member/bank within each original before declaring source coverage. Repeated runtime addresses can belong to independent OTA banks; do not deduplicate their RAM initializers by VMA or mistake a second bank for a load-address alias.
- Reuse an existing exact-source project/export only after matching original and extracted hashes, mapping, decoder version and qualifications. A similar filename, family or MID is insufficient. Explain any invalidated evidence.
- For Ghidra headless use a canonical absolute project directory and verify actual membership of the matching `.gpr` file and `.rep` directory; do not guess a mirrored project name/path.
- Keep vendor originals and existing projects immutable. Extract into a new ignored research directory; use a distinct project name for corrected mappings or processors. Preserve uncommitted public/private integration and unrelated work. Do not flash devices.
- Use the public repository root `venv/` for Python tooling; do not create nested environments. Decoder, disassembler, native execution and decompiler dependencies are research-only, never emulator/client runtime dependencies. Record interpreter/tool versions and executable paths.
- Research artifacts belong in the assigned private directory. Do not copy vendor binaries, bulk decompiled code, secrets or private captures into public fixtures. Do not edit generated `CHANGELOG.md`.

## Procedure

1. **Discover the actual content.** Inspect file signatures, headers, segment tables, compression/encryption/container structure, vectors and embedded files before choosing a CPU. A `.bin` may be a container, resource or non-executable payload. Document exact extraction operations and hashes of original, intermediate and executable bytes. Missing container decoding is a concrete blocker, not permission to guess an ISA.
   For compressed Realtek applications, identify and decompress the actual application stream and map its matching initialized RAM bytes as well as code. Keep each bank's code/initializer pair independent; a flat import or zero-filled RAM can manufacture missing callbacks, HID values and keys.
2. **Establish ISA and mapping.** Corroborate architecture, endian mode, instruction width/variants, entry points and address spaces using independent instruction evidence and control flow. Export a segment map: original offset, extracted offset, file size, memory size, permissions, load address, runtime address and provenance. Distinguish relocation/copy destinations, zero-initialized regions, unavailable ROM and overlays.
3. **Choose one canonical runtime view.** Import executable bytes at their actual runtime addresses. A load-image/LMA alias is not an additional executable function namespace. Record aliases explicitly and reject exported functions/edges outside canonical executable ranges. Rebuild in a new project if an old export included such aliases; retain the old export only as superseded evidence.
4. **Qualify the decoder before using its C.** Prefer an existing supported processor. For an unsupported/vendor ISA, isolate the language/processor extension and scripts in the research project; never modify a shared installed processor or shared RISC-V definitions. Independently qualify original-byte instruction spans/lengths, operands, signed immediates, branches, register widths, flags, memory effects and relevant p-code. Include positive execution vectors and negative decoding vectors. Unknown encodings must fail closed, not decode as a convenient instruction/no-op. Restrict inferred encodings to the actually qualified forms; label inferred slot order or semantics explicitly.
5. **Export rooted code and qualifications.** Preserve instructions with bytes/addresses, function entries/ranges, decompiled C, callgraph, segments and machine-readable per-function evidence. Record roots and discovery method, selected versus heuristic functions, decompiler warnings and failures, unresolved direct/indirect callees, ROM dependencies and transitive qualification. A successful C export or zero decompiler failures is not verified function coverage or complete firmware semantics. Separate raw-byte coverage, decoded-instruction coverage, rooted-function coverage and independently exercised behavior.
   Root actual registered callbacks, their constructor tables and callers; arbitrary `BL` targets and heuristic roots are leads, not proof of dispatch. Check output files, requested function entries, per-function errors and logs even when Ghidra exits 0; `MISSING_FUNCTION`, an empty export or script error is a failed export, not absent firmware behavior.
   Byte-correct rooted exports can still omit reachable switch cases or retry paths. Follow jump tables and raw mapped instructions before using missing C/listing entries as negative MID, initializer or operation evidence; retain any omitted span and its corrected roots.
6. **Bound executable claims.** Prefer execution of unchanged original instructions. Declare JSON/libc/allocator/ROM/I/O primitive substitutions and their exact call sites/ABI; do not replace the function behavior being claimed. Assert exact source hashes and instruction bytes before replay. Test signedness/width, boundaries, register/stack restoration, relevant control flow and literal independent outputs. A byte-asserted instruction translation is a translation, not native execution; a replacement AES primitive is not hardware AES proof.
   Old blanket `BL` skipping, forced stores or substituted callback results do not qualify original semantics. Preserve them as invalidated evidence and replay unchanged business instructions with corrected primitive adapters.
   Select ISA mode and CPU model when creating the execution engine, before any register/memory access. Qualify primitive adapters against the original binary ABI, including residual return-register behavior when a caller inspects a nominally C-void JSON helper. Match the actual cJSON version's ownership, reference and list semantics. Attribute decode/tool configuration failures or adapter errors to the harness, not to native firmware faults.
   Scope memory hooks to necessary ranges and verify conditional execution is unchanged; instrumentation-induced state corruption is a harness failure, not a native fault. For evidenced Cortex-M4 targets, select Thumb/M-class and M4 at engine construction, before mapping memory; a generic ARM default is not equivalent. Avoid broad data hooks that perturb Thumb ITSTATE; prefer final-memory inspection. Preserve the failing trace before correcting the harness and replay all affected consumers.
7. **Stop precisely at unavailable boundaries.** Identify missing ROM address ranges, save/restore ABI, reset/CSR semantics, initial registers/cache, memory layout or peripheral behavior. Keep unavailable memory unavailable: do not initialize it to invented useful values. Preserve original fault, PC, instruction and trace as the qualifier even if a separately labeled bounded model can proceed. No fake success, fabricated full boot, or blanket “needs hardware” excuse for source-reachable code.
   Before reporting missing ROM/crypto bytes or ABI, inspect all local SDKs, symbol/object archives and contained/member banks for the exact target implementation and call signature. An address in another supplied bank is not missing ROM; a similar SDK name or wrapper does not establish cipher mode, hardware selector enum or binary ABI.
   Resolve standard-library and peripheral leaves before labeling them business logic: `strncpy`'s small count is not an event ID, and an ignored return does not make an RTIM hardware call a mutex. Pin symbol version, caller registers and binary ABI; label a virtual peripheral backend separately.
8. **Hand off semantic research.** Link the canonical executable, source hashes, qualified functions and blockers to the research skill. Decoder correctness does not establish MID emission, socket dispatch, crypto framing, property support or appliance physics. Finish reachable functions instead of stopping all analysis at an unrelated reset/peripheral boundary.

## Evidence contract

Keep a source-specific manifest using existing research conventions. It must identify:

- source/provenance, original/extracted SHA-256, extraction recipe, embedded identity and exact toolchain;
- canonical segment/runtime map and explicitly non-executable or superseded aliases;
- processor/language identity, decoder provenance, qualified encodings, independent oracle/vectors and unsupported rejection behavior;
- instruction/function/callgraph/C export paths plus per-function qualification and dependency closure;
- checks as `{command, purpose, proves, boundaries}`, with observed result/artifact only when actually executed;
- unresolved functions/operations and exact missing bytes, ISA semantics, ABI or initialization, sources searched and next actionable evidence;
- downstream research targets, without promoting them to client quirks, MID families or emulator support.

`DecoderNext-verification.json` illustrates why qualifications matter: its TLCS rooted exports retain chip/peripheral and inferred-signature limits; its Hi3861 canonical exports retain ROM/save-restore and inferred HCC transfer-order limits. Follow referenced current exports rather than resurrecting superseded load-address exports. Do not inherit historical pass counts as new proof.

## Completion and execution authority

A decompilation deliverable is complete when every requested source has either reproducible canonical exports with explicit per-function qualifications or an evidence-backed blocker, and all source-reachable work is finished. “Blocked” must name the operation and exact missing prerequisite; failed tooling alone is not an irreducible blocker.

Follow the assignment's execution policy. In an edit-only phase, author the reproducible probes/decoder checks and exact runnable commands but execute no probes, tests, builds, lint or formatters; hand them to the integration owner. When checks are authorized, that owner runs them after edits settle and records actual results. Do not label authored/unrun checks as passing.

Return changed paths, source-by-source qualification, export/evidence paths, exact commands and whether run, boundaries and downstream implications. Never claim full-firmware boot, LAN support, hardware verification or complete function semantics from decompiler output alone.
