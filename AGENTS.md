# Guide for AI maintainers

This is the shared working policy for every agent contributing to xboxone-native. `CLAUDE.md` points here rather than maintaining a second policy. Read the request, `STATUS.md` and the relevant part of `docs/NEXT-TASK.md`; consult `docs/M0.md` for architecture rationale and affected subsystem or `docs/M*-STATUS.md` reports for evidence. Verify historical statements against the actual revision and implementation.

The maintainer selected [ps2-native's maintainer guide](https://github.com/fabegalo/ps2-native/blob/557a805d437b86367201d5edfb755b0ec0e96915/AGENTS.md) as the workflow and organization reference. This guide adapts its applicable practices while retaining Xbox One contracts. PS2 BIOS, R5900/VU semantics, GS rendering, game-specific addresses and static AOT policies are not xboxone-native contracts; neither are x360-native's PowerPC/ReXGlue/XAM implementations.

## Ponytail workflow

For coding tasks, use the [Ponytail skill](https://github.com/DietrichGebert/ponytail), `skills/ponytail/SKILL.md`, in `full` mode when available. Otherwise apply the same essentials: trace the affected implementation and callers, reuse existing helpers, and complete the smallest change that solves the requested problem. Keep investigation and output focused. Do not add dependencies or speculative frameworks just to follow a workflow, or claim to have run an unavailable skill.

Implement, run the relevant checks, correct failures, and validate the affected user path. Preserve error handling, accessibility and required correctness checks; saving tokens is not a reason to omit them. Report checks actually performed and remaining limitations, not unmeasured productivity claims. A new blocker changes the next diagnostic step; it is not by itself a reason to end the task with another plan when independent authorized work within scope remains possible.

## What the system is

xboxone-native is a **generic Xbox One compatibility project centered on the original SystemOS dashboard**, not a single-game port or a replacement launcher. The product goal is original dashboard -> library -> game -> Guide/dashboard, including local profiles, input, sound and persistent storage. The management frontend imports, prepares and diagnoses content; it must not fabricate the dashboard, Guide, sign-in or settings screens.

Prefer direct execution of original x86-64 code on compatible hosts, with explicit compatibility contracts for services and graphics. Matching the instruction set does not make Xbox binaries ordinary Windows applications. HostOS, SystemOS, GameOS/ERA and GameCore remain distinct environments. Win32 process creation, packaged desktop activation, UWP and Xbox WinRT/OneCore activation are not interchangeable proofs. Use native, VM or hybrid boundaries only as justified by the component's observed dependencies; do not build a hypervisor or another PE loader speculatively.

One shared C++ core and platform adapters serve the planned Windows x64/ARM64, Linux x64/ARM64 and macOS Intel/Apple Silicon targets. Windows x64 is the initial native execution target; Steam Deck follows Linux x64. Build support is not runtime certification. Identify necessary ARM64 instruction translation honestly. Do not impose a whole-program AOT recompiler, JIT or interpreter on code the host can execute directly, or replace this runtime with another engine without a separate maintainer decision.

| Area | Existing ownership |
| --- | --- |
| PE/XVD inspection and dependency metadata | `src/inspection.cpp`, `include/xboxone_native/inspection.h` |
| Inventory, hashes and path checks | `src/inventory.cpp`, `src/sha256.h`, `include/xboxone_native/inventory.h` |
| OSU study and version-bound preflight | `tools/study_update_zip.py`, `tools/systemos_preflight.py` |
| Sessions, explicit dependency bindings and native supervision | `src/bootstrap.cpp`, `include/xboxone_native/bootstrap.h` |
| AppModel manifests and Windows activation | `src/appmodel.cpp`, `src/appmodel_manifest.cpp`, `src/appmodel_activation.cpp`, `include/xboxone_native/appmodel.h` |
| CLI and build integration | `src/main.cpp`, `src/bootstrap_main.cpp`, `CMakeLists.txt`, `cmake/SystemOS.cmake` |
| Tests and evidence | `tests/`, `.github/workflows/`, `STATUS.md`, existing reports under `docs/` |
| User content and generated output | original input locations outside tracked source; ignored `build/` and `build-*/` outputs |

Check concurrent presentation/frontend work in the actual checkout before changing integration; do not invent paths or duplicate an uncommitted implementation. Keep title/revision-specific bindings in validated profiles, not shared runtime branches. Original dashboard versions are progressive targets. Xbox fidelity and Native enhancement are renderer directions, not proof of implemented backends.

## Performance target and acceptance

**Performance-first, correctness-preserving** is permanent policy. Target original-speed, responsive dashboard and gameplay with working input and sound on each explicitly validated host tier. Preserve original logic/video timing; do not force a 30 FPS title to 60 simulation updates or call repeated presentation of an old frame faster guest execution. Higher resolution, HDR or unlocked presentation in Native mode must preserve graphics, physics and timing. These are acceptance targets, not claims that current builds meet them.

Use the executable, build configuration, content/profile, activation path, scene and inputs the maintainer actually runs. Verify effective settings, backend and fallback. A backend name, activation request, CI pass or synthetic speedup is not a faster playable session. Parity with Azimuth or WinDurango requires comparable measured workloads.

Measure before/after on the same machine/settings. Separate import, verification, preparation, launch, guest progress and host presentation. Record pacing, stalls, latency, audio starvation, memory and storage as relevant. Do not invent universal guest-frame counters or turn game addresses into runtime rules. Keep optional hashes/timers outside timing windows; profile separately, preferably sampling Release with matching symbols. Re-profile after structural changes.

Select the next optimization from the current bottleneck. Keep reference/slow paths for differential tests where they exist. Production paths should not carry optional traces, dispatch history or intrusive profiling when diagnostics are disabled. Required validation may be specialized, cached or moved only with correct invalidation and equivalent observable behavior; do not remove identity, authorization or isolation checks to manufacture a gain. Never skip original effects, synchronization, audio or graphics.

Validate the affected original interface or gameplay and sound before declaring a functional build or hardware tier. Synthetic tests, replay and a commercial session each prove only their own scope. If the user's session did not improve, do not describe an isolated benchmark as delivery of that performance goal. Retain samples and explain inconclusive or negative results.

## Contracts to preserve

- **Content identity and version isolation:** bind OSUs, SystemOS/GameOS modules, packages, resources and caches to the actual revision/profile, provenance and SHA-256. No fallback by basename, shared exports/ordinals, WinRT class or another profile's API Set mapping. Shared members do not make archives interchangeable. Raw revisions, hashes and CRC are not publisher authentication or proof of a readable payload. Profile exclusion is not deletion or permission to repackage originals.
- **Original behavior:** retain original system components, service/API semantics, errors, memory and synchronization behavior, clocks, graphics, physics, input, audio, profiles and saves. Missing behavior produces a useful failure, never fake success, an invented API result or a silently ignored draw. Distinguish established behavior, a selected hypothesis and unverified behavior. Do not simulate Xbox Live as connected; prioritize offline behavior with explicit network limits.
- **Activation and execution identity:** retain explicit bindings, version/hash checks and supported activation models. Exports, forwarders and parsed manifests do not authorize execution or establish ABI compatibility. No silent Win32 fallback for an AppModel/Xbox failure. Distinguish identified, loaded, initialized, rendering, interactive, gameplay, playable and fully functional. A PID, exit 0, declared `original` origin or desktop test does not prove SystemOS initialization.
- **One logical console state:** session lifecycle, CPU/GPU resources, local users and storage must agree on the same contracts. Host handles and caches are not another console state and must not leak across sessions or restores. Frame transport needs ownership, lifetime and synchronization; a pointer in a child process is not a host buffer. Only observed execution of version-matched original code/resources, with identity, logs and an authorized capture, can establish the first authentic frame.
- **Launcher-to-runtime wiring:** every exposed setting needs a real consumer. Verify selected executable/component, profile, activation model, renderer and fallback reasons. Preserve pause/stop, focus-loss input release, controller reconnect, shutdown and return-to-dashboard behavior where implemented; do not declare these complete from a window opening. Reuse the existing presentation boundary, not a second renderer or mock shell.
- **User data and paths:** keep games, OSUs and firmware read-only and in place; preserve saves, profiles, settings and valid state. Destructive replacement needs appropriate confirmation and recoverable backup. Use shared Unicode/long-path I/O and retain traversal, symlink/reparse-point and identity checks. No hard-coded short-folder, Registry or administrator workaround for deep paths. Avoid duplicate content/caches; hardlinks must preserve integrity and isolation.
- **Host side effects:** package registration, certificates, policies, installations and privileged operations need explicit authorization. Keep AppModel deployment tests in the authorized disposable environment and verify cleanup; do not register test packages on the user's installation as a fallback. A Job Object or bounded process is not a security sandbox. Do not fetch or execute scripts embedded in user content.

## How to change things

Inspect `git status`, the current branch/head, relevant callers, existing helpers and tests before editing. Preserve concurrent work; do not reset, clean, overwrite or force-push somebody else's changes. Keep each implementation change focused and close the requested user-facing path before starting another milestone.

Reuse existing inspection, inventory, bootstrap, AppModel, CLI and presentation interfaces. Do not build another parser framework, profiler, launcher, renderer abstraction or runtime to avoid integration. Consult pinned primary references and licenses. Xbox One Research, Windows documentation and WinDurango inform different contracts; desktop behavior or a game workaround is not automatically Xbox behavior. x360-native and ps2-native are engineering references, not interchangeable console semantics.

Respect stop requests and permissions. Computer Use requires explicit authorization; visual system tests and long dashboard/game sessions require need and prior authorization. Do not repeatedly request permission for already-authorized scoped checks. Supervise bounded runs and clean up only task-owned processes. When permission or original input is unavailable, stop that operation, state the limit and complete independent authorized work. Do not fabricate tests, leave runs unattended or endlessly repeat ineffective OSU hashing/research.

## How to test

1. Build the affected targets in the existing compiler environment. Inspect effective Release flags and the build's source root; do not benchmark a stale, Debug or accidentally under-optimized executable. If the build fails, old binaries cannot validate the change.
2. Run focused regressions for the changed contract, then the relevant integration test through the production path. Preserve independent expected-result tests as well as reference comparisons. Do not weaken an assertion, path check or mandatory CI coverage merely to pass. Distinguish skipped/unavailable cases from successful tests; do not rerun full suites or approved unrelated tests automatically.
3. For content/activation changes, verify deterministic reports, profile/hash isolation, invalid inputs, HRESULT/exit codes, process identity/lifecycle, timeout and cleanup. Parsing, export presence, activation request, positive activation and original SystemOS execution require separate evidence. Use owned fixtures without proprietary binaries.
4. For runtime/graphics changes, compare state, pixels, audio, input and timing at matched boundaries; test persistence, session restart and cache invalidation when affected. A present call, synthetic counter or reference comparison does not prove console behavior. Exercise original scenes only with authorized inputs/permissions. Identify human, scripted UI, headless or synthetic validation, physical/software GPU and untested hardware.
5. Check CI for the exact published code revision and runner OS/architecture. Track the six planned targets separately; claim only actual matrix coverage. Separate compilation, inspection, CPU execution, GPU types and skipped tests. CI without originals does not certify dashboard/gameplay. Do not rerun the complete matrix for an instructions-only edit.

Baseline commands, adapted to the existing build directory and affected targets/tests:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target <existing-affected-target>
ctest --test-dir build -C Release -N
ctest --test-dir build -C Release -R "<existing-affected-test-pattern>" --output-on-failure
```

The placeholders require actual CMake target/test names, not literal execution. For multi-configuration generators select `Release` in both build and CTest. Verify current CLI help, CMake options and prerequisite tools instead of inventing commands, SDK pins or copying another project's scripts. These examples do not authorize package deployment or a full test suite.

## Build foundation and diagnostics

Generated output and caches must be content-addressed and owned by the correct content profile/revision, source checkout, compiler/ABI, configuration and inputs. Preserve unchanged timestamps and reusable objects where valid. Publish generated results transactionally; failure must not destroy the last valid output or unrelated files. Serialize writers to shared build/cache outputs and reserve RAM/threads for the host; do not benchmark while compiling.

Header/ABI, shader, generator, dependency or compiler changes invalidate affected artifacts. Preserve required identity checks on reuse and before execution. Pin adopted dependencies by revision/hash and keep patches reproducible; do not invent SDK locks or patch stacks. No unnecessary global AVX/AVX2 or fast-math; optional SIMD needs capability checks and a compatible path. Document original components' CPU requirements. Evaluate LTO/PGO with measured build-time, memory, disk and runtime impact, preventing stale profile reuse.

Reuse bounded local diagnostics. Keep exit codes and actionable errors, identify truncation, and collect only the task's processes. Export only an explicit reviewed allowlist with path/private-data redaction; no full environment dumps or automatic upload. Firmware, OSUs, games, saves, account data, keys, proprietary memory/graphics captures and generated proprietary code are not public diagnostic attachments. Basic frame accounting and intrusive timing are separate modes. Report storage generated/reused for changes to import, preparation or caching; avoid duplicate ZIPs, evidence snapshots and whole-input copies.

## Documentation, language and publication

`README.md` and `README.pt-BR.md` are stable public introductions with equivalent content. This file holds durable policy; `CLAUDE.md` is a pointer. Change them only for real policy, architecture or public-use changes. Evidence belongs in existing subsystem or `docs/M*-STATUS.md` reports and `STATUS.md`; next actions in `docs/NEXT-TASK.md`. No document churn, machine-specific counts or duplicated milestone reports. Historical research versions are not automatically chosen/validated dashboard targets.

Follow the reference's English convention for new code identifiers, comments and commit messages. New technical guidance may use English; preserve existing Portuguese reports and the English/Portuguese UI and README translations rather than translating unrelated files. User-facing replies stay in the user's language. Check translation placeholders and accessibility when changing the UI.

Preserve BSD-3-Clause and existing human/upstream attribution. The reference guides do not grant permission to relicense third-party code. WinDurango is an LGPL-3.0 reference: review integration and redistribution obligations before copying, adapting or linking it, and obtain a maintainer decision when needed. Azimuth is a public product/behavior reference, not an assumed source dependency. Do not silently incorporate incompatible implementations or fetch leaked SDKs. Do not commit Microsoft firmware, dashboards, games, protected XVD/XVC contents, fonts/assets, keys, saves, dumps or code derived from proprietary binaries without applicable authorization. Do not implement DRM bypass, key extraction or circumvention of access protections.

Work directly on `main` for authorized tasks unless the maintainer says otherwise. Use Conventional Commits without assistant co-author signatures or generated-by footers; preserve genuine credits. No PR, ZIP or Release unless requested; no history rewriting, force-push or repository visibility changes. Do not modify x360-native or ps2-native as part of this project's work. Finish with the actual commits, implemented behavior, checks/CI actually performed, measured user-path result when relevant and remaining limits. A green build or instructions update is not a performance fix or proof of original dashboard execution.
