# xboxone-native

**Experimental Xbox One compatibility project** — original SystemOS/dashboard first, then dashboard → game → dashboard.

Early technical milestone **M0**. This is **not yet an Xbox One emulator, a SystemOS boot environment, or a working dashboard**. Do not report game compatibility or publish end-user releases based on the successful compilation of these tools.

The Xbox One uses native x86-64 code but isolated HostOS, SystemOS and GameOS environments, including Xbox-specific virtual devices and services. Xbox One binaries are not automatically Windows desktop applications. The project will prioritize direct x86-64 execution when feasible, with isolated compatibility services and a possible SystemOS VM backend. The dashboard must ultimately be rendered by **original, legally obtained Microsoft components**, never screenshots or lookalike UI.

## M0 — first working increment

A portable, **read-only image inspector** identifies:

- XVD header magic at offset `0x200`, file size, format/content type, block size, declared volume size and raw required system version. **It does not verify Microsoft's signature or decrypt the payload.** A matching magic alone never proves authenticity.
- PE32+ AMD64 binaries, entry-point RVA, subsystem, image base, sections, and imported DLLs/functions (by name or ordinal). **This does not prove that a PE file belongs to Xbox One or can execute.**

No images or firmware are downloaded, copied, changed or shipped. The analyzer reads directly from the supplied path and never writes alongside it.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure

./build/xboxone-native inspect /path/to/legally-obtained/system.xvd --json
./build/xboxone-native inspect /path/to/legally-obtained/component.exe
```

On Windows use `build\\Release\\xboxone-native.exe` with multi-config generators; `build\\xboxone-native.exe` with single-config generators.

## Architecture and next blocking task

See [docs/M0.md](docs/M0.md) for the component boundaries, version choice, technical blockers, evidence and next task. `xboxone_inspection` is a library for the future content pipeline; its parser is separated from the CLI and UI, avoiding divergent copies across host platforms.

## Boundaries and licensing

- Original project code: BSD-3-Clause (`LICENSE`). Third-party code is **not vendored**.
- WinDurango: LGPL-3.0; inspect APIs and architecture, but do not copy source without an explicit license strategy.
- Azimuth: closed-source reference, not a dependency.
- No Xbox firmware, games, keys, XVD/XVC decryptors or DRM-bypass code in this repository.
- Original source content remains at its existing location. Future caches must be content-addressed and independently audited for redundant copies.

Reference sources: [Xbox One Research](https://xboxoneresearch.github.io/wiki/operating-system/xbox-operating-system/), [XVD format](https://xboxoneresearch.github.io/wiki/operating-system/xbox-virtual-drive/), [GameOS launch](https://xboxoneresearch.github.io/wiki/games/launching/), [WinDurango](https://github.com/WinDurango/WinDurango), [Azimuth](https://almost-there-games.itch.io/azimuth), [x360-native](https://github.com/fabegalo/x360-native).
