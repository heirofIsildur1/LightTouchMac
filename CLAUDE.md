# Working in Light Touch

For coding agents. The build, the gates, the layout and the style are in [CONTRIBUTING.md](CONTRIBUTING.md); this is
what to do and not do on a shared Mac.

## Files and processes

- Scratch goes under one root: `~/Developer/ltm-scratch.noindex/<task>/`. Never `/tmp/<name>`. Delete your task's
  directory when you are done; `scripts/clean` (a dry run; `--yes` acts) sweeps what is left.
- Never modify a shared base, vendor directory or another checkout in place. Copy it into your scratch directory (or
  boot it with an overlay) and work on the copy.
- Kill by PID only: the PID you started, or one read from a pid file. No `pkill`, `killall` or `pgrep -f` patterns;
  they hit other agents' emulators (and a `pgrep -f` wait loop matches its own shell).
- Never `git stash`: the stash is shared by every worktree. Commit work in progress on your branch instead.
- Never push; the lead lands changes.
- Emulators are silent: every headless boot passes `-audio driver=none`.
- Never launch, quit or UI-script Light Touch.app, Xcode previews or on-screen test windows. Everything you run is
  headless.

## Building and testing

- First build: `scripts/bootstrap` (or `scripts/vendor` when only the pins moved). Xcode fails with one line when the
  vendor directory is missing or stale; run what it says.
- Before `sessions`: `swift build --package-path tests/sessions`, then `swift run --package-path tests/sessions
  sessions …`.
- Unit tests: `xcodebuild test -workspace LightTouchMac.xcworkspace -scheme LightTouchMac -testPlan Unit`, or
  `swift test --package-path Packages/<Package>` for one package. Tests live in `Packages/*/Tests`, `tests/offline`
  and `tests/sessions` (CONTRIBUTING.md, Gates); the scripts' shell tests in `tests/scripts`.
- `sessions` and `scripts/release` end with one line, `PASS <summary> <log>` or `FAIL <first failure> <log>`; exit 0
  pass, 1 fail, 2 refused or stale input, 3 infrastructure. Read that line, not the logs.
- Before booting emulators, `scripts/host-ready` prints `READY …` (exit 0) or `WAIT <why>` (exit 1: load, all three
  emulator slots taken, or disk); `sessions` holds a slot for its run and waits for one when none is free.
- A new test must fail with the fix reverted; say so in the commit.
- Before committing Swift: `swift-format lint -r <changed paths>` stays quiet.

## Commits

- Repository style: one long message saying what changed and why, ending with `Checked:` and the evidence (test
  names, pass counts, what failed with the fix reverted).
- No AI attribution: no tool or assistant names, no session or co-author trailers.
- American spelling (license, behavior, color), but Apple's cancelled and cancellable.
- The product is "Light Touch", two words, wherever a person reads it; `LightTouch` only in identifiers.
