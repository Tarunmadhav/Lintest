# Proposal: flock-based lock for the alert state file

Status: **proposal only — not implemented.** Covers `AlertManager._load_state`
/ `_save_state` (`lintest/alerts/manager.py`).

## Current behaviour

Each dispatch does: load `state.json` at construction → decide cooldowns →
atomic save (`mkstemp` temp + `os.replace`, unique per write). Writes are
individually crash-safe; a reader only ever sees a complete file.

## What is still racy

The whole dispatch is a **read-modify-write** critical section with no lock:

1. **Lost updates.** Process A loads state; process B loads the same state,
   saves its alert entry; A saves its (stale) view — B's entry vanishes.
   Next run then treats B's problem as "not firing" and re-alerts, or loses a
   `firing` flag and its cooldown.
2. **Double alerts.** Two overlapping runs both see "not firing, not in
   cooldown" and both send the alert (or the RECOVERED message).
3. **Dropped recovery/suppression state** — the mirror of (1): an entry that
   should stay `firing` is overwritten by a stale snapshot that lacks it.

Today the blast radius is limited by design: `OnUnitInactiveSec` stops the
timer from overlapping itself, and state lives on local disk. The realistic
overlap sources are cron + a manual run, systemd + manual run, or two hosts
sharing a state path (unsupported). The failure is *probabilistic*, which is
exactly why it tends to surface as a rare test flake rather than a bug report.

## Does an `fcntl.flock` lock file fit? — Yes, with caveats

- **Mechanism:** a sibling lock file (`state.json.lock`, never itself renamed;
  the data file is replaced atomically, so flock must *not* be taken on
  `state.json`). Take `flock(LOCK_EX)` before `_load_state` and release after
  `_save_state` (context manager, released implicitly on process death —
  no stale locks after a crash, unlike lock-file-with-PID schemes).
- **Scope:** Linux-only by nature; guard with a `try: import fcntl` so the
  Windows dev environment degrades to today's behaviour (and POSIX-only tests
  skip, like the existing permission test).
- **Blocking policy:** runs are seconds long, so block with a short timeout
  (e.g. 30 s — well under the 5-min interval). On timeout, log a warning and
  proceed *without* persisting (deliver alerts, skip the save) — availability
  over bookkeeping; a wrong cooldown beats a missed alert.
- **Not fixed by flock:** multi-host shared state (NFS `flock` semantics are
  a separate question — keep state on local disk, as installed today), and
  last-writer-wins is still the outcome of *sequential* runs (harmless).

## Failure modes it removes

- Lost update between load and save (item 1).
- Duplicate alert / duplicate RECOVERED on genuine overlap (item 2).
- Cooldown or `firing` flag silently rolled back by a stale writer (item 3).

## Test it needs

A deterministic multi-process regression test in `tests/test_state_file.py`:

1. **Lost-update test:** spawn N (≈8) processes that each construct a manager
   against the same state file, inject a delay between load and save (test
   hook via a subclass in the child, since children re-import the module),
   and dispatch a unique alert key. After joining, assert the state file
   contains **all N keys** and is valid JSON. Without the lock this fails
   reliably; with it, it must pass.
2. **Crash-release test:** SIGKILL a child while it holds the lock; assert the
   parent's next dispatch acquires it promptly (flock auto-release) and the
   state file is still parseable.
3. **Windows skip:** mark the module POSIX-only (`os.name != "posix"` → skip),
   matching `test_state_file_is_owner_only_on_posix`.

## Cost

~30 lines in `manager.py` (lock context manager + import guard) plus one test
file section. No CLI, config, or state-format change; the lock file is an
implementation detail (add `state.json.lock` to `.gitignore` and the
installer's state dir handling — nothing to do, the dir is runtime-owned).
