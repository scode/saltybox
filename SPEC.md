# saltybox specification

This document specifies saltybox's user-visible behavior: the command-line interface and the on-disk file formats. It is
a specification of behavior — what users and other implementations can rely on — not documentation of the
implementation. Implementation details do not belong here.

NOTE: Coverage is deliberately incremental. Behavior not described here is existing-but-unspecified, not nonexistent.
When a change touches user-visible behavior, the touched area must be specified — including its pre-existing behavior —
in the same change. `AGENTS.md` states the compliance rule.

## Commands

Not yet specified: `encrypt`, `decrypt`, `update`, and the global `--passphrase-stdin` option.

## File formats

Not yet specified: the `saltybox1` armored format and its binary payload.
