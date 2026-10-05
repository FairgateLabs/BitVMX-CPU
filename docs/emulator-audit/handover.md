# Emulator / DRP audit: handover

State as of 2026-10-02. Nothing has been applied to production code: every fix exists only as a diff in its ticket, plus tests that prove the bug and, where noted, the fix.

Update 2026-10-05: the fixes are also available as validated, `git apply`-able diffs in [`patches/`](patches/) (see README section 9).

## Where things are

| What | Location |
|---|---|
| Architecture / protocol reference + ticket index | `BitVMX-CPU/docs/emulator-audit/README.md` |
| Which client (`rust-bitvmx-client` `dispute/*`) checks mitigate which ticket | `BitVMX-CPU/docs/emulator-audit/client-mitigations.md` |
| Tickets (bug, evidence, test, proposed diff, risks) | `BitVMX-CPU/docs/emulator-audit/tickets/EMU-001..014*.md` |
| Validated patches (CPU + client) | `BitVMX-CPU/docs/emulator-audit/patches/*.diff` |
| Emulator-side tests | `BitVMX-CPU/emulator/tests/audit_emu_0NN.rs` (EMU-010's tests are in `audit_emu_005.rs`) |
| Client-side test | `rust-bitvmx-client/tests/audit_emu_013_input_byte_order.rs` |
| Branch | `claudeaudit` in both `BitVMX-CPU` and `rust-bitvmx-client` (this file may still be uncommitted) |

## Test conventions

* `#[ignore = "EMU-0NN: fails until fixed"]`: asserts the correct behaviour. It fails today and must pass once the fix is applied. Run it with `--include-ignored`.
* `demo_*` / `emu0NN_demo_*`: demonstrates the bug and passes today. Delete it, or flip it, when the fix lands (it will start failing).
* `#[should_panic]` demos only panic in debug builds, because they rely on overflow checks.
* Commands:
  * CPU: `cargo test -p emulator --test audit_emu_0NN -- --nocapture --include-ignored` (from `BitVMX-CPU/`).
  * Client: `cargo test --release --test audit_emu_013_input_byte_order -- --nocapture --include-ignored` (from `rust-bitvmx-client/`; builds against the local workspace through `.cargo/config.toml` path overrides).
* Some emulator tests write checkpoints under `%TEMP%/bitvmx-audit-emu-0NN/`.

## Status by priority

| Ticket | Severity | Status | Next action |
|---|---|---|---|
| EMU-013 client input leaves, wrong byte order | **Critical** | Confirmed on the real leaf scripts with real WOTS signatures. Client-only fix validated. | Apply the diff in `challenge.rs`. Add a client e2e test with a non-palindromic input. |
| EMU-011 `get_chunks` `base_addr` in words | **Critical** | Fix validated (scratch copy + full regression) | Apply the one-line fix. Delete the `emu011_demo_*` tests. |
| EMU-002 → **EMU-012** registers counted as zero memory | **Critical** | EMU-012 fix validated (no regressions) | Apply EMU-012, not EMU-002's own proposal. Merge it with the EMU-006 diff (same function). |
| EMU-001 checkpoint-step trace is empty | High | Confirmed, diff in ticket | Apply. Only programs with more than 50M steps are affected. |
| EMU-003 read `last_step = 0` | High | Confirmed. The client does **not** block it. | Needs a script change: a `future_read` leaf with `prover_mem_witness`. |
| EMU-010 read search pulled to the conflict step | High | Confirmed, diff in EMU-005 | Apply. |
| EMU-004 `last_step == max_steps` with power-of-two `max_steps` | Medium | Confirmed | Fix in the CPU (`nary_def(max_steps + 1)`), or make the client COMMITMENT check strict (`<`). |
| EMU-006 exact-fill input section panic, PROGBITS input | Medium | Confirmed | Apply, merged with EMU-012. |
| EMU-008 no early exit in step queries | Medium (liveness) | Confirmed | Apply the early `break`. |
| EMU-014 client `rom` leaves (dead code, leaf counter can shift) | Medium (latent) | Code reading only | Remove the `rom` leaves. Derive leaf starts from `challenge_leaf_script.len()`. |
| EMU-005, EMU-007, EMU-009 | Low | See tickets | Robustness only. |

## Rollout notes

* EMU-011, EMU-012, EMU-013, EMU-014 and EMU-003 all change the dispute taproot leaves.
  * Ship them together in one coordinated version bump (CPU tag + client).
  * Existing dispute setups are incompatible after the change.
* EMU-006 and EMU-012 both edit `get_uninitialized_ranges`; merge them by hand.
* EMU-012 follow-up: `generate_rom_commitment` should also skip `section.registers`. This is EMU-009 item 1; it's not used by the client.

## Open questions

* EMU-011: the external report counts about 950 code chunks for `zkverifier-new-mul.elf`, but we count 1773. Check which ELF build the report used.
* EMU-001's consequence in the client (no EXECUTE tx, because opcode 0 doesn't decode) was found by reading the code, not by running it.
* EMU-014 has no executable test. One would need a `ProgramContext` to call `challenge_scripts`.
