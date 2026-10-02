# Do the client's dispute checks mitigate the emulator findings?

Scope: `rust-bitvmx-client/src/program/protocols/dispute/` (`mod.rs`, `challenge.rs`, `execution.rs`, `tx_news.rs`, `input_handler.rs`, `config.rs`), client `v0.8.6`, BitVMX-CPU `v0.8.6`. The client builds against the local workspace checkouts through the path overrides in `.cargo/config.toml`.

## On-chain checks the client adds (besides the challenge leaves)

| Where | Check | Relevant to |
|---|---|---|
| `mod.rs:694-716`, `get_validate_last_step_script` (`:1535`) | COMMITMENT: `prover_last_step != 0` and `prover_last_step <= max_steps` | EMU-004 |
| `mod.rs:718-736`, `get_verify_last_step_script` (`:1553`) | POST_COMMITMENT: the verifier re-signs `verifier_last_step_tk == prover_last_step` | EMU-004 |
| `mod.rs:768-769`, `:882-883`, `get_validate_selection_bits_script` (`:1520`) | every n-ary verifier selection is `<= 2^bits - 1` | n-ary search |
| `mod.rs:1294-1323`, `challenge_step_script`, conflict search (EXECUTE leaf 0) | the **prover** can end the dispute if the verifier's selection is `>= last_step`. The verifier then can't continue, because `prover_continue` is not signed. | EMU-004, EMU-005 |
| `mod.rs:1324-1354`, `challenge_step_script`, read search (GET_HASHES_AND_STEP leaf 0) | the **prover** can end the dispute if the 2nd-search selection is **greater** than the 1st-search selection (the conflict step) | EMU-003, EMU-010 |
| `mod.rs:1172-1205`, `get_reverse_and_strip_scripts` (EXECUTE) | `verify_challenge_step(prover_conflict_step_tk, selection)`. `prover_read_1/2_last_step`, `prover_step_number`, `prover_step_hash_tk` and `prover_next_hash_tk` are **dropped without any check**. | EMU-003 |
| `input_handler.rs:33` | input sizes are non-zero multiples of 4 | EMU-006, EMU-007 |
| `input_handler.rs` / `tx_news.rs` | the program input is always exactly `sum(inputs.size)` bytes | EMU-007 |

## Ticket by ticket

| Ticket | Mitigated by the client? | Details |
|---|---|---|
| EMU-001 checkpoint-step trace | **No** | The client sends `ProverFinalTrace(decision + 1)` with no check. The zeroed trace has `opcode = 0`, which doesn't decode to a known instruction, so `execution.rs:216-224` should return `InstructionNotFound` and the prover posts **no** EXECUTE tx (opcode 0 assumed to fail to decode, not run). The honest prover loses by timeout instead of by `TraceHash`, which is the same outcome. |
| EMU-002 / EMU-012 registers as zero memory | **No** | The `uninitialized` leaf is built straight from `get_uninitialized_ranges` (`challenge.rs:603`), and the `initialized` leaves from `get_initialized_chunks` (`:492`). The EMU-012 fix needs no client code change (the leaves follow the CPU functions). |
| EMU-003 read `last_step = 0` | **No.** The guess that the DRP rejects `last_step = 0` by script is not right. | The COMMITMENT check applies to `prover_last_step` (the program's final step), not to the read last steps. In EXECUTE, `prover_read_1_last_step` and `prover_read_2_last_step` are dropped unchecked (`mod.rs:1182-1185`), and no instruction script sees them. The only leaf that uses them is `future_read` (`conflict_step < read_step`), which accepts 0. The read-search rule makes the outcome deterministic: in release builds the underflow puts the verifier's 2nd-search selection in the top segment (`> conflict step`). The prover can then post the GET_HASHES_AND_STEP challenge-step leaf and **wins on-chain**. In debug builds the verifier job panics and the prover wins by timeout. The ticket's fix (extend `FUTURE_READ_CHALLENGE` with `prover_mem_witness`) is still needed. |
| EMU-004 `claim_last_step == 0` / `last_step == max_steps` | **Partly** | `claim_last_step == 0` is rejected by the COMMITMENT script, as the ticket already says. `last_step == max_steps` is **accepted** (`<=`), so the power-of-two `max_steps` panic is reachable. Cheaper alternative to the ticket's fix: make the COMMITMENT check strict (`last_step < max_steps`) if the CPU fix (`nary_def(max_steps + 1)`) is not wanted. |
| EMU-005 padding after halt | **Yes** | The conflict-search challenge-step rule stops the verifier from selecting at or after `last_step`, so padded hashes are never challenged. This confirms "benign". |
| EMU-006 `get_uninitialized_ranges` exact-fill panic | **No** | `challenge_scripts` calls it during setup on both parties (`challenge.rs:603`). Nothing compares `sum(inputs.size)` with the input section size, so the setup crashes (liveness only). |
| EMU-007 oversized input | **Yes** (already noted in the ticket) | The input is always exactly the declared size. The open endianness question is **resolved: it is a real Critical bug**, see EMU-013. |
| EMU-008 no early exit | **No** | Every round is a separate tx with the configured `timelock_blocks` (default 15). With mainnet block times a 2–3 min job is fine. With short test or regtest timelocks, or `max_steps` in the billions, the deadlines can be missed. Severity unchanged. |
| EMU-009 minor | Partly unreachable | The client doesn't call `generate_rom_commitment`, `is_register_address` or `get_last_register_address`, so items 1–2 don't affect the DRP. It has its own `rom` leaves instead, see EMU-014. |
| EMU-010 read search pulled to the conflict step | **No** | The read-search rule only lets the prover object when the verifier selects **past** the conflict step. Ending exactly at the conflict step is allowed, the verifier then has no challenge, and the cheating prover wins. |
| EMU-011 chunk `base_addr` units | **No** | The opcode and initialized leaves use `get_code_chunks` / `get_initialized_chunks` directly, with `chunk_index` as the leaf offset (`challenge.rs:293`, `:492`, `:851-859`, `:890-902`). |

## New findings in the client

| Ticket | Summary | Severity |
|---|---|---|
| [EMU-013](tickets/EMU-013-input-leaf-byte-order.md) | The `input` leaves compare raw input bytes with big-endian-signed read values, while the emulator reads memory little-endian. A malicious verifier wins against any honest prover that reads a non-palindromic input word, and a byte-swapped lie can't be refuted. Confirmed by running the real leaves with real WOTS signatures. Client-only fix validated. | Critical |
| [EMU-014](tickets/EMU-014-client-rom-leaf-count.md) | The `rom` leaves are dead code (the emulator never emits `RomData`). Their counter is off by one when `.rodata` has a multiple of 4 words, which would shift every later challenge leaf. Not triggered by current programs. | Medium (latent) |

Other things checked that look fine:
* the input leaf offset (`(address - base) / 4` matches the leaf order, because the input offsets are cumulative);
* the `ProverPrev` leaves;
* the EXECUTE instruction-leaf index;
* the `read_value_nary_search` leaf detection in `tx_news.rs`;
* the dedup guard for job results.
