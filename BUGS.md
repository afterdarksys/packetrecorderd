# BUGS — Remediation record for review of `d70d2dc`

**Status: REMEDIATED.** The seven major findings and the actionable minor findings below were
fixed on 2026-07-12. The remediation added regression coverage and was verified with
`git diff --check`, `cargo test` (45 passed), and `cargo build`.

Reviewed: 2026-07-12. Base: `20f1719..d70d2dc`.

## Remediation summary

- Reordered or gapped TCP no longer bypasses downstream analysis.
- Plugin stream state now has time-based TTL eviction, a 64 MiB buffered-byte budget, and a
  100,000-flow ceiling with oldest-flow eviction.
- Plugin requests use one cumulative deadline across bounded stdin writes and stdout reads.
- Capture timestamp anomalies fall back locally, packet writers flush periodically, and PCAP
  creation fails safely when the path already exists.
- Signature bytes are decoded during plugin registration, not per packet.
- TCP sequence wraparound, partial overlaps, duplicate pending accounting, and fully covered
  pending segments have regression tests.
- Circuit-breaker recovery, poisoned plugin locks, finding drops, plugin process sharing,
  captured/original length reporting, zero-length annotations, and metric registration were fixed.
- Failed database flushes remain bounded at one batch. Plugin-finding database contention is an
  operational load-testing follow-up rather than an unbounded-memory defect.

---

## Original major findings (resolved)

### 1. Forensics bypass on reordered TCP
- **Where:** `src/processing.rs:404-406`
- **Defect:** When reassembly yields no contiguous bytes (retransmission, out-of-order, or gapped
  segment), `process()` does an early `return Ok(())` that skips *everything* downstream —
  TLS/HTTP/DNS detection, forensics, flow tracking, ML — not just the plugin step.
- **Failure scenario:** An attacker evades Tor / DNS-tunneling / malicious-IP detection simply by
  reordering segments; ordinary lossy links silently drop packets from analysis. (Packet storage is
  unaffected — it runs on the separate writer path.)
- **Fix direction:** Only the plugin call at `processing.rs:408` should be conditional on
  reassembly; the rest of `process()` must still run.

### 2. Unbounded `plugin_streams` memory (OOM DoS)
- **Where:** `src/processing.rs:161-182, 213, 265`
- **Defect:** The per-flow reassembler map (each entry buffering up to 1 MiB) is pruned only by a
  wholesale `.clear()` at 100k entries, inside `cleanup_stale_flows`, which is gated on
  `flow_table.len() % 1000 == 0` — and `flow_table` is populated only by TLS-with-SNI/cert flows,
  so the trigger commonly never fires.
- **Failure scenario:** An attacker opens many TCP flows, each sending a segment past a deliberately
  withheld earlier one, buffering up to 1 MiB per flow — multiple GB with a few thousand flows,
  ~100 GB at the wipe threshold. When the wipe does fire, `.clear()` destroys all in-progress
  legitimate reassembly at once.
- **Fix direction:** Per-flow TTL eviction plus a byte-based (not count-based) global cap;
  time-based cleanup trigger instead of the `% 1000` gate (which also churns when len sits at
  exactly 1000).

### 3. Plugin read timeout is not a cumulative bound
- **Where:** `src/protocols/plugin.rs:239-258`
- **Defect:** The timeout applies per `poll`, so a plugin drip-feeding 1 byte per interval never
  times out.
- **Failure scenario:** With responses allowed up to 16 MiB, a malicious/buggy plugin holds a worker
  thread for days; the worker stops draining its `bounded(8192)` channel, backpressuring capture.
- **Fix direction:** Enforce a cumulative deadline for the whole response read.

### 4. No stdin write timeout — pipe deadlock risk
- **Where:** `src/protocols/plugin.rs:184-186`
- **Defect:** Reassembled payloads up to 1 MiB exceed the ~64 KiB OS pipe buffer, and `write_all`
  has no timeout.
- **Failure scenario:** A plugin that writes stdout before fully draining stdin deadlocks the worker
  permanently: Rust blocks in `write_all` while the plugin blocks writing stdout. (Confidence
  MEDIUM — the bundled example plugin drains first; this is an adversarial/buggy third-party
  plugin hazard.)
- **Fix direction:** One cumulative deadline covering write + read per plugin call (also fixes #3).

### 5. Fatal per-packet timestamp error aborts capture
- **Where:** `src/main.rs:402` (`capture_timestamp` call site in `cmd_capture`)
- **Defect:** A `capture_timestamp` failure aborts the entire capture, where the previous
  `Utc::now()` path could not fail. (Unit conversion itself is correct: µs→ns, no overflow.)
- **Failure scenario:** An interface configured for nanosecond-precision pcap, or a driver returning
  out-of-range `tv_usec`, kills a long-running root daemon on the first such packet.
- **Fix direction:** Handle per-packet anomalies locally (log + fallback timestamp), never fatally.

### 6. Buffered data lost on non-graceful exit
- **Where:** `src/capture/writer.rs:137` (and `DatabaseWriter` batching)
- **Defect:** `PcapWriter::flush()` is a no-op (the 1 MB `BufWriter` drains only in `close()`), and
  `DatabaseWriter` buffers up to 512 packets in `pending` with no time-based flush and no periodic
  `flush()` call in the capture loop.
- **Failure scenario:** SIGKILL / panic / power loss silently drops up to 1 MB of PCAP output and up
  to 511 in-memory packets from a recording the operator believes is durable. Graceful Ctrl+C is
  fine.
- **Fix direction:** Real `flush()` plus a periodic time-based flush in the capture loop.

### 7. Per-packet hex decode of signatures on the hot path
- **Where:** `src/config/plugins.rs:22-27` (`PayloadSignature::matches`)
- **Defect:** Every unmatched packet re-decodes each signature's constant hex bytes
  (hex-decode + `Vec` allocation per signature per packet).
- **Fix direction:** Precompute decoded bytes at config load. (Matching arithmetic itself is
  correct — `checked_add` + `payload.get(..)`, no short-payload panic.)

---

## Original minor findings (resolved unless noted)

1. **Sequence-number wraparound stalls flows** — `src/protocols/reassembly.rs:19,23`. In a flow
   exceeding 4 GB, at the seq wrap an in-order segment compares `< next_seq`, is discarded as a
   retransmission, and the flow stalls permanently.
2. **Partially-overlapping segments dropped whole** — `src/protocols/reassembly.rs:19-21,30-32`.
   A segment with `sequence < next_seq` but `sequence + len > next_seq` loses its non-overlapping
   tail; the drain loop only matches keys exactly equal to `next_seq`.
3. **`pending_bytes` underflow** — `src/protocols/reassembly.rs:24-26,31`. Re-inserting a duplicate
   out-of-order `sequence` with a different length replaces the vec without adjusting the counter;
   the drain subtracts the new length. Release: wraps to huge `usize`, making the
   `> max_pending_bytes` guard permanently true (all future out-of-order data dropped). Debug: panic.
4. **Circuit breaker never half-opens cleanly** — `src/protocols/plugin.rs` (`CircuitBreaker::allow`).
   Cooldown expiry clears `opened_at` but not `failures`, so one post-recovery failure re-opens
   immediately and `failures` grows unbounded across cycles.
5. **Poisoned plugin lock silently disables plugin** — `src/protocols/plugin.rs`.
   `if let Ok(mut plugin_instance) = plugin.lock()` discards `PoisonError`; after any panic while
   the lock is held, every subsequent packet skips that plugin with no log or metric.
6. **Findings silently dropped when channel full** — `src/processing.rs`
   (`let _ = sink.try_send(PluginFindingRecord{..})`). No counter or warning — silent data loss in
   a forensics tool.
7. **One plugin process per worker thread** — each worker's `PacketProcessor` →
   `register_config` → `PluginInstance::new` spawns its own process, so a single configured plugin
   runs `num_threads` OS processes.
8. **`captured_length == original_length` always** — the proto distinguishes captured vs. original
   (wire) length for snaplen truncation; plugins keying on truncation always see them equal.
9. **Zero-length annotation is fatal** — `validate_response` bails on the entire response (and
   increments the circuit-breaker failure count) for a single zero-length annotation instead of
   ignoring it.
10. **`create_private_file` follows symlinks** — `src/capture/writer.rs:148`. An attacker with write
    access to the output directory pre-plants a symlink at the `--pcap` path; the root daemon
    truncates and chmods the target. Use `create_new` (fail-if-exists). No create/chmod race for
    the new-file case (mode set via `O_CREAT`).
11. **Latent `register_metrics` double-registration panic** — `src/metrics.rs:75`. Single call site
    today (`main.rs:110`); hazard for any future second entry point (tests, embedded serve).
12. **`save_plugin_finding` contention / error growth** — `src/storage/mod.rs` does one autocommit
    INSERT per finding on the same `Arc<Mutex<PacketStore>>` as the batched packet writer
    (`main.rs:302`); on persistent DB error `DatabaseWriter.pending` (`writer.rs:72-77`) is never
    cleared and grows unbounded. **Resolved:** failed packet batches are now capped; finding-write
    contention remains a load-testing and performance follow-up.

---

## Verified clean (explicitly checked, no defects)

- **Protobuf framing Rust↔Python matches exactly** — 4-byte big-endian length prefix + prost body on
  both sides (`plugin.rs:183-199` / `example_plugin.py:9-55`); field semantics and generated
  `plugin_api_pb2.py` in sync with the `.proto`.
- **`validate_response` is genuinely defensive** — request cap via `encoded_len`,
  `max_response_bytes` cap before allocation, `checked_add` on annotation offset+length with
  payload-bounds check (`plugin.rs:173-221`).
- **`PluginsConfig::validate` is thorough and unit-tested** (`plugins.rs:82-152`) — rejects unknown
  api_version, empty name/executable, duplicate names, zero/absent selectors, out-of-range limits.
  (The only tested part of the change — the pattern to copy elsewhere.)
- **No zombie processes** — `stop_process()` does kill + wait; `Drop for PluginInstance` calls it
  (`plugin.rs:224-274`); child reaped before retry on parse error.
- **No lock-across-await issues** — processing runs on dedicated OS worker threads
  (`thread::spawn`, `main.rs:351`), no async runtime; per-worker mutexes are uncontended.
- **Shutdown ordering is deadlock-free** — `senders` dropped before `join` (`main.rs:456`),
  finding channel closed before joining its thread (`main.rs:460`). Backpressure via
  `bounded` + `try_send` drop-and-warn correctly prioritizes recording over analysis
  (`main.rs:334,418-428`).
- **Hardening done right** — `env_clear()` + explicit PATH, shell-string→args-vector change,
  auth added on `list_sessions` (`api.rs:161-165`, closed an unauthenticated-enumeration gap),
  CDN-before-hosting reorder in `classify_ip_type` (`ip_reputation.rs:96-103`) is a correct fix.

---

## Completed order of work

1. **#1 and #2 first** — they undermine the tool's core purpose (forensic completeness) and its
   stability.
2. **#3 / #4 together** — both are "untrusted plugin can stall a root daemon" bugs; one cumulative
   deadline covering write+read per plugin call addresses both.
3. **#5–#7**, then the minors.
4. **Tests:** 59 changed functions are untested. Priorities: plugin runtime (`plugin.rs` lifecycle,
   circuit breaker, timeouts), reassembly edge cases (wraparound, overlap, `pending_bytes`), and
   writer flush/durability behavior.
