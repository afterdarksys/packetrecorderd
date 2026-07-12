# Decoder Plugin V1 Implementation Plan

> **For Codex:** Use `${SUPERPOWERS_SKILLS_ROOT}/skills/collaboration/executing-plans/SKILL.md` to implement this plan task-by-task.

**Goal:** Deliver a safe, versioned native subprocess plugin contract for proprietary packet decoders without coupling plugins to packet recording.

**Architecture:** Trusted configuration declares an executable and argument vector, selectors, and resource/protocol limits. Decoder subprocesses exchange bounded length-prefixed protobuf messages and return typed fields, byte annotations, confidence, findings, and explicit partial-data status. Existing bounded analysis workers invoke plugins; capture and PCAP persistence remain independent.

**Tech Stack:** Rust, serde/JSON manifests, Prost/Protocol Buffers, supervised native subprocesses, existing crossbeam analysis workers.

---

### Task 1: Versioned manifest and safe process launch

**Files:**
- Modify: `src/config/plugins.rs`
- Modify: `plugins.json`
- Modify: `src/main.rs`
- Test: `src/config/plugins.rs`

**Step 1:** Add tests for executable/argument arrays, API version validation, duplicate/empty selectors, and bounded limits.

**Step 2:** Run `cargo test config::plugins::tests -- --nocapture`; expect the new tests to fail.

**Step 3:** Replace shell-like `command` strings with `executable` and `args`; add selector and limit defaults plus validation.

**Step 4:** Update plugin registration and the example manifest.

**Step 5:** Run `cargo test config::plugins::tests -- --nocapture`; expect all tests to pass.

### Task 2: Typed, bounded decoder protocol

**Files:**
- Modify: `proto/packetrecorder/v1/plugin_api.proto`
- Modify: `src/protocols/plugin.rs`
- Modify: `examples/plugins/example_plugin.py`
- Regenerate: `examples/plugins/packetrecorder/v1/plugin_api_pb2.py`
- Test: `src/protocols/plugin.rs`

**Step 1:** Add tests rejecting oversized requests/responses and invalid byte annotations.

**Step 2:** Run `cargo test protocols::plugin::tests -- --nocapture`; expect failures.

**Step 3:** Add API version, packet/flow metadata, typed fields, byte annotations, findings, confidence, partial-data status, and response limits to protobuf.

**Step 4:** Implement bounded framing, response validation, child cleanup/restart, environment clearing, and executable/argument launch.

**Step 5:** Update and regenerate the example plugin, then run the focused tests; expect all to pass.

### Task 3: Integration and operator documentation

**Files:**
- Modify: `src/processing.rs`
- Modify: `src/main.rs`
- Modify: `src/protocols/README`
- Modify: `README.md`

**Step 1:** Add an integration test proving selector dispatch returns structured plugin information without affecting unsupported traffic.

**Step 2:** Run the focused integration test; expect failure before wiring.

**Step 3:** Wire validated manifests into the existing bounded analysis workers and translate typed plugin results into protocol summaries/findings.

**Step 4:** Document plugin authoring, security boundaries, limits, and overload behavior.

**Step 5:** Run `cargo test --all-targets`, `cargo check --all-targets`, and `git diff --check`; expect clean success.
