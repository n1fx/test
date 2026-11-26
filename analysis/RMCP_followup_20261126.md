# RMCP analysis follow-up (2026-11-26)

## Confirmed from APK disassembly

- Enrollment offer validation checks binding, protocol identifier `noise_hybrid_ik_v1`, `connection_protocol=rmcp`, `role=environment`, and `executor_registration_id` consistency.
- A `sig` value is checked for a 64-character lowercase hexadecimal shape; this alone does not establish cryptographic signature verification.
- `v` must be present/nonempty and `exp` parseable as a long.
- The RMCP transport/handshake path has explicit failure strings `RMCP handshake grant rejected` and `Missing Noise handshake`.
- `Lc0z0` adapts server-frame callback identified as `com/openai/feature/deviceexecutor/impl/RmcpHttp2Server$Frame`. It maintains a lock, queue, and HTTP/2 frame handling callback. Lifecycle/startup trigger remains unresolved.
- Local endpoint `http://127.0.0.1:39801/android-executor/mcp` routes internally to MCP handling, but arbitrary ACA access without enrollment/RMCP handshake is not established.

## Next unresolved questions
1. Find server lifecycle/startup code and instantiation conditions.
2. Trace grant/offer data and cryptographic Noise handshake to transport.
3. Trace enrollment caller and feature gating.
4. Determine whether ACA interoperability requires enrollment plus Noise/RMCP. Evidence suggests ordinary MCP HTTP alone is insufficient.
