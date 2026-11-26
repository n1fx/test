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


## Follow-up (2026-11-26, next pass)

- Re-checked successful analysis run `45767589998` and the generated `selected_classes_full.txt` on branch `apk-analysis-20261126`.
- In the extracted `Lxb30` coroutine branch invoked with operation `register`, the caller explicitly constructs `Lxb30` with flag `true` and the string `register`; the Offer parsing/validation checks include matching provider binding, `noise_hybrid_ik_v1`, `connection_protocol=rmcp`, `role=environment`, nonblank and matching `executor_registration_id`, `sig` format, nonblank `v`, and parseable `exp`. This confirms checks in the code path, but not cryptographic verification of the signature by this method.
- The extracted `Ls5f0` coroutine segment contains the exception strings `RMCP handshake grant rejected` and `Missing Noise handshake`; nearby byte-array and handshake-object operations appear to assemble/use a handshake result, but the exact verification semantics remain unresolved due to obfuscation and fragmented extraction.
- `Lc0z0` is tied to `RmcpHttp2Server.Frame` via a callback signature and has a lock/queue-like flow with a `HTTP/2 connection closed` failure. This is evidence of a server-frame handler component, not proof of the server startup trigger or listener binding.
- `x-codex-rmcp-grant` occurs in the extracted handler that checks the HTTP path `/mcp` and filters that header. This appears to be part of a grant-bearing MCP request path. Its downstream use still requires caller/data-flow tracing.

### Next unresolved items

1. Locate constructor and call sites for `RmcpHttp2Server` and establish startup/port/host binding conditions.
2. Trace `x-codex-rmcp-grant` into the Noise handshake and identify how the grant is accepted or rejected.
3. Determine if this RMCP path is gated by feature flags, enrollment state, or user-facing activation.
4. Do not modify ACA until a compatible transport/handshake integration point is established.
