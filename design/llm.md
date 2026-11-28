# dos-llm: model gateway

## Goal

Port the oracle model gateway (`oracle/decision-os-min/decision_os_min/gateway/llm_proxy.py`)
to Rust. Given an upstream model response (OpenAI chat completions, OpenAI Responses,
Anthropic Messages; JSON body or SSE stream), find every tool call the client would
execute, gate each one through a decision callback, and rewrite the response so refused
calls are removed and replaced by the oracle's note. Nothing refused and nothing
rewritten: the bytes pass through unchanged.

Out of scope here: TLS upstreams, gzip/deflate decoding (refused instead), the
dashboard, `decision-os run` environment wiring.

## Two approaches

1. **Typed model.** serde structs per API shape, rewrite on structs, serialize.
   Loses unknown fields and key order unless every struct carries a flatten map, and
   new item kinds (`shell_call`, future `*_call`) need code changes before they are
   gated. Rejected: fail-open on new shapes is the mistake already made once.
2. **Port the oracle on `serde_json::Value`** (`preserve_order`), same functions, same
   order of operations, same note texts. The pure core is a set of functions over
   bytes plus a `Gate` callback; I/O is a thin std-only HTTP layer on top.

Choice: 2. It keeps unknown fields, matches the oracle line by line, and lets the
vectors be generated from the oracle functions directly.

Streams: the oracle relays events live until the first tool call, then buffers to the
end of the message. Rust keeps that, as an incremental `StreamRewriter` fed with
arbitrary byte chunks. Its output must not depend on how the input was chunked.

## Failure modes (each refuses)

| Input | Result |
|---|---|
| `Content-Encoding` other than empty or `identity` (gzip, deflate, br, lists) | `unsupported_encoding`, 502, nothing delivered (oracle decodes gzip/deflate; Rust has no inflater without a new dependency) |
| JSON body that does not parse, has duplicate keys, a BOM, or is not an object | `unparseable_body`, 502 |
| `choices`, `tool_calls`, `content`, `output` of the wrong JSON type | `unparseable_body` (the oracle crashes here) |
| SSE: invalid UTF-8, a bare CR, a leading BOM, a `data:` payload that is not a JSON object (except `[DONE]`), duplicate keys | `malformed_stream`; the stream stops, an error event is written, the chunked body is not terminated |
| chat stream: a tool-call `index` that is not an integer | `malformed_stream` |
| Anthropic stream: two `content_block_start` for one index, `tool_use` inside `message_start` | `malformed_stream` |
| Responses stream: a gated item in a non-final response snapshot | `malformed_stream` |
| a chat tool call with both `function` and `custom`, or a `type` that disagrees | the call is blocked ("unrecognized format") |
| an Anthropic `tool_use` without a string name | the block is removed with a note (oracle keeps it unjudged in JSON) |
| a gated Responses item in the final `response.output` that differs from its `output_item.done` | judged separately; blocked if either is refused |
| a 2xx status other than 200 on a gated route | gated like 200 (oracle passes non-200 through) |
| decision callback refuses or errors | the call is removed with the note |

Each Rust-stricter case is a deliberate divergence, recorded with `oracle_expected`
in the vectors and in `conformance/disagreements/llm-fail-closed.json`.

## Test plan

- Vectors `conformance/vectors/llm/*.json`, generated from the oracle functions by
  `conformance/gen/llm_from_oracle.py` with a scripted gateway (fixed decisions,
  fixed note ids), covering every scenario in `tests/gateway/test_llm_proxy.py`.
  Input: shape, stream flag, encoding, upstream body, decisions. Expected: exact
  output bytes and the ordered list of gated calls, or an error code.
- `crates/dos-llm/tests/vectors.rs` runs every vector; for stream vectors it also
  feeds the input split at every byte offset and in single bytes and requires the
  same output.
- Ported oracle assertions as named Rust tests (`tests/oracle_ported.rs`).
- Fail-closed tests for every row of the table above.
- Server tests: a std-only fake upstream on 127.0.0.1, passthrough, 401 relay, 404
  route, 502 on gzip and garbage, streamed rewrite.
