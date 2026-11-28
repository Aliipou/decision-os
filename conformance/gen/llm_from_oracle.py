"""Generate conformance/vectors/llm/*.json from the frozen oracle model gateway.

Run from the repo root:  python -I conformance/gen/llm_from_oracle.py [out_dir]

Every case runs through the oracle functions in
oracle/decision-os-min/decision_os_min/gateway/llm_proxy.py (gate_* for JSON bodies,
stream_* for SSE) with a scripted gateway: fixed decisions per tool name, and note
ids msg_dos_<n as 20 hex digits> counting from 1 in each case. The fixtures are the
ones in oracle/decision-os-min/tests/gateway/test_llm_proxy.py.

Vector input:  {shape, stream, body | body_b64, content_encoding?, model?, decisions}
  decisions: {tool: {"allow": true} | {"deny": reason} | {"output": {...}}};
  a tool not listed is denied with reason "no decision in vector".
Vector expected: {"ok": {"body": <client bytes as text>, "calls": [[tool, args], ...]}}
  or {"error": "unsupported_encoding" | "unparseable_body" | "malformed_stream"}.
`expected` is what the spec requires (design/llm.md). Where the oracle differs on
purpose, `oracle_expected` holds what the oracle does.
"""

from __future__ import annotations

import base64
import copy
import gzip
import io
import json
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "oracle" / "decision-os-min"))

from decision_os_min.gateway import llm_proxy as lp  # noqa: E402

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "conformance" / "vectors" / "llm"
TEST = "oracle tests/gateway/test_llm_proxy.py"


class _Res:
    def __init__(self, executed, output, reason):
        self.executed, self.output, self.reason = executed, output, reason


class FakeGateway:
    def __init__(self, decisions):
        self.decisions = decisions
        self.calls = []

    def govern(self, *, server, tool, arguments, model, release):
        assert server == "llm"
        self.calls.append([tool, copy.deepcopy(arguments)])
        d = self.decisions.get(tool, {"deny": "no decision in vector"})
        if "deny" in d:
            return _Res(False, None, d["deny"])
        if "output" in d:
            return _Res(True, copy.deepcopy(d["output"]), "")
        return _Res(True, release(arguments), "")


class _Uuid:
    def __init__(self):
        self.n = 0

    def uuid4(self):
        self.n += 1
        n = self.n

        class U:
            hex = f"{n:020x}" + "0" * 12

        return U()


def run_oracle(case):
    """What the oracle gateway sends the client, as {"ok": ...} or {"error": ...}."""
    lp.uuid = _Uuid()
    gw = FakeGateway(case["decisions"])
    judge = lp.ToolCallJudge(gw, case.get("model"))
    raw = case["raw"]
    enc = (case.get("content_encoding") or "identity").lower().strip()
    if enc not in ("", "identity"):
        try:
            if enc in ("gzip", "x-gzip"):
                raw = zlib.decompress(raw, 16 + zlib.MAX_WBITS)
            elif enc == "deflate":
                raw = zlib.decompress(raw)
            else:
                raise ValueError(enc)
        except (zlib.error, ValueError):
            return {"error": "unsupported_encoding"}
    shape = case["shape"]
    try:
        if not case["stream"]:
            try:
                parsed = json.loads(raw)
            except ValueError:
                return {"error": "unparseable_body"}
            gate = {
                "chat": lp.gate_chat_completion,
                "anthropic": lp.gate_anthropic_message,
                "responses": lp.gate_responses_body,
            }[shape]
            out = json.dumps(gate(parsed, judge), ensure_ascii=False).encode("utf-8")
        else:
            chunks = []
            streamer = {
                "chat": lp.stream_chat,
                "anthropic": lp.stream_anthropic,
                "responses": lp.stream_responses,
            }[shape]
            streamer(io.BytesIO(raw), chunks.append, judge)
            out = b"".join(chunks)
    except Exception as exc:  # the oracle crashed: the client gets no response
        return {"error": "oracle_exception", "detail": type(exc).__name__}
    return {"ok": {"body": out.decode("utf-8"), "calls": gw.calls}}


# ------------------------------------------------------------------ fixtures
# Copied from tests/gateway/test_llm_proxy.py.


def chat_tool_message():
    return {
        "id": "c1",
        "object": "chat.completion",
        "model": "gpt-x",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "t1",
                            "type": "function",
                            "function": {"name": "get_weather", "arguments": '{"city":"Oulu"}'},
                        },
                        {
                            "id": "t2",
                            "type": "function",
                            "function": {"name": "delete_repo", "arguments": '{"repo":"me/x"}'},
                        },
                    ],
                },
            }
        ],
    }


def chat_stream(allowed_only=False):
    base = {"id": "c2", "object": "chat.completion.chunk", "created": 1, "model": "gpt-x"}
    ev = [
        {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {"content": "Let me check."}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "t1", "type": "function", "function": {"name": "get_weather", "arguments": ""}}]}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"city":'}}]}, "finish_reason": None}]},
        {**base, "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '"Oulu"}'}}]}, "finish_reason": None}]},
    ]
    if not allowed_only:
        ev += [
            {**base, "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 1, "id": "t2", "type": "function", "function": {"name": "delete_repo", "arguments": '{"repo":"me/x"}'}}]}, "finish_reason": None}]},
        ]
    ev += [
        {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
        {**base, "choices": [], "usage": {"prompt_tokens": 5, "completion_tokens": 7}},
    ]
    return b"".join(f"data: {json.dumps(e)}\n\n".encode() for e in ev) + b"data: [DONE]\n\n"


def anthropic_message(tool="Bash", tool_input=None):
    return {
        "id": "m1",
        "type": "message",
        "role": "assistant",
        "model": "claude-x",
        "stop_reason": "tool_use",
        "content": [
            {"type": "text", "text": "Cleaning up."},
            {"type": "tool_use", "id": "tu1", "name": tool, "input": tool_input or {"command": "rm -rf /"}},
        ],
    }


def anthropic_stream(tool="Bash", tool_input='{"command": "rm -rf /"}'):
    def e(t, d):
        return f"event: {t}\ndata: {json.dumps({'type': t, **d})}\n\n".encode()

    half = len(tool_input) // 2
    return b"".join(
        [
            e("message_start", {"message": {"id": "m2", "type": "message", "role": "assistant", "content": [], "model": "claude-x", "stop_reason": None}}),
            e("content_block_start", {"index": 0, "content_block": {"type": "text", "text": ""}}),
            e("content_block_delta", {"index": 0, "delta": {"type": "text_delta", "text": "On it."}}),
            e("content_block_stop", {"index": 0}),
            e("content_block_start", {"index": 1, "content_block": {"type": "tool_use", "id": "tu2", "name": tool, "input": {}}}),
            e("content_block_delta", {"index": 1, "delta": {"type": "input_json_delta", "partial_json": tool_input[:half]}}),
            e("ping", {}),
            e("content_block_delta", {"index": 1, "delta": {"type": "input_json_delta", "partial_json": tool_input[half:]}}),
            e("content_block_stop", {"index": 1}),
            e("message_delta", {"delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 9}}),
            e("message_stop", {}),
        ]
    )


def responses_body():
    return {
        "id": "r1",
        "object": "response",
        "output": [
            {"type": "function_call", "id": "fc1", "call_id": "c1", "name": "delete_repo", "arguments": '{"repo":"a"}'},
            {"type": "function_call", "id": "fc2", "call_id": "c2", "name": "get_weather", "arguments": '{"city":"Oulu"}'},
        ],
    }


def responses_stream(out=None):
    out = out if out is not None else responses_body()["output"]
    seq = iter(range(100))

    def e(t, d):
        return f"event: {t}\ndata: {json.dumps({'type': t, 'sequence_number': next(seq), **d})}\n\n".encode()

    chunks = [e("response.created", {"response": {"id": "r2", "output": []}})]
    for i, item in enumerate(out):
        chunks += [
            e("response.output_item.added", {"output_index": i, "item": {**item, "arguments": ""}}),
            e("response.function_call_arguments.delta", {"output_index": i, "item_id": item["id"], "delta": item["arguments"]}),
            e("response.output_item.done", {"output_index": i, "item": item}),
        ]
    chunks.append(e("response.completed", {"response": {"id": "r2", "output": out}}))
    return b"".join(chunks)


def custom_chat_message():
    body = chat_tool_message()
    body["choices"][0]["message"]["tool_calls"] = [
        {"id": "c1", "type": "custom", "custom": {"name": "delete_repo", "input": "me/x"}},
        {"id": "c2", "type": "custom", "custom": {"name": "get_weather", "input": "Oulu"}},
        {"id": "c3", "type": "mystery", "mystery": {"payload": 1}},
    ]
    return body


def shell_body():
    return {
        "id": "r9",
        "object": "response",
        "output": [
            {"type": "shell_call", "id": "s1", "call_id": "x", "action": {"commands": ["rm -rf /"]}},
            {"type": "web_search_call", "id": "w1", "status": "completed"},
        ],
    }


def streamed_custom_calls():
    base = {"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "gpt-x"}

    def ch(delta, fin=None):
        return f"data: {json.dumps({**base, 'choices': [{'index': 0, 'delta': delta, 'finish_reason': fin}]})}\n\n"

    return (
        "".join(
            [
                ch({"role": "assistant", "tool_calls": [{"index": 0, "id": "a", "type": "custom", "custom": {"name": "get_weather", "input": "Ou"}}]}),
                ch({"tool_calls": [{"index": 0, "custom": {"input": "lu"}}]}),
                ch({"tool_calls": [{"index": 1, "id": "b", "type": "custom", "custom": {"name": "delete_repo", "input": "me/x"}}]}),
                ch({}, "tool_calls"),
            ]
        ).encode()
        + b"data: [DONE]\n\n"
    )


def j(obj):
    return json.dumps(obj).encode()


POLICY = {
    "get_weather": {"allow": True},
    "delete_repo": {"deny": "repos are not deleted by agents"},
    "send_email": {"output": {"to": "a@b.c", "password": "[REDACTED]"}},
    "Bash": {"deny": "guardrail: recursive delete of / or home"},
    "shell": {"deny": "guardrail: recursive delete of / or home"},
}
ALLOW_ALL = {k: {"allow": True} for k in ("get_weather", "delete_repo", "Bash", "shell", "send_email")}

# (name, shape, stream, raw bytes, decisions, extra, source)
CASES = [
    ("chat-json-deny-one-keep-one", "chat", False, j(chat_tool_message()), POLICY, {},
     f"{TEST}::test_chat_completion_drops_denied_call_keeps_allowed"),
    ("chat-json-all-allowed-passthrough", "chat", False, j(chat_tool_message()), ALLOW_ALL, {},
     "spec: byte-identical when nothing is refused (oracle re-serializes)"),
    ("chat-stream-deny-after-first-tool-call", "chat", True, chat_stream(), POLICY, {},
     f"{TEST}::test_chat_stream_rewrites_only_after_the_first_tool_call"),
    ("chat-stream-all-allowed-byte-identical", "chat", True, chat_stream(True), POLICY, {},
     f"{TEST}::test_chat_stream_all_allowed_is_byte_identical"),
    ("anthropic-json-guardrail-blocks-bash", "anthropic", False, j(anthropic_message()), POLICY, {"model": "claude-x"},
     f"{TEST}::test_anthropic_guardrail_blocks_catastrophic_bash"),
    ("anthropic-json-allowed-passthrough", "anthropic", False, j(anthropic_message("Bash", {"command": "ls"})), ALLOW_ALL, {"model": "claude-x"},
     f"{TEST}::test_interactive_approval_through_the_model_gateway (approved)"),
    ("anthropic-stream-block-and-reindex", "anthropic", True, anthropic_stream(), POLICY, {"model": "claude-x"},
     f"{TEST}::test_anthropic_stream_block_and_reindex"),
    ("anthropic-stream-limit-rewrites-arguments", "anthropic", True,
     anthropic_stream("send_email", '{"to": "a@b.c", "password": "hunter2"}'), POLICY, {"model": "claude-x"},
     f"{TEST}::test_anthropic_stream_limit_rewrites_arguments"),
    ("anthropic-stream-allowed-byte-identical", "anthropic", True, anthropic_stream("Bash", '{"command": "ls"}'), ALLOW_ALL, {"model": "claude-x"},
     "spec: byte-identical when nothing is refused"),
    ("anthropic-json-limit-rewrites-input", "anthropic", False,
     j(anthropic_message("send_email", {"to": "a@b.c", "password": "hunter2"})), POLICY, {"model": "claude-x"},
     "oracle gate_anthropic_message LIMIT path"),
    ("responses-json-deny-one", "responses", False, j(responses_body()), POLICY, {},
     f"{TEST}::test_responses_non_stream_and_stream (non-stream)"),
    ("responses-json-all-allowed-passthrough", "responses", False, j(responses_body()), ALLOW_ALL, {},
     "spec: byte-identical when nothing is refused (oracle re-serializes)"),
    ("responses-stream-deny-one", "responses", True, responses_stream(), POLICY, {},
     f"{TEST}::test_responses_non_stream_and_stream (stream)"),
    ("responses-stream-all-allowed-byte-identical", "responses", True, responses_stream(), ALLOW_ALL, {},
     "spec: byte-identical when nothing is refused"),
    ("responses-stream-limit-rewrites-arguments", "responses", True,
     responses_stream([{"type": "function_call", "id": "fc1", "call_id": "c1", "name": "send_email",
                        "arguments": '{"to": "a@b.c", "password": "hunter2"}'}]), POLICY, {},
     "oracle stream_responses transformed-item path"),
    ("chat-json-custom-and-unknown-tool-calls", "chat", False, j(custom_chat_message()), POLICY, {},
     f"{TEST}::test_custom_and_unknown_chat_tool_calls"),
    ("chat-json-gzip-refused", "chat", False, gzip.compress(j(chat_tool_message()), mtime=0), POLICY,
     {"content_encoding": "gzip", "rust": {"error": "unsupported_encoding"}},
     f"{TEST}::test_gzip_upstream_is_decoded_and_gated; Rust refuses (no inflater, fail closed)"),
    ("chat-json-brotli-refused", "chat", False, b"\x0b\x02\x80{}\x03", POLICY, {"content_encoding": "br"},
     "spec: fail closed on unknown encodings"),
    ("chat-json-garbage-refused", "chat", False, b"{not json", POLICY, {},
     f"{TEST}::test_unparseable_model_response_is_not_delivered"),
    ("responses-json-shell-call-gated-server-tools-pass", "responses", False, j(shell_body()), POLICY, {},
     f"{TEST}::test_responses_shell_call_is_gated_server_tools_pass"),
    ("chat-stream-custom-tool-calls", "chat", True, streamed_custom_calls(), POLICY, {},
     f"{TEST}::test_streamed_custom_tool_calls"),
    ("chat-json-legacy-function-call-denied", "chat", False,
     j({"id": "c3", "object": "chat.completion", "choices": [{"index": 0, "finish_reason": "function_call",
        "message": {"role": "assistant", "content": None,
                    "function_call": {"name": "delete_repo", "arguments": '{"repo":"me/x"}'}}}]}),
     POLICY, {}, "oracle gate_chat_completion legacy function_call path"),
    ("chat-json-limit-rewrites-arguments", "chat", False,
     j({"id": "c4", "object": "chat.completion", "choices": [{"index": 0, "finish_reason": "tool_calls",
        "message": {"role": "assistant", "content": None, "tool_calls": [
            {"id": "t1", "type": "function",
             "function": {"name": "send_email", "arguments": '{"to": "a@b.c", "password": "hunter2"}'}}]}}]}),
     POLICY, {}, "oracle gate_chat_completion LIMIT path"),
    ("chat-stream-unparseable-chunk-refused", "chat", True,
     b'data: {"id":"x","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"t","type":"function","function":{"name":"delete_repo","arguments":"{}"}}]},"finish_reason":null}],"z":NaN}\n\n'
     b"data: [DONE]\n\n",
     POLICY, {"rust": {"error": "malformed_stream"}},
     "red team: Python clients parse NaN, the oracle relays the unparseable chunk raw; Rust fails closed"),
    ("chat-json-duplicate-keys-refused", "chat", False,
     b'{"id":"d","choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}],'
     b'"choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}',
     POLICY, {"rust": {"error": "unparseable_body"}},
     "spec: an ambiguous body is refused (a first-wins client would read another body)"),
    ("responses-stream-tool-call-only-in-completed", "responses", True,
     b'event: response.created\ndata: {"type":"response.created","sequence_number":0,"response":{"id":"r3","output":[]}}\n\n'
     b'event: response.completed\ndata: {"type":"response.completed","sequence_number":1,"response":{"id":"r3","output":'
     b'[{"type":"function_call","id":"fc1","call_id":"c1","name":"delete_repo","arguments":"{\\"repo\\":\\"a\\"}"}]}}\n\n',
     POLICY, {"rust_body": True},
     "red team: a call present only in response.completed is relayed ungated by the oracle"),
]


def vector(name, shape, stream, raw, decisions, extra, source):
    case = {"shape": shape, "stream": stream, "raw": raw, "decisions": decisions, **extra}
    inp = {"shape": shape, "stream": stream}
    try:
        inp["body"] = raw.decode("utf-8")
    except UnicodeDecodeError:
        inp["body_b64"] = base64.b64encode(raw).decode()
    if extra.get("content_encoding"):
        inp["content_encoding"] = extra["content_encoding"]
    if extra.get("model"):
        inp["model"] = extra["model"]
    inp["decisions"] = decisions
    oracle = run_oracle(case)
    expected = oracle
    if "rust" in extra:
        expected = extra["rust"]
    elif not stream and "ok" in oracle:
        # Nothing refused or rewritten: the client gets the upstream bytes unchanged.
        if json.loads(oracle["ok"]["body"]) == json.loads(raw):
            expected = {"ok": {"body": raw.decode("utf-8"), "calls": oracle["ok"]["calls"]}}
    v = {"v": 1, "area": "llm", "name": name, "input": inp, "expected": expected}
    if extra.get("rust_body"):
        v["expected"] = None  # filled in by hand below
    if expected != oracle:
        v["oracle_expected"] = oracle
    v["source"] = source
    return v


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for c in CASES:
        v = vector(*c)
        if v["expected"] is None:
            v["expected"] = HAND[v["name"]](v)
        (OUT / f"{v['name']}.json").write_text(
            json.dumps(v, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
        )


def _only_in_completed(v):
    # Rust gates the call it finds in the final response and drops it, adding the note.
    note = {
        "type": "message",
        "id": "msg_dos_00000000000000000001",
        "status": "completed",
        "role": "assistant",
        "content": [{"type": "output_text",
                     "text": "[Decision OS] Blocked the `delete_repo` tool call: repos are not deleted by agents",
                     "annotations": []}],
    }
    body = (
        'event: response.created\ndata: {"type":"response.created","sequence_number":0,"response":{"id":"r3","output":[]}}\n\n'
        + "event: response.output_item.added\ndata: "
        + json.dumps({"type": "response.output_item.added", "output_index": 0, "item": {**note, "status": "in_progress"}, "sequence_number": 1}, ensure_ascii=False)
        + "\n\nevent: response.output_item.done\ndata: "
        + json.dumps({"type": "response.output_item.done", "output_index": 0, "item": note, "sequence_number": 2}, ensure_ascii=False)
        + "\n\nevent: response.completed\ndata: "
        + json.dumps({"type": "response.completed", "sequence_number": 3, "response": {"id": "r3", "output": [note]}}, ensure_ascii=False)
        + "\n\n"
    )
    return {"ok": {"body": body, "calls": [["delete_repo", {"repo": "a"}]]}}


HAND = {"responses-stream-tool-call-only-in-completed": _only_in_completed}

if __name__ == "__main__":
    main()
