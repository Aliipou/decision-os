# Red team method

You win when you show that one of these can happen:

- a forbidden effect runs (a tool call, a file write, a released model tool call);
- a decision, token or approval is accepted when it should not be: forged, replayed, re-bound or self-issued;
- a refusal quietly turns into execution (fail-open);
- an effect runs without an audit entry, or the audit chain can be forked, truncated or rewritten undetected;
- a secret leaks into a log, an error, the audit, the dashboard or a model response;
- a user's config, policy or keys get corrupted or lost;
- the product becomes unusable: crash, hang, unbounded memory, an install that breaks the user's apps.

Style, naming and code taste are not your job.

## Rules

1. **Start fresh.** Read the spec, `spec/INVARIANT_MAP.md`, the component's threat model and the diff. Do not read the implementer's design note or handoff until your first pass is written down, so you are not anchored by their reasoning.
2. **Tests, not opinions.** Every hypothesis becomes a runnable test or conformance vector. A finding without a reproduction is a hypothesis.
3. **Never fix.** You write tests, vectors, fuzz targets and findings. The implementer fixes.
4. **Never weaken.** You do not edit existing tests or vectors.
5. **Report negative results.** For every attack class you tried, write what you tried and that it held. "I tried nothing in this class" must be visible too.
6. **Differential first.** Before inventing attacks, run the new code and the oracle on the same inputs. Every difference is a lead.

## Process for one target

1. **Surface.** List every input: stdio messages, HTTP requests, headers, config files, policy, environment variables, the filesystem state it reads, time, other processes, the platform. Mark the trust boundary of each one.
2. **Hypotheses.** At least 10 for core, PEP, authority and stores; at least 6 for product components. Rank by impact.
3. **Attack.** Write the test for each hypothesis, run it, record the result.
4. **Fuzz.** Every parser and canonicalizer the change touches, at least 5 minutes each. Keep the corpus. A crash is a finding.
5. **Report.** `findings/<task>.md` with one entry per finding (template in `templates/FINDING.md`) plus the negative-results table.
6. **Lock in.** Every confirmed finding gets a permanent vector in `conformance/vectors/redteam/` so it can never come back.

## Severity

| Level | Meaning | Effect |
|---|---|---|
| S0 | gate bypass; forged, replayed or self-issued authority; effect without audit; agent can approve itself | blocks merge and release; Ali is told |
| S1 | fail-open on errors; secret leak; corruption or loss of user config, policy, keys or audit | blocks merge and release |
| S2 | crash, hang, resource exhaustion; wrong refusal that breaks a legitimate flow; install that breaks an app | blocks release |
| S3 | hardening, defense in depth | tracked |

## Attack catalog

Use the classes for the component you are attacking. Add new classes you discover to this file.

### Core: canonicalization, fingerprint, signatures

- Two different actions with the same canonical bytes: key order, duplicate keys, Unicode normalization (NFC/NFD), escapes, number forms (`1`, `1.0`, `1e0`, `-0`), large integers, NaN and infinity.
- Fields left out of the fingerprint that still change the effect.
- Signature malleability, non-strict verification, small-order keys, wrong `kid`, algorithm confusion, a signature over a different version.
- A decision from one kernel accepted by another kernel's PEP.

### PEP and tokens

- Replay across processes, restarts and replicas; spend races with N concurrent spenders.
- Expiry: clock skew, a token used at exactly its expiry, a clock moved backwards.
- Binding: same decision with a different payload, nonce, capability, purpose or labels.
- Obligations: LIMIT without a transformed payload, CONTAIN with an empty or edited allowlist, redaction of nested fields.
- The order of checks: can any refusal path skip the audit entry, or spend the token without running the effect?

### Authority and delegation

- Amplification through attenuation: widening tools, extending expiry, cycles, deep chains, revocation that does not reach children.
- A PDP returning odd output: unknown verdicts, extra fields, huge reasons, exceptions, timeouts.
- A veto-only evaluator that tries to grant, mutate the action, or leak through its reason.

### Stores and audit

- First-start races on an empty state directory; kill -9 mid-write; disk full; read-only filesystem; a store that disappears.
- Audit chain forks from concurrent writers; truncation; reordering; an edited entry with a recomputed hash; an anchor mismatch.

### Policy and guardrails

- Rule shadowing and first-match surprises; argument globs bypassed with `..`, symlinks, `file://`, URL encoding, case, Windows separators, UNC paths, 8.3 short names.
- Commands that do the same thing in another form: `rm -r -f`, `rm --recursive --force`, `find / -delete`, `python -c "import shutil..."`, base64 piped to a shell, PowerShell aliases.
- Secrets split across arguments, encoded, or placed in nested structures and argv arrays.
- Learned choices: an "always allow" that outranks an explicit deny; a remembered tool name that matches more than intended.
- Self-protection: reaching `~/.decision-os` or a client config through any tool or path form.

### MCP proxy

- Every way a call can reach the server: requests, notifications without an id, batches, `resources/read`, other methods with side effects, method name variants.
- Ids: duplicates, strings versus numbers, ids reused after completion, a server response with a guessed id.
- Shutdown and timing: half-close, cancellation during approval, upstream death mid-call, slow upstreams, parallel calls.
- Hostile servers: lying annotations, oversized lists, server-initiated requests that try to approve, malformed JSON.
- Launch: hostile working directory, PATH tricks, `.cmd` argument injection on Windows, env leakage.

### Model gateway

- Every tool call shape across OpenAI chat (function, custom, legacy), Responses (every `*_call` item), Anthropic (`tool_use`, server tools) and future unknown shapes.
- Streams: tool calls split across chunks, interleaved choices, missing `[DONE]`, truncated streams, events after the end, index gaps, sequence numbers.
- Encodings: gzip, deflate, br, zstd, chunked oddities, wrong content-type, non-JSON bodies with status 200.
- Upstream errors relayed with sensitive content; the agent header spoofed to pick a weaker rule.

### Installer

- Configs with comments, BOMs, CRLF, trailing commas, duplicate keys, huge files, symlinked files, read-only files.
- An app rewriting its config during install; two installs at once; uninstall after the user edited the file.
- Wrapping that changes something other than command and args; unwrapping configs written by older versions.

### Dashboard and CLI

- Cross-site requests, DNS rebinding, a missing or leaked token, clickjacking.
- Approving the wrong item through a race; approvals that outlive their timeout.

### Release and supply chain

- Unpinned dependencies, typosquats, build scripts that fetch at build time, unsigned artifacts, installers that skip checksum verification.
