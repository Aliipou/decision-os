# Documentation index

The oracles keep their documents where they were, so every existing link and test
still works. This index groups them. Statements in oracle documents describe the
oracle at import time; where they disagree with the code, the code and tests win,
and `spec/KNOWN_GAPS.md` records the disagreement.

`SG` = `../oracle/sluicegate-py/`, `DM` = `../oracle/decision-os-min/`,
`CS` = `../oracle/contracts-spec/`.

## Normative (this repository)

- [Rewrite plan](../RUST_REWRITE.md) and [how work is run](../CLAUDE.md)
- [Known gaps](../spec/KNOWN_GAPS.md)

## Rust implementation: audit log (`dos-audit`)

- Design: [design/audit.md](../design/audit.md). Status and open decisions: [status/audit.md](../status/audit.md). Red-team results: [findings/audit.md](../findings/audit.md).
- Code: [crates/dos-audit](../crates/dos-audit/) (sink, anchor, verifier, `dos-audit verify` CLI). Vectors: [conformance/vectors/audit](../conformance/vectors/audit/).

## Requirements and conformance

- [AE-1..AE-10 profile](../oracle/contracts-spec/conformance/PROFILE.md), [claim](../oracle/contracts-spec/conformance/CLAIM.md), [taxonomy](../oracle/contracts-spec/conformance/TAXONOMY_MAP.md)
- [Composition](../oracle/contracts-spec/COMPOSITION.md), [obligations](../oracle/contracts-spec/OBLIGATIONS.md), [containment](../oracle/contracts-spec/CONTAINMENT.md), [dependency rules](../oracle/contracts-spec/DEPENDENCY_RULES.md)

## Security model

- SG: [threat model](../oracle/sluicegate-py/THREAT_MODEL.md), [threat and defense pairs](../oracle/sluicegate-py/THREAT_DEFENSE_PAIRS.md), [assumptions](../oracle/sluicegate-py/ASSUMPTIONS.md), [semantics](../oracle/sluicegate-py/SEMANTICS.md), [TCB](../oracle/sluicegate-py/TCB.md), [TCB discipline](../oracle/sluicegate-py/TCB_DISCIPLINE.md), [key management](../oracle/sluicegate-py/KEY_MANAGEMENT.md), [label propagation](../oracle/sluicegate-py/LABEL_PROPAGATION.md), [security](../oracle/sluicegate-py/SECURITY.md), [findings](../oracle/sluicegate-py/FINDINGS.md)
- DM: [security](../oracle/decision-os-min/SECURITY.md), [docs folder](../oracle/decision-os-min/docs/)

## Formal

- This repository: [formal/audit/](../formal/audit/) (Lean 4 models of the audit chain and the verdict logic).
- SG: [formal/](../oracle/sluicegate-py/formal/) (Lean 4, TLA+, Kani), [axiomatic foundation](../oracle/sluicegate-py/AXIOMATIC_FOUNDATION.md)

## Decisions and positioning

- SG: [status](../oracle/sluicegate-py/STATUS.md), [decisions](../oracle/sluicegate-py/DECISIONS.md), [non-goals](../oracle/sluicegate-py/NON_GOALS.md), [why not OPA](../oracle/sluicegate-py/WHY_NOT_OPA.md), [why not DLP](../oracle/sluicegate-py/WHY_NOT_DLP.md), [green team](../oracle/sluicegate-py/GREEN_TEAM_authgate.md), [real agent test](../oracle/sluicegate-py/REAL_AGENT_TEST.md), [MCP standardization](../oracle/sluicegate-py/MCP_STANDARDIZATION.md), [positioning](../oracle/sluicegate-py/POSITIONING.md), [prior art](../oracle/sluicegate-py/PRIOR_ART.md), [first adopter](../oracle/sluicegate-py/FIRST_ADOPTER.md)
- CS: [positioning](../oracle/contracts-spec/POSITIONING.md), [claim audit](../oracle/contracts-spec/CLAIM_AUDIT.md)

## Operations (oracle era; to be rewritten for the Rust service)

- SG: [deployment](../oracle/sluicegate-py/DEPLOYMENT.md), [infra](../oracle/sluicegate-py/INFRA.md), [disaster recovery](../oracle/sluicegate-py/DISASTER_RECOVERY.md), [incident response](../oracle/sluicegate-py/INCIDENT_RESPONSE.md), [migration](../oracle/sluicegate-py/MIGRATION.md)
- DM: [README](../oracle/decision-os-min/README.md), [infra](../oracle/decision-os-min/INFRA.md), [benchmarks](../oracle/decision-os-min/BENCHMARKS.md)

## History (not current status)

- SG: master plan, TODO, infrastructure plan, branches, industry and deployment readiness, feature freeze, changelog, comparative evaluation, team: all at the root of `oracle/sluicegate-py/`.
