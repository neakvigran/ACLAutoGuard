# Independent access requirements: version 1 design

This document defines the initial input contract for future requirement checking.
`aclautoguard.requirements.load_requirements(path)` implements safe loading and
structural and field validation, raising `RequirementsError` on invalid input.
It preserves entries without evaluating their semantic conflicts or ACL behavior.
`aclautoguard.requirements_analysis.find_requirement_conflicts(document)` accepts
the validated document and returns every overlapping pair with opposite expected
actions as `RequirementConflict(first_id, second_id)`. It does not modify input.
Host-level ACL requirement checking is available through
`aclautoguard.requirement_checker.check_host_requirements`, with mandatory explicit
selection of applicable requirement IDs. It supports `/32` endpoints, TCP/UDP
with a specific destination port, and ICMP. Broader selected requirements are
rejected. Any contradictory pair in the document blocks checking, including
unselected pairs. Results compare modeled actions only. The current `analyze`
command accepts policy files only.

Requirements describe intended access and must be reviewed separately from ACL
rules. Do not generate expected outcomes from the policy under test: that would
allow a faulty policy to define its own success criteria.

## File structure

See [the baseline example](../examples/requirements/baseline.yaml).

| Top-level field | Meaning |
| --- | --- |
| `schema_version` | Integer `1`; booleans are invalid |
| `name` | Nonempty string identifying the requirement set |
| `requirements` | Nonempty list of requirement mappings |

| Requirement field | Meaning |
| --- | --- |
| `id` | Unique nonempty string with no surrounding whitespace |
| `expected_action` | `permit` or `deny` |
| `protocol` | `ip`, `tcp`, `udp`, or `icmp` |
| `source` | Strict IPv4 CIDR; use `/32` for one host |
| `destination` | Strict IPv4 CIDR; use `/32` for one host |
| `destination_port` | Optional integer 1–65535, for TCP/UDP only |

All listed fields except `destination_port` are required. Unknown fields and
duplicate YAML keys are to be rejected. Loading must use safe YAML semantics.
IPv6, source-port conditions, port ranges, and advanced ACL syntax are outside
this initial format.

`ip` means all IPv4 protocols. A missing TCP/UDP destination port means all
destination ports. A requirement applies to every packet matching its specified
conditions. Passing a few probes cannot establish that an entire subnet or
all-port requirement holds.

Requirements have no first-match ordering and no default action. Every
requirement is an independent obligation; reordering cannot resolve contradictory
expectations. The conflict detector reports overlapping contradictory requirements
as input conflicts rather than silently selecting one. It compares both address
networks, protocol, and destination port. Same-action overlaps are consistent
and are not reported. An empty conflict list does not prove that an ACL meets
the requirements.

## Baseline samples and future evidence

The example records the eight host-level checks from the project scenario.
Addresses are proposals for the isolated lab, pending topology verification.

| ID | Connection | Expected | Planned evidence role |
| --- | --- | --- | --- |
| T1 | Student → Teaching server TCP 80 | Permit | Student traffic ACL validation |
| T2 | Student → Teaching server TCP 22 | Deny | Student traffic ACL validation |
| T3 | Student → Staff test server TCP 80 | Deny | Student traffic ACL validation |
| T4 | Staff → Teaching server TCP 80 | Permit | Regression check outside Student ACL path |
| T5 | Staff → Teaching server TCP 22 | Permit | Regression check outside Student ACL path |
| T6 | Student → Student router gateway TCP 22 | Deny | Router administration protection |
| T7 | Staff → Staff router gateway TCP 22 | Deny | Router administration protection |
| T8 | Management → Management router address TCP 22 | Permit | Management access regression check |

These roles are design intentions. Verify ACL attachment, routing paths, and
router-local traffic handling before assigning checks to a deployed ACL.
Administration protection may use a separate manually configured access ACL.
One Student-interface policy must not be treated as enforcing every row.
The future checker will need explicit policy applicability; this file alone
does not establish which ACL a connection traverses.

The broader requirements remain in [project scope](PROJECT_SCOPE.md): Students
cannot access the Staff network and only Management may administer the router.
T1–T8 sample these requirements; they do not exhaustively establish them.

Later evidence should reference these stable IDs and record the applied policy,
test source, observed outcome, service-health controls, applicable counters or
captures, and any recovery verification. No network tests or evidence collection
are performed by this example. A failed TCP connection alone does not prove an
ACL blocked it; runtime results must allow pass, fail, and inconclusive outcomes.
