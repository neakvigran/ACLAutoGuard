# Implementation and evidence status

## Verified local capabilities

- Safe YAML policy and independent requirements loading with field validation.
- Single-earlier-rule shadow analysis; joint coverage remains unsupported.
- Contradictory requirements detection.
- First-match evaluation of one concrete TCP, UDP, or ICMP flow.
- Explicitly selected host requirements checked against the policy model.
- Combined static assessment, blocking on shadows or requirement mismatches.
- Interactive and noninteractive `analyze`, `check`, and `assess` operations.
- Optional JSON static-assessment export with refusal to overwrite files.

These are local software capabilities. Automated tests are not device or traffic
evidence. A nonblocking static assessment does not establish deployment readiness.
General subnet/all-port requirement checking and joint-rule shadow detection
remain implementation work.

## Lab information needed before implementing the device adapter

Record the isolated lab platform, exact router model and software version,
available licensing, and authorized management address. Establish the managed
ACL name, interface, direction, and how proposed traffic reaches that attachment.
Keep router administration protection separate where appropriate.

Verify SSH host identity, authentication method, command privileges, and a
console or independent management path. Do not put passwords or private keys
in inventory files or reports. Specify authorized read and change operations.

Identify test hosts in Student, Staff, Server, and Management zones, how the
controller can invoke probes in each zone, destination service health checks,
capture points, and how captures and ACL counters will be collected.

Identify the device-side rollback mechanism and verify its exact semantics,
timer behavior, persistence procedure, and recovery scope before attempting a
management-loss experiment. Device-side whole-configuration rollback and
controller ACL restoration may restore different state.

## Core workflow still to implement and verify

1. Inventory and device-specific adapter with verified SSH host keys.
2. Configuration inspection and ACL attachment verification.
3. Baseline health and service controls from the correct source zones.
4. Managed configuration backup, preview, and explicit deployment confirmation.
5. Pre-armed recovery or verified independent recovery access.
6. Deployment command checking, uncertain-state handling, and configuration readback.
7. Live probes with pass, fail, and inconclusive classification.
8. Restoration, reconnection, and configuration plus traffic recovery checks.
9. Device and traffic evidence reporting, including errors and measured timings.

No SSH deployment, live traffic testing, automatic recovery, or threat-response
extension has been implemented. The optional extension begins after core acceptance.

## Requirements-to-evidence mapping

| Obligation | Current local evidence | Required lab/course evidence |
| --- | --- | --- |
| T1 Student HTTP permitted | Corrected policy model agrees; shadowed example disagrees | Healthy HTTP service control, Student probe, capture and applicable counters |
| T2 Student teaching-server SSH blocked | Corrected policy model agrees | Healthy SSH service control, Student probe, packet/counter evidence |
| T3 Student Staff HTTP blocked | Corrected policy model agrees through default deny | Staff test-service control, Student probe, packet/counter evidence |
| T4–T5 Staff teaching-server access | Requirement definitions only; not asserted against Student ACL | Staff HTTP/SSH probes as regression checks |
| T6–T7 router SSH blocked | Requirement definitions only | Verify router-local administration safeguards and source-zone probes |
| T8 Management router SSH permitted | Requirement definition only | Management SSH baseline and post-change recovery checks |
| Shadowing gate | Local automated tests and static reports | Demonstrate rejection before any device change |
| Invalid input handling | Local automated tests | Demonstrate a clear error and no device change |
| Failed/inconclusive validation recovery | Not implemented | Measured restoration and independently verified recovery |
| Lost management recovery | Platform capability unverified | Pre-armed device-side recovery or independent path, measured recovery |
| Network architecture and routing | Scenario documented; topology unverified | Working Packet Tracer `.pkt`, addressing, routing tables, explained paths |
| Packet-level validation | Not collected | Packet Tracer Simulation evidence and separate real Wireshark captures |
| Demonstration and formal report | Not verified | Reproducible demonstration, annotated captures, references, PDF report |

Host-level checks sample broader access requirements. They cannot establish all
subnet traffic restrictions or prove that only Management can administer the
router. Report these boundaries explicitly during evaluation.
