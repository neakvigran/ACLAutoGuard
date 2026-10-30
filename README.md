# ACLAutoGuard

ACLAutoGuard is a two-person university project for analyzing ACL changes,
checking independent access requirements, and eventually deploying changes,
validating real traffic, and verifying recovery.

**Current stage: a working static-analysis prototype.** The tool runs locally
and sends no network traffic. SSH deployment, live traffic validation, and
rollback are not implemented yet.

## Current features

- Safe YAML loading with duplicate-key rejection and supported-field validation.
- Detection of rules fully shadowed by a single earlier rule.
- Detection of overlapping access requirements that demand opposite actions.
- First-match policy evaluation for concrete TCP, UDP, and ICMP traffic.
- Checking explicitly selected host-level requirements against a policy model.
- Combined static assessment with a blocking decision and optional JSON report.
- Interactive shell with detailed help, command/option/path completion, and
  in-session history.
- Noninteractive commands for scripts and repeatable demonstrations.

## Installation

The verified development environment is Kali Linux with Python **3.14.7**.
Package metadata requires Python 3.14 or newer; other versions and Windows
have not been verified.

```sh
git clone https://github.com/neakvigran/ACLAutoGuard.git
cd ACLAutoGuard
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e .
source .venv/bin/activate
```

If you already have the repository and `.venv`, skip cloning and environment
creation. The editable installation uses your working source files directly.
`requirements.txt` pins the development environment, including dependencies for
planned features. `pyproject.toml` declares the current runtime dependency
(PyYAML), the pinned build backend, and the executable entry point.

The examples below run from the repository root with the environment activated.
Without activation, use `.venv/bin/aclautoguard`. You can also run
`.venv/bin/python -m aclautoguard`.

## Interactive shell

Launch the application without arguments:

```sh
aclautoguard
```

```text
ACLAutoGuard | ACL analysis workspace
  Local policy analysis | No device connections
  Type help for commands and examples. Ctrl+D or exit to close.

ACLAutoGuard> help
```

| Command | Purpose | Example |
| --- | --- | --- |
| `help [command]` | Show commands, arguments, and examples | `help assess` |
| `analyze <policy-path>` | Validate a policy and detect single-rule shadows | `analyze examples/policies/shadowed.yaml` |
| `check <policy-path> <requirements-path> --ids ID [ID ...]` | Compare selected requirements with modeled decisions | `check examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3` |
| `assess <policy-path> <requirements-path> --ids ID [ID ...] [--report PATH]` | Combine shadow and requirement checks | `assess examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3` |
| `exit` | Close the shell | `exit` |

Type `help` for the complete command reference, or `help <command>` for one
command. Angle brackets mark required values; square brackets mark optional
parts. Do not type the brackets themselves. `--ids` requires one or more IDs.

### Terminal controls

- **Tab:** complete command names, help topics, options, files, and directories.
  Press Tab twice to list ambiguous matches on GNU Readline.
- **Up/Down:** recall commands from this session; no history file is written.
- **Ctrl+D:** close the shell on Linux. `exit` also closes it with code 0.
- **Ctrl+C:** cancel the current input or local command and return to the prompt.
  Close the shell with Ctrl+D on an empty input line or by typing `exit`.

Paths are relative to your current directory. Quote paths containing spaces,
for example `analyze "my policies/policy.yaml"`. Completion inserts shell-safe
quoting automatically. It completes existing paths, not requirement IDs or new
report filenames. Type a new report filename manually.

Completion requires Python Readline support, verified with GNU Readline on
Kali. Systems without Readline retain the plain input shell. Color is used
only for terminal output; launch with `NO_COLOR=1 aclautoguard` to disable it.

Findings, mismatches, and input errors leave the shell open. `check --help` and
`assess --help` also return to the prompt. Both interfaces share application
functions and result formatting.

## Noninteractive usage

```sh
aclautoguard --help
aclautoguard analyze examples/policies/shadowed.yaml
aclautoguard analyze examples/policies/corrected.yaml
aclautoguard check examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3
aclautoguard assess examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3
```

| Command | Exit 0 | Exit 1 | Exit 2 |
| --- | --- | --- | --- |
| `analyze` | No single-rule shadows found | Shadows found | Input or usage error |
| `check` | All selected modeled decisions agree | At least one mismatch | Invalid or unsupported input |
| `assess` | No blocking static findings | Shadow or requirement mismatch | Invalid input, unsupported check, or report export error |

Help exits with code 0. Exit 1 is an expected outcome for the shadowed example.
`check` reports `MATCH` or `MISMATCH`, expected and modeled actions, and the
first deciding rule or default action. `check` does not run shadow analysis.
`assess` runs both checks and blocks on any detected shadow, including
same-action redundancy.

### Expected example behavior

| Example | Selected checks | Expected result |
| --- | --- | --- |
| `corrected.yaml` | T1–T3 | All agree with the policy model; no single-rule shadows |
| `shadowed.yaml` | T1 | HTTP permission is shadowed by `rule_10`; T1 disagrees with modeled deny |

These results concern the supplied policy model. They do not establish actual
connectivity or that a router applies the policy to the selected traffic.

## Static assessment reports

Append `--report PATH` to `assess` in either interface:

```sh
aclautoguard assess examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3 --report "static evidence.json"
```

The JSON report contains a UTC creation time, shadow findings, selected
requirement results, blocking status, and limitations. The parent directory
must exist. Existing files are never overwritten; use a fresh path for each
run. Export failure produces CLI exit code 2 and leaves the shell open.

These reports contain static analysis only. Live traffic, deployment, and
recovery evidence remain future work. Review generated reports before sharing;
the repository ignores `reports/`, `captures/`, `backups/`, and `logs/`.
The root-level report filename above is not ignored automatically.

## Supported inputs and limitations

Policies use the project's YAML schema, rather than native router ACL syntax.
See [shadowed](examples/policies/shadowed.yaml) and
[corrected](examples/policies/corrected.yaml) examples. Supported policy fields
include ordered permit/deny rules, strict IPv4 CIDRs, `ip`/`tcp`/`udp`/`icmp`,
and an optional TCP/UDP destination port from 1 to 65535. The default action
must be deny. Missing TCP/UDP ports mean all destination ports.

Independent requirements describe intended access separately from proposed
ACLs. See the [format](docs/REQUIREMENTS_FORMAT.md) and
[T1–T8 baseline](examples/requirements/baseline.yaml). Requirement order gives
no precedence; contradictory overlapping expectations are rejected by checking.

Current boundaries:

- Several earlier rules jointly shadowing a later rule are not detected.
- A covering rule may itself be shadowed; it need not decide packet actions.
- Requirement checking supports `/32` endpoints with TCP/UDP and a specific
  destination port, or ICMP. Broader selected checks are rejected.
- `--ids` explicitly selects applicable requirements. It does not establish
  network paths or ACL attachment. Unselected requirements are not evaluated.
- T1–T3 are intended Student traffic ACL checks. T4–T8 require separate path
  and safeguard analysis; one Student ACL must not be assumed to enforce them.
- IPv6, source-port conditions, port ranges, object groups, and advanced ACL
  syntax are outside the supported subset.
- A nonblocking assessment does not prove security, broad access compliance,
  baseline health, recovery readiness, or deployment safety.

## Python API

Interfaces reuse functions in `aclautoguard.application`:

```python
from aclautoguard.application import assess_policy

assessment = assess_policy(
    "examples/policies/corrected.yaml",
    "examples/requirements/baseline.yaml",
    requirement_ids=["T1", "T2", "T3"],
)
print("Blocked:", assessment.blocked)
for result in assessment.requirement_results:
    print(result.requirement_id, result.expected_action, result.decision, result.satisfied)
```

`analyze_policy(path)` returns shadow findings. `check_policy_requirements(...)`
returns selected requirement results without shadow analysis. `assess_policy(...)`
returns both. Invalid input raises `PolicyError`, `RequirementsError`, or
`RequirementCheckError`; a modeled mismatch is returned as a result.

Lower-level APIs include `load_policy`, `load_requirements`,
`find_requirement_conflicts`, `evaluate_connection`, and `check_host_requirements`.
The evaluator returns `Decision(action, matched_rule_id)`, where a `None` ID
identifies the default action. Its concrete traffic input accepts individual
IPv4 addresses and TCP/UDP with a port, or ICMP without one. Policy `ip` is a
wildcard, not a concrete traffic protocol. Invalid concrete input raises
`aclautoguard.evaluator.ConnectionError`.

## Verification

```sh
.venv/bin/python -m pytest -x -q
```

The current suite has **312 passing tests** at the latest verification. These
check local software behavior, not router interaction or real network traffic.

## Remaining project work

The core still needs device inventory and setup, a verified router adapter,
configuration inspection and backup, deployment preview and confirmation,
command checking and readback, baseline/service controls, probes from the
correct zones, verified restoration, and runtime evidence reports.

Router model, software, licensing, management access, topology, and recovery
capabilities must be verified before device experiments. Management-loss
recovery requires proven device-side rollback or an independent management
path. The optional suspicious-traffic detection and temporary-blocking
extension begins after core acceptance.

Course deliverables also include a working Packet Tracer `.pkt`, Packet Tracer
Simulation evidence, separate real Wireshark captures, a demonstration, and a
PDF report. Packet Tracer simulated traffic is not directly captured by
Wireshark.

See [project scope](docs/PROJECT_SCOPE.md) and
[implementation/evidence status](docs/IMPLEMENTATION_STATUS.md) for remaining
work, lab prerequisites, and the requirements-to-evidence mapping.
