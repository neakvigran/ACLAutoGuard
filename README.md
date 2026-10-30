# ACLAutoGuard

University project for ACL analysis and a planned deployment, traffic-validation,
and verified-recovery workflow. Current functionality validates YAML policies
and detects rules fully shadowed by a single earlier rule. Router deployment
and traffic validation are not implemented.

## Install for development

Use Python 3.14 (verified with 3.14.7). From the repository root:

```sh
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -e .
```

Skip environment creation when `.venv` already exists. The editable installation
keeps the command connected to your working source files. Packaging declares
the current runtime dependency, PyYAML; `requirements.txt` pins the development
environment, including tools reserved for later project stages. The build
backend is pinned separately in `pyproject.toml`.

## Run the current CLI

From the repository root, using the existing virtual environment:

```sh
.venv/bin/aclautoguard --help
.venv/bin/aclautoguard analyze examples/policies/shadowed.yaml
.venv/bin/aclautoguard analyze examples/policies/corrected.yaml
```

After activating the environment with `source .venv/bin/activate`, you can use
`aclautoguard` directly. `python -m aclautoguard` is also supported. Policy paths
are resolved relative to your current directory.

Quote paths containing spaces, for example `analyze "my policies/policy.yaml"`.
Noninteractive exit codes are 0 for no detected shadows, 1 for detected shadows, and 2 for
input or usage errors. Help exits with 0.

Check explicitly selected host requirements against a policy model:

```sh
.venv/bin/aclautoguard check examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3
```

For `check`, exit 0 means all selected modeled decisions agree, 1 means at least
one mismatch, and 2 means invalid or unsupported input. Each result shows
`MATCH` or `MISMATCH`, expected and modeled actions, and the deciding rule or
default action. These are static comparisons; no packets are sent. Selecting IDs
asserts that this policy applies to their traffic; routing and ACL attachment
remain unverified. Unselected requirements are not evaluated. Run `analyze`
separately for shadow findings. The interactive shell supports the same `check`
syntax, including explicit `--ids` selection.

The analyzer does not check several earlier rules jointly covering a later
rule. No findings does not prove security or compliance with access requirements.
A covering rule may itself be shadowed; it does not necessarily decide packet
actions. See [project scope](docs/PROJECT_SCOPE.md) for planned work and boundaries.

The [independent requirements format](docs/REQUIREMENTS_FORMAT.md) and
[T1–T8 baseline example](examples/requirements/baseline.yaml) define the next
input contract. Safe requirements loading and field validation are available
through `aclautoguard.requirements.load_requirements`. On a validated document,
`aclautoguard.requirements_analysis.find_requirement_conflicts` detects overlapping
requirements that demand opposite actions. Host-level ACL requirement checking
is available through `check` and the Python API below. The `analyze` command
continues to accept policy files only.

The Python API `aclautoguard.evaluator.evaluate_connection` evaluates one concrete
TCP, UDP, or ICMP flow against a policy returned by `load_policy`. It returns a
`Decision(action, matched_rule_id)`; a `None` rule ID identifies the default action.
Supply individual IPv4 address strings and a destination port for TCP/UDP (no
port for ICMP). Invalid traffic input raises the module's `ConnectionError`.
The policy protocol `ip` is a wildcard, not a concrete traffic protocol.
This function is not exposed as a CLI command yet. It models a policy decision
only; it sends no traffic and does not establish routing, ACL attachment, return
traffic behavior, or real service reachability. The caller must establish that
the evaluated policy applies to the flow.

`aclautoguard.requirement_checker.check_host_requirements(policy, requirements,
requirement_ids=["T1", "T2", "T3"])` compares explicitly selected requirements
with modeled policy decisions. Both documents must already be validated. Each
result includes the requirement ID, expected action, decision, and `satisfied`
boolean. Selection asserts applicability; it does not verify the network path.
Only `/32` endpoints with TCP/UDP and a specific destination port, or ICMP, are
supported. Invalid selections, unsupported selected requirements, and any
contradiction in the requirements document raise `RequirementCheckError`.
Unselected entries receive no result. These are static model checks, not live
connectivity results or proof of broader subnet access requirements.

For file-based callers, the shared application function loads and validates both
documents before checking selected IDs:

```python
from aclautoguard.application import check_policy_requirements

results = check_policy_requirements(
    "examples/policies/corrected.yaml",
    "examples/requirements/baseline.yaml",
    requirement_ids=["T1", "T2", "T3"],
)
for result in results:
    print(result.requirement_id, result.expected_action, result.decision, result.satisfied)
```

Loading errors raise `PolicyError` or `RequirementsError`; invalid selections,
conflicts, and unsupported checks raise `RequirementCheckError`. A mismatch is
returned as a result with `satisfied=False`. This function does not run shadow
analysis; use `analyze_policy` separately for that operation. The CLI `check`
command and interactive shell both use this function and share result formatting.

For a combined local gate, the Python API
`aclautoguard.application.assess_policy(policy_path, requirements_path,
requirement_ids=["T1", "T2", "T3"])` loads each file once and returns a
`StaticAssessment` with `shadow_findings`, `requirement_results`, and `blocked`.
Any detected shadow (including same-action redundancy) or selected requirement
mismatch makes `blocked=True`. Both types of findings are retained. Invalid
or unsupported input raises the same errors as requirement checking and returns
no assessment; callers must treat these errors as a stop condition.

`blocked=False` means only that the supported static checks found no blocking
issue. Joint shadow coverage, broader requirements, ACL applicability, baseline
health, and recovery readiness remain outside this gate. It does not authorize
deployment or establish network behavior. Both interfaces expose the combined
gate as `assess <policy-path> <requirements-path> --ids ID [ID ...]`. Exit codes
are 0 for no blocking static findings, 1 for blocking findings, and 2 for input
errors. For example:

```sh
.venv/bin/aclautoguard assess examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3
```

Optionally append `--report "static-evidence.json"` to `assess` in either
interface. It creates a JSON static-assessment report with a UTC creation time,
findings, selected requirement results, blocking status, and limitations. The
parent directory must exist, and existing files are never overwritten. Export
failure returns CLI code 2 (the shell stays open). This report contains no live
traffic, deployment, or recovery evidence. Review reports before sharing;
generated files can be kept under the ignored `reports/` directory.

## Interactive shell

Launch `.venv/bin/aclautoguard` without arguments (or `aclautoguard` after
activating the environment):

```text
ACLAutoGuard> help
ACLAutoGuard> help analyze
ACLAutoGuard> help check
ACLAutoGuard> analyze examples/policies/shadowed.yaml
ACLAutoGuard> analyze "my policies/policy.yaml"
ACLAutoGuard> check examples/policies/corrected.yaml examples/requirements/baseline.yaml --ids T1 T2 T3
ACLAutoGuard> exit
```

EOF (Ctrl+D on Linux) also closes the shell cleanly with exit code 0.
Analysis findings, requirement mismatches, and input errors leave the shell open
for the next command. `check --help` also returns to the prompt.
Ctrl+C at the prompt exits with code 130. Blank lines do nothing. Both
interfaces use the same analysis, requirement checking, and output functions.
Only `help`, `analyze`, `check`, `assess`, and `exit` are implemented in the shell.
Type `help` to list every implemented command with required and optional arguments
and usage examples. Use `help <command>` for the same details for one command.
On terminals with Python Readline support, press Tab to complete commands,
help topics, options, and file/directory paths. Press Tab twice to list ambiguous
matches. Completion quotes paths containing spaces. Use Up/Down for in-session
history; no history file is written. Systems without Readline keep the plain
input shell. Color is enabled only for terminal output and can be disabled with
`NO_COLOR=1`. Windows terminal completion has not been verified.

## Verify

```sh
.venv/bin/python -m pytest -q
```

Dependencies are pinned in `requirements.txt`. Linux is the verified development
environment; Windows support has not been verified.

See [implementation and evidence status](docs/IMPLEMENTATION_STATUS.md) for
remaining core work, required lab details, and the requirements-to-evidence map.
