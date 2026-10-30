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

The analyzer does not check several earlier rules jointly covering a later
rule. No findings does not prove security or compliance with access requirements.
A covering rule may itself be shadowed; it does not necessarily decide packet
actions. See [project scope](docs/PROJECT_SCOPE.md) for planned work and boundaries.

The [independent requirements format](docs/REQUIREMENTS_FORMAT.md) and
[T1–T8 baseline example](examples/requirements/baseline.yaml) define the next
input contract. Safe requirements loading and field validation are available
through `aclautoguard.requirements.load_requirements`. On a validated document,
`aclautoguard.requirements_analysis.find_requirement_conflicts` detects overlapping
requirements that demand opposite actions. ACL requirement checking is not
implemented yet; requirements files cannot be passed to `analyze`.

## Interactive shell

Launch `.venv/bin/aclautoguard` without arguments (or `aclautoguard` after
activating the environment):

```text
ACLAutoGuard> help
ACLAutoGuard> help analyze
ACLAutoGuard> analyze examples/policies/shadowed.yaml
ACLAutoGuard> analyze "my policies/policy.yaml"
ACLAutoGuard> exit
```

EOF (Ctrl+D on Linux) also closes the shell cleanly with exit code 0.
Analysis findings and input errors leave the shell open for the next command.
Ctrl+C at the prompt exits with code 130. Blank lines do nothing. Both
interfaces use the same analysis and output functions. Only `help`, `analyze`,
and `exit` are implemented in the shell.

## Verify

```sh
.venv/bin/python -m pytest -q
```

Dependencies are pinned in `requirements.txt`. Linux is the verified development
environment; Windows support has not been verified.
