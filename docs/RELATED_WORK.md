# Related Work — Initial Comparison

## Purpose
Identify existing capabilities and use them to guide ACLAutoGuard.
This is an initial documentation review, not a complete literature review
or a hands-on evaluation of the compared tools.

## Existing tools

### Netmiko
Simplifies CLI connections to network devices.
ACLAutoGuard will use it for communication rather than implement SSH.
Source: https://github.com/ktbyers/netmiko

### Ansible Cisco IOS ACL module
Configures and manages named or numbered IOS ACLs.
It provides a reference for structured configuration management.
Source: https://docs.ansible.com/projects/ansible/latest/collections/cisco/ios/ios_acls_module.html

### Batfish
Analyzes ACL behavior and identifies unreachable lines, including rules
shadowed by earlier entries. Its output can identify blocking rules.
It provides a reference for analyzer findings and test cases.
Source: https://batfish.readthedocs.io/en/latest/notebooks/filters.html

### NAPALM
Provides configuration loading, comparison, commit, and rollback methods.
Confirmed commits with automatic reversion are available on certain
platforms; availability must be checked for our selected device.
Source: https://napalm.readthedocs.io/en/stable/tutorials/changing_the_config.html

## Proposed contribution
Implement and evaluate a small, reproducible workflow combining:
1. Explainable analysis of a documented ACL subset.
2. Independent access requirements.
3. Controlled configuration deployment.
4. Real traffic tests from relevant network zones.
5. Verified recovery and evidence reporting.

These individual capabilities already exist.
We do not claim that no existing framework integrates them.
Other tools may provide additional functionality beyond this review.

## Initial evaluation plan
- Check analyzer findings against manually reviewed ACL examples.
- Measure detection of blocked required access and permitted forbidden access.
- Distinguish service failures from evidence of ACL blocking.
- Verify restoration and measure recovery time.
- Test management-loss recovery only after platform support is proven.

## Follow-up research
- Review academic work on ACL anomalies and rule-order analysis.
- Define the exact supported syntax and analysis limitations.
- Review platform-specific deployment and recovery documentation.
