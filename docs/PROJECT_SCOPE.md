# ACLAutoGuard — Project Scope

## Objective
Develop a Python CLI that analyzes proposed router ACL changes,
deploys them, validates actual traffic, and verifies recovery after failure.

## Baseline scenario
A university teaching lab has Student, Staff, Server, and Management zones.
The router controls traffic between zones.

## Required access
- Students may access the teaching website using HTTP.
- Students must not access the Staff network.
- Students must not access teaching-server SSH.
- Authorized Staff may access teaching-server HTTP and SSH.
- Only Management may access router SSH.

These requirements are independent of the proposed ACL.
Selected traffic tests provide evidence; they do not exhaustively
prove every possible connection.

## Core deliverables
- One router platform and one automatically managed traffic ACL.
- A defined, documented subset of IPv4 ACL syntax.
- Analysis of duplicates, overlaps, shadowing, and requirement violations.
- Findings that explain affected rules and traffic.
- Baseline checks, configuration backup, and change preview.
- SSH deployment with command-error checking and configuration readback.
- Active traffic tests from the appropriate network zones.
- Pass, fail, and inconclusive test outcomes.
- Restoration after failed or inconclusive deployment validation.
- Verification of recovery and reports containing results and timings.
- A working Packet Tracer topology and annotated packet evidence.

## Recovery constraints
Management access protection is configured separately.
Recovery after management access is lost requires a proven device-side
rollback mechanism or independent management path.
Router model, software version, and recovery support remain unverified.
Controller-driven ACL restoration and device-side rollback may have
different restoration scopes; document and test both.

## Optional extension
After the core passes its acceptance tests:
- Detect one defined suspicious-connection pattern.
- Start in alert-only mode.
- Add temporary blocking with protected-address safeguards.
- Verify legitimate access, expire blocks, and generate alerts.
- Coordinate temporary blocks with policy deployment and rollback.

## Boundaries
- No web dashboard in the first version.
- No machine learning requirement.
- No multi-vendor support in the first version.
- No claim of replacing a full IDS or IPS.
- Windows support remains unverified until tested.
- All experiments use an authorized, isolated lab.

## Current status
Professor approval confirmed.
Team size: two.
Python environment and dependencies prepared.
Router identification and lab feasibility tests pending.
Related-work research started; detailed comparison pending.
