# Security policy

## Scope

SENTINEL is a closed simulator with synthetic data. Security reports we want:

- sandbox or container escapes, and ways to reach the host, the network, or the Docker socket;
- ways for a submission to read hidden scenarios, labels, reference plans, or other teams' data;
- ways to alter scores or evaluator metrics outside the defense/attacker contracts;
- validator bypasses that let a mutation touch undeclared state;
- leaderboard authentication or injection issues.

Attacks against the simulated agent inside declared scenario surfaces are the challenge itself, not
vulnerabilities.

## Reporting

Report privately to the organizers through the disclosure contact published in the official competition rules
(organizers: set this before launch; see `docs/organizer-guide.md`). Include the affected version, the
steps to reproduce against a local checkout, and the impact. Do not open public issues for unfixed
vulnerabilities.

## Rules

- Reproduce only on your own local checkout. Never test against shared organizer, sponsor, or third-party
  infrastructure.
- Do not access, modify, or retain data beyond what is needed to demonstrate the issue.
- Do not use real credentials or personal data.

Good-faith reports that follow these rules will not be penalized in the competition. Organizers will
acknowledge reports, fix confirmed issues, rotate any affected hidden scenarios, and credit reporters who
want credit.

## Hardening summary

See [docs/security-model.md](docs/security-model.md).
