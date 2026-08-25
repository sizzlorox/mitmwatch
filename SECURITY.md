# Security Policy

mitmwatch is a security tool, so its own integrity matters as much as its
features. Two things belong here: how to report a vulnerability, and what
counts as one.

## Reporting a vulnerability

Please report privately, not in a public issue.

- Use **GitHub's private vulnerability reporting**: the **Security** tab →
  **Report a vulnerability**. This opens a private advisory visible only to the
  maintainers.

Include what you would want if you received the report: affected version or
commit, platform, a minimal reproduction, and the impact you believe it has.
A proof-of-concept that runs contained (not against third parties) is ideal.

You will get an acknowledgement, a fix or a mitigation as fast as is
responsible, and credit in the advisory unless you ask otherwise. Please give
maintainers a reasonable window to ship a fix before disclosing publicly.

## What counts as a vulnerability here

Because mitmwatch is a detector, the highest-severity class is anything that
makes it **miss a real attack or fabricate a false one** while appearing to work:

- A probe that can be made to report "clean" while interception is occurring
  (a detection bypass).
- A way to make the two-way TLS verification, the embedded-root pinning, or the
  pinned witness transport accept something it should reject.
- A path that lets an on-network attacker drive the detector into adopting the
  attacker's state as the baseline ("learning its own attacker").
- A crash or panic reachable from hostile network input (the `internal/frame`
  parsers face exactly this and are meant to be total).
- Any exfiltration of what the sensor observes to an endpoint the operator did
  not configure.
- A false-positive path that fires reliably on a benign, unmodified network —
  because a detector that cries wolf gets ignored, which is itself a failure of
  the security goal.

Also in scope: secrets, credentials, or personal network details committed to
the repository, and supply-chain issues in dependencies or the build.

## What is out of scope

- Attacks that require already-root/admin control of the host the sensor runs
  on (mitmwatch trusts the machine it runs on; a compromised host is a different
  threat model).
- Passive eavesdropping / a silent tap, which leaves no trace and is out of
  scope by design — see the README.
- Reports generated solely by running the tool against networks or hosts you are
  not authorised to test.

## Supported versions

mitmwatch is pre-1.0 and moves fast; fixes land on the latest `main`. Please
reproduce against a recent build before reporting.
