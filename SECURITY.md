# Security

stng reads hostile input by design: every file it is pointed at may have been
built to break it. Bugs that let such a file do harm are security bugs.

## In scope

- A crash or panic on any input.
- A hang, or work out of proportion to the input's size.
- Unbounded memory use.
- Output that can forge or corrupt a terminal (escape sequences that survive
  printing) or a log line.
- Anything that executes, loads or writes data from the input.

Missed strings, false positives and wrong classifications are not security
bugs; please report them with the issue templates instead.

## Reporting

Report privately through GitHub: on the repository's **Security** tab choose
**Report a vulnerability**. Please include the input that triggers the bug
(compressed, and marked as malware if it is), the command line, and the stng
version (`stng --version`).

Do not attach live malware to a public issue.

## Supported versions

Fixes go into the next release. Only the latest release is supported.
