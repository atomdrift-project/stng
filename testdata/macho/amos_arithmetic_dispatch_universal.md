# AMOS arithmetic state-machine fixture

Malicious universal x86_64/arm64 Mach-O, retained for static analysis only.
SHA-256: `26f642d041fa0fc603fca776166093725e3f000282bc17f86d42c43745c157b7`.
Source: August 2025 abuse.ch corpus in `/var/tmp/triage40/mislabeled-bad/macho`.

The x86 entrypoint at `0x100002490` constructs four hex strings with a
three-state dispatcher. Each byte is the low byte of `(A[i] - C[i]) ^ B[i]`.
The inclusive loop bounds are 127, 1429, 63629 and 59. The first string decodes
to a 64-byte alphabet; the remaining strings use that custom Base64 alphabet.
Table references and loop bounds are recovered from instructions, not guessed.

Independent static decoding yielded these complete stages:

| Stage | Length | SHA-256 |
| --- | ---: | --- |
| VM gate | 536 | `22422ea28dc3168fca0f6633341402f35ad168770ad51960e030a9f94946e080` |
| AppleScript | 23861 | `cbb31c74b087514bbf31dd78721fdd38db755e4ae67d61688c90f6e824a07ec3` |
| Terminal cleanup | 22 | `20a60a29c697e89aeab8cc741327f19f84b599e628d175aab132f1551f1da29c` |

The gate checks hardware descriptions for VM identifiers. A zero exit status
allows cleanup and background AppleScript execution. The script phishes the
account password, gathers browser/wallet/Telegram/keychain data, uploads it to
`45.94.47.136/contact`, replaces Ledger Live and installs a root LaunchDaemon.
Its executable behavior matches the September arithmetic fixture, with changed
campaign identifiers and endpoint. Interspersed RNG/math routines do not supply
the table decoder's inputs. The specimen was never executed.
