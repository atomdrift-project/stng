# KWorker Process Spoofing Malware Sample

This directory contains test samples for detecting character-by-character string assembly patterns used by the `kworker_pretenders` malware family.

## Sample: kworker_obfuscated_1

Binary ELF x64 compiled with GCC 10.2.1, linked against libcurl-gnutls.

### Obfuscation Technique

Strings never appear whole in the file. GCC inlined `strcat(buf, "lit")` for
short literals: each append computes `buf + strlen(buf)` and stores the
literal, NUL included, as `mov` immediates at that pointer, a few bytes at a
time:

```x86asm
lea  rax, [rbp-0x90]
mov  rdi, rax
call strlen
mov  rdx, rax
lea  rax, [rbp-0x90]
add  rax, rdx
mov  dword [rax], 0x6d742f      ; "/tm\0"
```

### Strings the sample builds

Verified against the disassembly; all are recovered as `StackString`:

- `[kworker/8:3]` — spoofed kernel worker process name
- `%s/.local/kworker` — where it copies itself
- `%s/.bashrc` — shell-startup persistence
- `/tmp/.ICE-unix.pid` — lock file
- `%s 2>&1 > /dev/null` — command template

The C2 address is stored UTF-16LE in `.rodata` (`htp:/cunilos.aemrg…`).
