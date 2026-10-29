# sigstore-exec-gate (`sxg`)

Exec gate for Linux x86_64: it checks a **cosign-compatible blob signature**
over an ELF and, only if it verifies, runs **exactly the verified bytes**
under Landlock + seccomp. Once the program is running, every later
`execve`/`execveat` in its process tree is denied by a supervisor.

The name says "sigstore", but what is implemented is **cosign key-based blob
signatures** (`cosign sign-blob --key`). Keyless signing (Fulcio certificate
plus Rekor inclusion proof) is **not** implemented. See "Not covered" below.

```
sxg run --key cosign.pub -- ./prog args...
  │ open ./prog, copy it into a memfd, seal it (F_SEAL_WRITE|SHRINK|GROW|SEAL)
  │ read the sealed bytes back → ECDSA-P256/SHA-256 verify (cosign format) → static ELF policy
  │ fork
  ├─ child:  clear READ_IMPLIES_EXEC → NO_NEW_PRIVS → Landlock → seccomp(NEW_LISTENER)
  │          → send listener fd to parent → execveat(memfd, "", AT_EMPTY_PATH)
  └─ parent: seccomp user-notification supervisor
             allows exactly one execveat (the child's, on that memfd); every other exec → EPERM
```

## What this is / is not

| Claim | Status |
|---|---|
| Verify the signature format of `cosign sign-blob --key` (base64 DER ECDSA P-256 over SHA-256 of the blob, SPKI PEM public key) | **Implemented.** Checked both ways against the real cosign v2.4.1 binary in CI (`scripts/cosign-interop.sh`) |
| Run exactly the bytes that were verified (no TOCTOU between verify and exec) | **Implemented** with a sealed memfd and `execveat(AT_EMPTY_PATH)`. Tested: swapping the file on disk after signing only produces a deny |
| Nested `execve`/`execveat`, including an absolute path with an arbitrary dirfd and from forked children | **Denied** (seccomp `USER_NOTIF` + supervisor) |
| ia32 `int $0x80` and x32 syscalls | **Process killed** (arch / x32-bit check in the filter) |
| Executable memory via `mprotect`/`pkey_mprotect(PROT_EXEC)` and anonymous `mmap(PROT_EXEC)` | **Denied** (`EACCES`) unless `--allow-jit` is passed |
| `personality(READ_IMPLIES_EXEC)` | **Denied**. The gate also clears an inherited persona before exec |
| ELF without `PT_GNU_STACK` or with an executable stack; ELF32 | **Refused** (static policy) |
| `LD_*` and `GLIBC_TUNABLES` in the environment | **Removed** (`--keep-ld-env` keeps them) |
| `ptrace`, `process_vm_writev`, `uselib` | **Denied** (`EPERM`) |
| Killing the supervisor to free up exec | Landlock ABI ≥ 6 blocks the signal (`LANDLOCK_SCOPE_SIGNAL`). If the supervisor does die, its listener closes and exec stays denied. Tested |
| Keyless Sigstore (Fulcio/Rekor/TUF), bundles, attestations/in-toto | **Not implemented, not claimed** |
| Kernel module, IMA/IPE, Secure Boot | **Out of scope** (userspace only) |

## Not covered (explicit gaps)

- **`mremap` is NOT covered.** It is allowed with no checks, and no test
  exercises it as a bypass vector.
- **`remap_file_pages` is NOT covered.** It is allowed with no checks, and no
  test exercises it as a bypass vector.
- **File-backed `mmap(PROT_EXEC)` is NOT covered.** The dynamic loader needs
  it, so a signed program can still `dlopen` or map unsigned code from a
  file or a `memfd` it creates itself. This gate decides which *program
  image* runs and blocks *new execs*. It does not enforce "only signed code
  in memory". That needs an LSM `mmap_file`/`file_mprotect` hook (IMA/IPE
  class), which is outside this repo.
- With `--allow-jit`, the W^X policy is off.
- Confused-deputy via IPC is not covered: asking an unsandboxed process
  (systemd-run, ssh localhost, a daemon) to execute something.
- x86_64 only. Other architectures are refused (`build_filter` assumes the
  x86_64 syscall table).
- Interpreted scripts (`#!`) are not supported. Only ELF.
- The signature only proves that the holder of the private key signed the
  bytes. Key management, revocation and identity are not covered (that is
  what keyless/Rekor would add).
- The audit was done by the author and the test suite, not by an
  independent third party.

## Measurement (reproducible)

```
scripts/measure.sh            # cargo build --release + sxg-measure (builds the corpus with cc)
```

The corpus is generated from `fixtures/src/*.c` with a fresh P-256 test key:

- 50 signed ELFs (25 dynamic PIE + 25 `-static`)
- 50 unsigned
- 20 tampered (one byte of the signed marker changed while keeping the
  original signature; they still run if executed directly)
- 10 signed with another key
- 4 positive controls: signature deleted, empty signature, garbage signature,
  signed ELF with `-z execstack`
- 6 bypass cases, each run under the gate and directly as a control

Results from two environments. Both use the same command:
`TIMING=50 scripts/measure.sh`.

| Metric | Threshold | Build box (Linux 6.12.94+, Landlock ABI 6) | CI `ubuntu-latest` (Linux 7.0.0-1017-azure, Landlock ABI 8), run [40817792882](https://github.com/federiconbaez/cortex9-sigstore-exec-gate/actions/runs/40817792882) |
|---|---|---|---|
| Signed ELFs that run | ≥ 95% | **50/50** | **50/50** |
| Unsigned executions | 0 | **0/50** (50 denied, exit 126; all 50 run directly) | **0/50** (50 denied; 50 run directly) |
| Tampered executions | 0 | **0/20** (20 denied; all 20 run directly) | **0/20** (20 denied; 20 run directly) |
| Foreign-key executions | 0 | **0/10** | **0/10** |
| Positive controls (strip/empty/garbage/execstack) | 0 run | **0/4** | **0/4** |
| Bypasses that succeed under the gate | 0 | **0/6** (direct control succeeds in 5/6) | **0/6** (direct control 5/6) |
| Wall time p50 / p95, gate vs direct (50 runs) | n/a | 3.19 / 4.22 ms vs 0.51 / 0.60 ms | 3.77 / 4.12 ms vs 0.43 / 0.49 ms |

The per-case JSON from CI is uploaded as the `measurement` artifact
(`corpus/results.json`). The int80 direct control also reproduces on the CI
kernel (`int80 direct control: pwned=true` in the test log).

### Bypass cases

The first four are the bypass classes recorded in our internal notes against
an earlier version of cortex9-elf-zk-loader (#9). Those notes were not
re-verified against that repo. What is verified here is that each one works
without the gate (control) and fails under it.

| Case | Without gate | Under gate |
|---|---|---|
| `execve`: execve, execveat, execveat with absolute path + arbitrary dirfd, `/bin/sh`, and a forked child | payload runs | 5× `EPERM`, `BLOCKED` |
| `pkey_mprotect`: plus `mprotect` and anonymous RWX `mmap` | shellcode runs (3/3) | 3× `EACCES` |
| `int80`: ia32 `execve` (nr 11) from a 64-bit process | payload runs | killed by `SIGSYS` (exit 159) |
| `read_implies_exec` (the program sets the persona) | RW memory becomes executable, shellcode runs | `personality` → `EPERM` |
| `read_implies_exec_inherited` (the invoker sets the persona) | **does not reproduce**: after exec of the 64-bit ELF the persona is 0 (observed). Kept as a regression test, not counted as a working control | persona 0 |
| `seccomp_notif_override`: the program installs its own execve notifier and answers `CONTINUE` | payload runs | the kernel refuses a second listener in the same filter chain (`EBUSY`, observed on 6.12), and the exec is denied |

The last case came from reading the warning in `linux/seccomp.h` that "the
most recently added filter takes precedence" between `USER_NOTIF` filters. In
practice the kernel already blocks it with `EBUSY`. The test makes sure it
stays that way.

## Usage

```
sxg keygen test                       # test.key (PKCS#8) + test.pub (SPKI)
sxg sign --key test.key ./prog        # ./prog.sig, same format as cosign sign-blob
cosign sign-blob --key cosign.key --tlog-upload=false --output-signature prog.sig prog   # alternative
sxg verify --key cosign.pub ./prog
sxg run --key cosign.pub [--sig f.sig] [--allow-jit] [--allow-exec-stack] [--keep-ld-env] [-v] -- ./prog args
sxg probe                             # Landlock ABI
```

Exit codes: 126 means denied (signature, missing signature, or ELF policy).
125 means the sandbox could not be applied (fail closed). Anything else is
the program's own exit code, or 128+signal.

## Tests

`cargo test --release` runs:

- Unit tests: a cBPF interpreter evaluates the real filter, plus ELF parser,
  signature and ABI-layout tests.
- End-to-end tests: real fixtures compiled with `cc`, run with real Landlock
  + seccomp.

There is no skip path. Without Landlock or seccomp user notification, the
tests **fail**.

## Sources actually consulted

- Kernel UAPI headers on the build box: `/usr/include/linux/seccomp.h`
  (`SECCOMP_RET_USER_NOTIF`, `SECCOMP_FILTER_FLAG_NEW_LISTENER`, the
  `SECCOMP_USER_NOTIF_FLAG_CONTINUE` warning and precedence between
  filters), `/usr/include/linux/landlock.h` (`LANDLOCK_ACCESS_FS_EXECUTE`,
  `LANDLOCK_SCOPE_SIGNAL`), `/usr/include/linux/memfd.h` (`MFD_EXEC`).
- cosign v2.4.1, the `cosign-linux-amd64` binary from the official
  sigstore/cosign release, sha256 checked against `cosign_checksums.txt` from
  that release. It was used for black-box interop, not as documentation.

## License

Apache-2.0. See `LICENSE`.
