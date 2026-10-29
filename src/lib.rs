//! sigstore-exec-gate: verify a cosign-compatible blob signature over an ELF
//! and execute exactly the verified bytes under Landlock + seccomp.
//!
//! Scope and non-goals are documented in README.md. In short: this gates the
//! *initial* program image and denies every later execve/execveat of the
//! sandboxed tree; it does not police file-backed `mmap(PROT_EXEC)`, `mremap`
//! or `remap_file_pages`.

pub mod corpus;
pub mod elf;
pub mod gate;
pub mod landlock;
pub mod seccomp;
pub mod sig;

/// Exit code used by the gate when it refuses to run a program.
pub const EXIT_DENIED: i32 = 126;
/// Exit code used by the gate for internal/sandbox setup errors (fail closed).
pub const EXIT_SETUP: i32 = 125;
