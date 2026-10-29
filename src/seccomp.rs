//! Hand-assembled classic-BPF seccomp filter for x86_64 + user-notification
//! plumbing. No libseccomp dependency so every instruction is reviewable.

use anyhow::{bail, Result};

pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

pub const SYS_MMAP: u32 = 9;
pub const SYS_MPROTECT: u32 = 10;
pub const SYS_EXECVE: u32 = 59;
pub const SYS_PTRACE: u32 = 101;
pub const SYS_USELIB: u32 = 134;
pub const SYS_PERSONALITY: u32 = 135;
pub const SYS_PROCESS_VM_WRITEV: u32 = 311;
pub const SYS_SECCOMP: libc::c_long = 317;
pub const SYS_EXECVEAT: u32 = 322;
pub const SYS_PKEY_MPROTECT: u32 = 329;

pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
pub const fn ret_errno(e: i32) -> u32 {
    0x0005_0000 | (e as u32 & 0xffff)
}

pub const PROT_EXEC: u32 = 0x4;
pub const MAP_ANONYMOUS: u32 = 0x20;
pub const READ_IMPLIES_EXEC: u32 = 0x0040_0000;

const BPF_LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const BPF_JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}
const fn ins(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter { code, jt, jf, k }
}
fn ld(off: u32) -> SockFilter {
    ins(BPF_LD_W_ABS, 0, 0, off)
}
fn ret(v: u32) -> SockFilter {
    ins(BPF_RET_K, 0, 0, v)
}

#[derive(Debug, Clone, Copy)]
pub struct FilterPolicy {
    /// Deny PROT_EXEC via mprotect/pkey_mprotect and anonymous PROT_EXEC mmap.
    pub wx: bool,
}

/// Build the filter. Layout:
/// arch != x86_64 (covers `int 0x80` / ia32 entry) -> KILL_PROCESS;
/// x32 bit set -> KILL_PROCESS; execve/execveat -> USER_NOTIF (the supervisor
/// allows exactly one: the gate's own execveat); ptrace, process_vm_writev,
/// uselib -> EPERM; personality(x) with READ_IMPLIES_EXEC (except the
/// 0xffffffff query) -> EPERM; with `wx`: mprotect/pkey_mprotect(PROT_EXEC) ->
/// EACCES and mmap(PROT_EXEC|MAP_ANONYMOUS) -> EACCES. Everything else -> ALLOW.
pub fn build_filter(p: FilterPolicy) -> Vec<SockFilter> {
    let mut f = vec![
        ld(OFF_ARCH),
        ins(BPF_JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        ret(RET_KILL_PROCESS),
        ld(OFF_NR),
        ins(BPF_JSET_K, 0, 1, X32_SYSCALL_BIT),
        ret(RET_KILL_PROCESS),
    ];
    let simple = [
        (SYS_EXECVE, RET_USER_NOTIF),
        (SYS_EXECVEAT, RET_USER_NOTIF),
        (SYS_PTRACE, ret_errno(libc::EPERM)),
        (SYS_PROCESS_VM_WRITEV, ret_errno(libc::EPERM)),
        (SYS_USELIB, ret_errno(libc::EPERM)),
    ];
    for (nr, v) in simple {
        f.push(ins(BPF_JEQ_K, 0, 1, nr));
        f.push(ret(v));
    }
    // personality: body = 5 instructions
    f.push(ins(BPF_JEQ_K, 0, 5, SYS_PERSONALITY));
    f.push(ld(off_arg_lo(0)));
    f.push(ins(BPF_JEQ_K, 2, 0, 0xffff_ffff));
    f.push(ins(BPF_JSET_K, 0, 1, READ_IMPLIES_EXEC));
    f.push(ret(ret_errno(libc::EPERM)));
    f.push(ret(RET_ALLOW));
    if p.wx {
        for nr in [SYS_MPROTECT, SYS_PKEY_MPROTECT] {
            f.push(ins(BPF_JEQ_K, 0, 4, nr));
            f.push(ld(off_arg_lo(2)));
            f.push(ins(BPF_JSET_K, 0, 1, PROT_EXEC));
            f.push(ret(ret_errno(libc::EACCES)));
            f.push(ret(RET_ALLOW));
        }
        f.push(ins(BPF_JEQ_K, 0, 6, SYS_MMAP));
        f.push(ld(off_arg_lo(2)));
        f.push(ins(BPF_JSET_K, 0, 3, PROT_EXEC));
        f.push(ld(off_arg_lo(3)));
        f.push(ins(BPF_JSET_K, 0, 1, MAP_ANONYMOUS));
        f.push(ret(ret_errno(libc::EACCES)));
        f.push(ret(RET_ALLOW));
    }
    f.push(ret(RET_ALLOW));
    f
}

/// Tiny cBPF interpreter (only the opcodes emitted above) so the filter
/// logic is unit-tested without loading it.
pub fn eval(f: &[SockFilter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
    let mut data = [0u8; 64];
    data[0..4].copy_from_slice(&nr.to_le_bytes());
    data[4..8].copy_from_slice(&arch.to_le_bytes());
    for (i, a) in args.iter().enumerate() {
        data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_le_bytes());
    }
    let mut a: u32 = 0;
    let mut pc = 0usize;
    while pc < f.len() {
        let i = f[pc];
        match i.code {
            BPF_LD_W_ABS => {
                let o = i.k as usize;
                a = u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
                pc += 1;
            }
            BPF_JEQ_K => {
                pc += 1 + if a == i.k {
                    i.jt as usize
                } else {
                    i.jf as usize
                }
            }
            BPF_JSET_K => {
                pc += 1 + if a & i.k != 0 {
                    i.jt as usize
                } else {
                    i.jf as usize
                }
            }
            BPF_RET_K => return i.k,
            c => panic!("unsupported opcode {c:#x}"),
        }
    }
    panic!("fell off the end of the filter")
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

pub const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;

/// Install the filter on the calling thread; returns the listener fd.
/// Caller must have set PR_SET_NO_NEW_PRIVS. Async-signal-safe (no alloc).
pub fn install_with_listener(f: &[SockFilter]) -> Result<i32, i32> {
    let prog = SockFprog {
        len: f.len() as u16,
        filter: f.as_ptr(),
    };
    let r = unsafe {
        libc::syscall(
            SYS_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const SockFprog,
        )
    };
    if r < 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    Ok(r as i32)
}

pub fn check_len(f: &[SockFilter]) -> Result<()> {
    if f.is_empty() || f.len() > 4096 {
        bail!("filter length {} out of range", f.len());
    }
    Ok(())
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
// _IOWR('!', 0, struct seccomp_notif) / _IOWR('!', 1, struct seccomp_notif_resp)
pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;

pub fn notif_recv(fd: i32) -> std::io::Result<SeccompNotif> {
    let mut n = SeccompNotif::default();
    let r = unsafe {
        libc::ioctl(
            fd,
            SECCOMP_IOCTL_NOTIF_RECV as _,
            &mut n as *mut SeccompNotif,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n)
}

pub fn notif_send(fd: i32, resp: &SeccompNotifResp) -> std::io::Result<()> {
    let r = unsafe {
        libc::ioctl(
            fd,
            SECCOMP_IOCTL_NOTIF_SEND as _,
            resp as *const SeccompNotifResp,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const X: u32 = AUDIT_ARCH_X86_64;
    const Z: [u64; 6] = [0; 6];
    fn a(i: usize, v: u64) -> [u64; 6] {
        let mut x = Z;
        x[i] = v;
        x
    }

    #[test]
    fn struct_sizes_match_kernel_abi() {
        assert_eq!(std::mem::size_of::<SockFilter>(), 8);
        assert_eq!(std::mem::size_of::<SeccompData>(), 64);
        assert_eq!(std::mem::size_of::<SeccompNotif>(), 80);
        assert_eq!(std::mem::size_of::<SeccompNotifResp>(), 24);
        assert_eq!(SECCOMP_IOCTL_NOTIF_RECV & 0x3fff_0000, 80 << 16);
        assert_eq!(SECCOMP_IOCTL_NOTIF_SEND & 0x3fff_0000, 24 << 16);
        check_len(&build_filter(FilterPolicy { wx: true })).unwrap();
    }

    #[test]
    fn arch_and_x32_are_killed() {
        let f = build_filter(FilterPolicy { wx: true });
        assert_eq!(
            eval(&f, 11, 0x4000_0003 /* AUDIT_ARCH_I386 */, Z),
            RET_KILL_PROCESS
        );
        assert_eq!(eval(&f, X32_SYSCALL_BIT | 59, X, Z), RET_KILL_PROCESS);
        assert_eq!(eval(&f, 39 /* getpid */, X, Z), RET_ALLOW);
    }

    #[test]
    fn exec_family_goes_to_supervisor() {
        let f = build_filter(FilterPolicy { wx: false });
        assert_eq!(eval(&f, SYS_EXECVE, X, Z), RET_USER_NOTIF);
        assert_eq!(eval(&f, SYS_EXECVEAT, X, a(4, 0x1000)), RET_USER_NOTIF);
        assert_eq!(eval(&f, SYS_PTRACE, X, Z), ret_errno(libc::EPERM));
        assert_eq!(
            eval(&f, SYS_PROCESS_VM_WRITEV, X, Z),
            ret_errno(libc::EPERM)
        );
        assert_eq!(eval(&f, SYS_USELIB, X, Z), ret_errno(libc::EPERM));
    }

    #[test]
    fn personality_read_implies_exec() {
        let f = build_filter(FilterPolicy { wx: true });
        let eperm = ret_errno(libc::EPERM);
        assert_eq!(eval(&f, SYS_PERSONALITY, X, a(0, 0xffff_ffff)), RET_ALLOW);
        assert_eq!(eval(&f, SYS_PERSONALITY, X, a(0, 0)), RET_ALLOW);
        assert_eq!(
            eval(&f, SYS_PERSONALITY, X, a(0, READ_IMPLIES_EXEC as u64)),
            eperm
        );
        assert_eq!(
            eval(
                &f,
                SYS_PERSONALITY,
                X,
                a(0, (READ_IMPLIES_EXEC | 0x0800) as u64)
            ),
            eperm
        );
    }

    #[test]
    fn wx_rules() {
        let f = build_filter(FilterPolicy { wx: true });
        let e = ret_errno(libc::EACCES);
        assert_eq!(eval(&f, SYS_MPROTECT, X, a(2, 5)), e);
        assert_eq!(eval(&f, SYS_MPROTECT, X, a(2, 1)), RET_ALLOW);
        assert_eq!(eval(&f, SYS_PKEY_MPROTECT, X, a(2, 4)), e);
        assert_eq!(eval(&f, SYS_PKEY_MPROTECT, X, a(2, 3)), RET_ALLOW);
        let mut m = Z;
        m[2] = 5;
        m[3] = 0x22; // PRIVATE|ANON
        assert_eq!(eval(&f, SYS_MMAP, X, m), e);
        m[3] = 0x02; // file-backed PROT_EXEC: allowed (dynamic loader) -> documented gap
        assert_eq!(eval(&f, SYS_MMAP, X, m), RET_ALLOW);
        m[2] = 3;
        m[3] = 0x22;
        assert_eq!(eval(&f, SYS_MMAP, X, m), RET_ALLOW);
        let g = build_filter(FilterPolicy { wx: false });
        assert_eq!(eval(&g, SYS_MPROTECT, X, a(2, 7)), RET_ALLOW);
    }

    #[test]
    fn not_covered_syscalls_are_allowed_on_purpose() {
        // mremap (25) and remap_file_pages (216) are NOT policed: see README.
        let f = build_filter(FilterPolicy { wx: true });
        assert_eq!(eval(&f, 25, X, Z), RET_ALLOW);
        assert_eq!(eval(&f, 216, X, a(2, 7)), RET_ALLOW);
    }
}
