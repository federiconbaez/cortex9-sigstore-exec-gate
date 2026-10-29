//! The gate: read -> seal into memfd -> verify the sealed bytes -> static ELF
//! policy -> fork -> (child) Landlock + seccomp -> execveat(memfd).
//! The parent stays as seccomp user-notification supervisor: it allows exactly
//! one execveat (the gate's own, on the sealed memfd) and denies every other
//! execve/execveat issued by the sandboxed process tree.

use crate::{elf, landlock, seccomp, sig, EXIT_DENIED, EXIT_SETUP};
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::CString;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

const MFD_CLOEXEC: u32 = 0x1;
const MFD_ALLOW_SEALING: u32 = 0x2;
const MFD_EXEC: u32 = 0x10;
const MAX_IMAGE: u64 = 1 << 30;

#[derive(Debug, Clone)]
pub struct Policy {
    /// seccomp W^X rules (deny PROT_EXEC via mprotect/pkey_mprotect/anon mmap)
    pub wx: bool,
    /// refuse ELF without PT_GNU_STACK or with an executable stack
    pub require_nx_stack: bool,
    /// strip LD_* and GLIBC_TUNABLES from the environment
    pub scrub_env: bool,
    /// print supervisor decisions to stderr
    pub verbose: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            wx: true,
            require_nx_stack: true,
            scrub_env: true,
            verbose: false,
        }
    }
}

/// Verified image ready to execute.
pub struct Sealed {
    pub memfd: OwnedFd,
    pub sha256: String,
    pub info: elf::ElfInfo,
}

fn memfd_seal(bytes: &[u8]) -> Result<OwnedFd> {
    let name = c"sxg-image";
    let mut fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC,
        )
    };
    if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // kernels < 6.3 do not know MFD_EXEC
        fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                MFD_CLOEXEC | MFD_ALLOW_SEALING,
            )
        };
    }
    if fd < 0 {
        bail!("memfd_create: {}", std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    let mut off = 0usize;
    while off < bytes.len() {
        let w = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes[off..].as_ptr().cast(),
                bytes.len() - off,
            )
        };
        if w <= 0 {
            bail!("write memfd: {}", std::io::Error::last_os_error());
        }
        off += w as usize;
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        bail!("F_ADD_SEALS: {}", std::io::Error::last_os_error());
    }
    Ok(fd)
}

fn read_back(fd: &OwnedFd, len: usize) -> Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    let mut off = 0usize;
    while off < len {
        let r = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                v[off..].as_mut_ptr().cast(),
                len - off,
                off as i64,
            )
        };
        if r <= 0 {
            bail!("pread memfd: {}", std::io::Error::last_os_error());
        }
        off += r as usize;
    }
    Ok(v)
}

/// Load `path`, seal it, verify `sig_b64` with `key` over the *sealed* bytes,
/// and apply the static ELF policy. Errors mean "deny".
pub fn load_and_verify(
    path: &str,
    key: &p256::ecdsa::VerifyingKey,
    sig_b64: &str,
    policy: &Policy,
) -> Result<Sealed> {
    let mut f = std::fs::File::open(path).with_context(|| format!("open {path}"))?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        bail!("{path} is not a regular file");
    }
    if meta.len() > MAX_IMAGE {
        bail!("{path} is larger than {MAX_IMAGE} bytes");
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    f.read_to_end(&mut bytes)?;
    let memfd = memfd_seal(&bytes)?;
    drop(bytes);
    let len = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(memfd.as_raw_fd(), &mut st) < 0 {
            bail!("fstat memfd");
        }
        st.st_size as usize
    };
    let img = read_back(&memfd, len)?;
    sig::verify_blob(key, &img, sig_b64).context("provenance check failed")?;
    let info = elf::inspect(&img, policy.require_nx_stack)?;
    Ok(Sealed {
        memfd,
        sha256: sig::sha256_hex(&img),
        info,
    })
}

fn scrubbed_env(scrub: bool) -> Vec<CString> {
    std::env::vars_os()
        .filter_map(|(k, v)| {
            let ks = k.to_string_lossy();
            if scrub && (ks.starts_with("LD_") || ks == "GLIBC_TUNABLES") {
                return None;
            }
            let mut s = k.into_encoded_bytes();
            s.push(b'=');
            s.extend_from_slice(&v.into_encoded_bytes());
            CString::new(s).ok()
        })
        .collect()
}

fn child_fail(msg: &[u8], errno: i32) -> ! {
    unsafe {
        libc::write(2, msg.as_ptr().cast(), msg.len());
        let mut buf = [0u8; 16];
        let mut n = errno.unsigned_abs();
        let mut i = buf.len();
        loop {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        libc::write(2, buf[i..].as_ptr().cast(), buf.len() - i);
        libc::write(2, b"\n".as_ptr().cast(), 1);
        libc::_exit(EXIT_SETUP)
    }
}

fn send_fd(sock: i32, fd: i32) -> i32 {
    // async-signal-safe: stack buffers only
    unsafe {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut cbuf = [0u64; 4]; // >= CMSG_SPACE(sizeof(int)), 8-aligned
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut i32, fd);
        if libc::sendmsg(sock, &msg, 0) < 0 {
            return *libc::__errno_location();
        }
        0
    }
}

fn recv_fd(sock: i32) -> Result<OwnedFd> {
    unsafe {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut cbuf = [0u64; 4];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n <= 0 {
            bail!("child did not send the seccomp listener (sandbox setup failed)");
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if c.is_null() || (*c).cmsg_type != libc::SCM_RIGHTS {
            bail!("no SCM_RIGHTS from child");
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const i32);
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Outcome of a gated run.
#[derive(Debug)]
pub struct RunReport {
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub denied_execs: u32,
}

/// Run a verified image. Never returns success for a sandbox that could not
/// be fully applied: every setup failure is an error (fail closed).
pub fn run_sealed(s: Sealed, argv: &[String], policy: &Policy) -> Result<RunReport> {
    let mut exec_allow = Vec::new();
    if let Some(i) = &s.info.interp {
        let real = std::fs::canonicalize(i).with_context(|| format!("PT_INTERP {i} not found"))?;
        exec_allow.push(real.to_string_lossy().into_owned());
    }
    let ll = landlock::prepare(&exec_allow)?;
    let filter = seccomp::build_filter(seccomp::FilterPolicy { wx: policy.wx });
    seccomp::check_len(&filter)?;

    let c_argv: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<_, _>>()?;
    let mut p_argv: Vec<*const libc::c_char> = c_argv.iter().map(|c| c.as_ptr()).collect();
    p_argv.push(std::ptr::null());
    let c_env = scrubbed_env(policy.scrub_env);
    let mut p_env: Vec<*const libc::c_char> = c_env.iter().map(|c| c.as_ptr()).collect();
    p_env.push(std::ptr::null());
    let empty = c"";
    let memfd = s.memfd.as_raw_fd();

    let mut sv = [0i32; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    } < 0
    {
        bail!("socketpair: {}", std::io::Error::last_os_error());
    }
    let (psock, csock) = (sv[0], sv[1]);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        // ---- child: no allocation from here on ----
        unsafe {
            libc::close(psock);
            let cur = libc::personality(0xffff_ffff);
            if cur >= 0 && (cur as u32 & seccomp::READ_IMPLIES_EXEC) != 0 {
                let want = (cur as u32 & !seccomp::READ_IMPLIES_EXEC) as libc::c_ulong;
                if libc::personality(want) < 0 {
                    child_fail(
                        b"sxg: cannot clear READ_IMPLIES_EXEC errno=",
                        *libc::__errno_location(),
                    );
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                child_fail(
                    b"sxg: PR_SET_NO_NEW_PRIVS failed errno=",
                    *libc::__errno_location(),
                );
            }
            if let Err(e) = landlock::restrict_self(ll.fd) {
                child_fail(b"sxg: landlock_restrict_self failed errno=", e);
            }
            libc::close(ll.fd);
            let lfd = match seccomp::install_with_listener(&filter) {
                Ok(fd) => fd,
                Err(e) => child_fail(b"sxg: seccomp NEW_LISTENER failed errno=", e),
            };
            let e = send_fd(csock, lfd);
            if e != 0 {
                child_fail(b"sxg: send listener failed errno=", e);
            }
            libc::close(lfd);
            let mut ack = [0u8; 1];
            if libc::read(csock, ack.as_mut_ptr().cast(), 1) != 1 {
                child_fail(b"sxg: supervisor did not ack errno=", 0);
            }
            libc::close(csock);
            libc::syscall(
                libc::SYS_execveat,
                memfd,
                empty.as_ptr(),
                p_argv.as_ptr(),
                p_env.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            child_fail(
                b"sxg: execveat(memfd) failed errno=",
                *libc::__errno_location(),
            );
        }
    }
    // ---- parent / supervisor ----
    unsafe {
        libc::close(csock);
        libc::close(ll.fd);
    }
    let listener = match recv_fd(psock) {
        Ok(fd) => fd,
        Err(e) => {
            let st = wait_child(pid);
            unsafe { libc::close(psock) };
            return Err(anyhow!("{e}; child status {st:?}"));
        }
    };
    let denied = Arc::new(AtomicU32::new(0));
    let denied_t = denied.clone();
    let verbose = policy.verbose;
    let lfd = listener.as_raw_fd();
    let child = pid as u32;
    let expected_fd = memfd as u64;
    unsafe {
        libc::write(psock, b"k".as_ptr().cast(), 1);
        libc::close(psock);
    }
    let sup = std::thread::spawn(move || {
        let mut allowed_first = false;
        loop {
            let n = match seccomp::notif_recv(lfd) {
                Ok(n) => n,
                Err(e)
                    if e.raw_os_error() == Some(libc::EINTR)
                        || e.raw_os_error() == Some(libc::ENOENT) =>
                {
                    continue
                }
                Err(_) => break,
            };
            let nr = n.data.nr as u32;
            let first_ok = !allowed_first
                && n.pid == child
                && nr == seccomp::SYS_EXECVEAT
                && (n.data.args[0] & 0xffff_ffff) == expected_fd
                && (n.data.args[4] & 0xffff_ffff) == libc::AT_EMPTY_PATH as u64;
            let resp = if first_ok {
                allowed_first = true;
                seccomp::SeccompNotifResp {
                    id: n.id,
                    val: 0,
                    error: 0,
                    flags: seccomp::SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                }
            } else {
                denied_t.fetch_add(1, Ordering::SeqCst);
                if verbose {
                    eprintln!(
                        "sxg: denied {} by pid {}",
                        if nr == seccomp::SYS_EXECVE {
                            "execve"
                        } else {
                            "execveat"
                        },
                        n.pid
                    );
                }
                seccomp::SeccompNotifResp {
                    id: n.id,
                    val: 0,
                    error: -libc::EPERM,
                    flags: 0,
                }
            };
            let _ = seccomp::notif_send(lfd, &resp);
        }
    });
    let st = wait_child(pid);
    // Keep the listener open until the direct child is gone; descendants that
    // outlive it get ENOSYS for exec once the listener closes (fail closed).
    drop(listener);
    let _ = sup.join();
    let (exit_code, signal) = st?;
    Ok(RunReport {
        exit_code,
        signal,
        denied_execs: denied.load(Ordering::SeqCst),
    })
}

fn wait_child(pid: libc::pid_t) -> Result<(i32, Option<i32>)> {
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            bail!("waitpid: {}", std::io::Error::last_os_error());
        }
        break;
    }
    if libc::WIFEXITED(status) {
        Ok((libc::WEXITSTATUS(status), None))
    } else if libc::WIFSIGNALED(status) {
        let s = libc::WTERMSIG(status);
        Ok((128 + s, Some(s)))
    } else {
        Ok((EXIT_SETUP, None))
    }
}

/// Convenience used by the CLI: deny => Err with EXIT_DENIED semantics.
pub fn gate(
    path: &str,
    key: &p256::ecdsa::VerifyingKey,
    sig_b64: Option<&str>,
    argv: &[String],
    policy: &Policy,
) -> Result<RunReport, (i32, String)> {
    let sig_b64 = sig_b64.ok_or((EXIT_DENIED, format!("denied: no signature for {path}")))?;
    let sealed = load_and_verify(path, key, sig_b64, policy)
        .map_err(|e| (EXIT_DENIED, format!("denied: {e:#}")))?;
    if policy.verbose {
        eprintln!(
            "sxg: verified sha256:{} interp={:?}",
            sealed.sha256, sealed.info.interp
        );
    }
    run_sealed(sealed, argv, policy).map_err(|e| {
        (
            EXIT_SETUP,
            format!("sandbox setup failed (fail closed): {e:#}"),
        )
    })
}
