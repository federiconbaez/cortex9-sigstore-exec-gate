//! Raw Landlock syscalls (no crate): handle FS EXECUTE and, from ABI 6,
//! scope signals so the sandboxed tree cannot kill its supervisor.

use anyhow::{bail, Result};
use std::ffi::CString;

const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
pub const ACCESS_FS_EXECUTE: u64 = 1;
pub const SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Landlock ABI version, or an error if Landlock is unavailable.
pub fn abi_version() -> Result<i64> {
    let r = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if r < 0 {
        bail!("Landlock unavailable: {}", std::io::Error::last_os_error());
    }
    Ok(r)
}

/// A prepared ruleset fd: built in the parent (may allocate), applied in the
/// child after fork with `restrict_self` (no allocation).
pub struct Prepared {
    pub fd: i32,
    pub abi: i64,
    pub scoped_signals: bool,
}

/// Handle EXECUTE; allow it only on `exec_allow` (the ELF interpreter, which
/// the kernel opens with FMODE_EXEC). memfd images live on an internal mount
/// that Landlock does not police, so the verified memfd itself is executable.
pub fn prepare(exec_allow: &[String]) -> Result<Prepared> {
    let abi = abi_version()?;
    let scoped = abi >= 6;
    let attr = RulesetAttr {
        handled_access_fs: ACCESS_FS_EXECUTE,
        handled_access_net: 0,
        scoped: if scoped { SCOPE_SIGNAL } else { 0 },
    };
    let size = if abi >= 6 {
        std::mem::size_of::<RulesetAttr>()
    } else if abi >= 4 {
        16
    } else {
        8
    };
    let fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const RulesetAttr,
            size,
            0u32,
        )
    };
    if fd < 0 {
        bail!(
            "landlock_create_ruleset: {}",
            std::io::Error::last_os_error()
        );
    }
    let fd = fd as i32;
    for p in exec_allow {
        let c = CString::new(p.as_str())?;
        let pfd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if pfd < 0 {
            unsafe { libc::close(fd) };
            bail!("open {p}: {}", std::io::Error::last_os_error());
        }
        let rule = PathBeneathAttr {
            allowed_access: ACCESS_FS_EXECUTE,
            parent_fd: pfd,
        };
        let r = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const PathBeneathAttr,
                0u32,
            )
        };
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(pfd) };
        if r < 0 {
            unsafe { libc::close(fd) };
            bail!("landlock_add_rule {p}: {err}");
        }
    }
    Ok(Prepared {
        fd,
        abi,
        scoped_signals: scoped,
    })
}

/// Apply in the child. Returns errno on failure. No allocation.
pub fn restrict_self(fd: i32) -> Result<(), i32> {
    let r = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0u32) };
    if r < 0 {
        return Err(unsafe { *libc::__errno_location() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn attr_layout() {
        assert_eq!(std::mem::size_of::<super::RulesetAttr>(), 24);
        assert_eq!(std::mem::size_of::<super::PathBeneathAttr>(), 12);
    }
}
