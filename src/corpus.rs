//! Fixture corpus builder + runner shared by `sxg-measure` and the
//! integration tests. Requires a C compiler (`cc`) with static glibc.

use crate::sig;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

pub struct Corpus {
    pub dir: PathBuf,
    pub src: PathBuf,
    pub key_pub: PathBuf,
    pub sk: p256::ecdsa::SigningKey,
    pub foreign_sk: p256::ecdsa::SigningKey,
}

pub fn cc(src: &Path, out: &Path, defines: &[String], extra: &[&str]) -> Result<()> {
    let mut c = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()));
    c.arg("-O1").arg("-o").arg(out).arg(src);
    for d in defines {
        c.arg(format!("-D{d}"));
    }
    c.args(extra);
    let o = c
        .output()
        .context("running cc (a C toolchain is required for the corpus)")?;
    if !o.status.success() {
        bail!(
            "cc {} failed: {}",
            src.display(),
            String::from_utf8_lossy(&o.stderr)
        );
    }
    Ok(())
}

impl Corpus {
    pub fn new(dir: &Path, src: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let (k, p) = sig::keygen()?;
        let (fk, _) = sig::keygen()?;
        let key_pub = dir.join("test.pub");
        std::fs::write(&key_pub, p)?;
        Ok(Corpus {
            dir: dir.to_path_buf(),
            src: src.to_path_buf(),
            key_pub,
            sk: sig::load_private_pem(&k)?,
            foreign_sk: sig::load_private_pem(&fk)?,
        })
    }
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
    pub fn build(
        &self,
        fixture: &str,
        name: &str,
        defines: &[String],
        extra: &[&str],
    ) -> Result<PathBuf> {
        let out = self.path(name);
        cc(&self.src.join(format!("{fixture}.c")), &out, defines, extra)?;
        Ok(out)
    }
    pub fn sign(&self, p: &Path) -> Result<()> {
        let s = sig::sign_blob(&self.sk, &std::fs::read(p)?);
        std::fs::write(sig_path(p), s)?;
        Ok(())
    }
    pub fn sign_foreign(&self, p: &Path) -> Result<()> {
        let s = sig::sign_blob(&self.foreign_sk, &std::fs::read(p)?);
        std::fs::write(sig_path(p), s)?;
        Ok(())
    }
}

pub fn sig_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

/// Copy `from` (and its signature) to `to`, flipping MARK:OK -> MARK:TK in the
/// image. The tampered binary still runs when executed directly.
pub fn tamper(from: &Path, to: &Path) -> Result<()> {
    let mut b = std::fs::read(from)?;
    let needle = b"MARK:OK-";
    let pos = b
        .windows(needle.len())
        .position(|w| w == needle)
        .context("marker not found")?;
    b[pos + 5] = b'T';
    std::fs::write(to, &b)?;
    set_exec(to)?;
    std::fs::copy(sig_path(from), sig_path(to))?;
    Ok(())
}

pub fn set_exec(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

pub struct Run {
    pub out: Output,
    pub wall: Duration,
}
impl Run {
    pub fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.out.stdout).into_owned()
    }
    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.out.stderr).into_owned()
    }
    pub fn code(&self) -> i32 {
        use std::os::unix::process::ExitStatusExt;
        self.out
            .status
            .code()
            .unwrap_or_else(|| 128 + self.out.status.signal().unwrap_or(0))
    }
    /// Any fixture output that proves unattested code ran.
    pub fn executed_marker(&self) -> bool {
        let s = self.stdout();
        s.contains("MARK:") || s.contains("PWNED")
    }
    pub fn pwned(&self) -> bool {
        self.stdout().contains("PWNED")
    }
}

fn run_cmd(mut c: Command, read_implies_exec: bool) -> Result<Run> {
    c.stdin(Stdio::null());
    if read_implies_exec {
        use std::os::unix::process::CommandExt;
        unsafe {
            c.pre_exec(|| {
                if libc::personality(0x0040_0000) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let t = Instant::now();
    let out = c.output()?;
    Ok(Run {
        out,
        wall: t.elapsed(),
    })
}

pub fn run_gated(sxg: &Path, key: &Path, target: &Path, args: &[&str], rie: bool) -> Result<Run> {
    let mut c = Command::new(sxg);
    c.arg("run")
        .arg("--key")
        .arg(key)
        .arg("--")
        .arg(target)
        .args(args);
    run_cmd(c, rie)
}

pub fn run_direct(target: &Path, args: &[&str], rie: bool) -> Result<Run> {
    let mut c = Command::new(target);
    c.args(args);
    run_cmd(c, rie)
}
