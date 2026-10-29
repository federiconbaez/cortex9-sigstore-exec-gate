//! End-to-end tests: real fixtures compiled with cc, real Landlock + seccomp.
//! There is no skip path: if the kernel lacks Landlock or seccomp user
//! notification, these tests FAIL.

use std::path::{Path, PathBuf};
use sxg::corpus::{self, Corpus};

fn sxg() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sxg"))
}
fn corpus(name: &str) -> Corpus {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    Corpus::new(
        &dir,
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/src"),
    )
    .unwrap()
}

#[test]
fn prerequisites_present_no_skip() {
    let v =
        sxg::landlock::abi_version().expect("Landlock must be available: this test never skips");
    assert!(v >= 1);
}

#[test]
fn signed_dynamic_and_static_run() {
    let c = corpus("valid");
    for (i, st) in [(0, false), (1, true)] {
        let extra: &[&str] = if st { &["-static"] } else { &[] };
        let p = c
            .build("ok", &format!("ok{i}"), &[format!("TAG=\"{i:02}\"")], extra)
            .unwrap();
        c.sign(&p).unwrap();
        let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &[], false).unwrap();
        assert_eq!(r.code(), 0, "stderr: {}", r.stderr());
        assert!(r.stdout().contains(&format!("MARK:OK-{i:02}")));
    }
}

#[test]
fn unsigned_tampered_foreign_and_stripped_are_denied() {
    let c = corpus("deny");
    let p = c.build("ok", "ok", &["TAG=\"07\"".into()], &[]).unwrap();
    c.sign(&p).unwrap();
    let t = c.path("tampered");
    corpus::tamper(&p, &t).unwrap();
    let direct = corpus::run_direct(&t, &[], false).unwrap();
    assert!(
        direct.stdout().contains("MARK:TK-07"),
        "tampered fixture must be runnable without the gate"
    );
    let r = corpus::run_gated(&sxg(), &c.key_pub, &t, &[], false).unwrap();
    assert_eq!(r.code(), sxg::EXIT_DENIED);
    assert!(!r.executed_marker());
    assert!(r.stderr().contains("provenance check failed"));

    let u = c
        .build("ok", "unsigned", &["TAG=\"U1\"".into()], &[])
        .unwrap();
    let r = corpus::run_gated(&sxg(), &c.key_pub, &u, &[], false).unwrap();
    assert_eq!(r.code(), sxg::EXIT_DENIED);
    assert!(!r.executed_marker());

    let f = c
        .build("ok", "foreign", &["TAG=\"F1\"".into()], &[])
        .unwrap();
    c.sign_foreign(&f).unwrap();
    let r = corpus::run_gated(&sxg(), &c.key_pub, &f, &[], false).unwrap();
    assert_eq!(r.code(), sxg::EXIT_DENIED);
    assert!(!r.executed_marker());

    std::fs::remove_file(corpus::sig_path(&p)).unwrap();
    let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &[], false).unwrap();
    assert_eq!(r.code(), sxg::EXIT_DENIED, "signature strip must deny");
    assert!(!r.executed_marker());
}

#[test]
fn exec_stack_elf_is_refused() {
    let c = corpus("execstack");
    let p = c
        .build("execstack", "es", &[], &["-z", "execstack"])
        .unwrap();
    c.sign(&p).unwrap();
    let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &[], false).unwrap();
    assert_eq!(r.code(), sxg::EXIT_DENIED);
    assert!(r.stderr().contains("executable stack"));
}

fn bypass(name: &str, extra: &[&str]) -> (Corpus, PathBuf, String) {
    let c = corpus(name);
    let payload = c.build("payload", "payload", &[], &[]).unwrap();
    let p = c.build(name, name, &[], extra).unwrap();
    c.sign(&p).unwrap();
    (c, p, payload.to_string_lossy().into_owned())
}

#[test]
fn bypass_execve_blocked_with_working_control() {
    let (c, p, payload) = bypass("bypass_execve", &[]);
    let d = corpus::run_direct(&p, &[&payload], false).unwrap();
    assert!(
        d.pwned(),
        "control: without the gate the nested exec must succeed"
    );
    let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &[&payload], false).unwrap();
    assert!(!r.pwned(), "stdout: {}", r.stdout());
    assert!(
        r.stdout().contains("BLOCKED:execve errnos=1,1,1,1 child=1"),
        "stdout: {}",
        r.stdout()
    );
    assert!(r.stderr().contains("exec attempt(s) denied"));
}

#[test]
fn bypass_pkey_mprotect_blocked_with_working_control() {
    let (c, p, _) = bypass("bypass_pkey", &[]);
    assert!(corpus::run_direct(&p, &[], false).unwrap().pwned());
    let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &[], false).unwrap();
    assert!(!r.pwned(), "stdout: {}", r.stdout());
    assert!(r.stdout().contains("BLOCKED:wx errnos=13,13,13"));
}

#[test]
fn bypass_int80_killed() {
    let (c, p, payload) = bypass("bypass_int80", &["-no-pie"]);
    let d = corpus::run_direct(&p, &[&payload], false).unwrap();
    // The direct control depends on CONFIG_IA32_EMULATION; report it, never hide it.
    eprintln!(
        "int80 direct control: pwned={} stdout={:?}",
        d.pwned(),
        d.stdout()
    );
    let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &[&payload], false).unwrap();
    assert!(!r.pwned());
    assert_eq!(
        r.code(),
        128 + libc::SIGSYS,
        "ia32 entry must be killed by the arch check"
    );
}

#[test]
fn bypass_read_implies_exec_blocked_with_working_control() {
    let (c, p, _) = bypass("bypass_rie", &[]);
    assert!(corpus::run_direct(&p, &[], false).unwrap().pwned());
    let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &[], false).unwrap();
    assert!(!r.pwned());
    assert!(r.stdout().contains("BLOCKED:rie errno=1"));
    let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &["inherited"], true).unwrap();
    assert!(!r.pwned());
}

fn signed_sh(c: &Corpus) -> PathBuf {
    let sh = c.path("sh");
    std::fs::copy("/bin/sh", &sh).unwrap();
    c.sign(&sh).unwrap();
    sh
}

#[test]
fn ld_env_is_scrubbed() {
    let c = corpus("ldenv");
    let sh = signed_sh(&c);
    let mut cmd = std::process::Command::new(sxg());
    cmd.args(["run", "--key"])
        .arg(&c.key_pub)
        .arg("--")
        .arg(&sh);
    cmd.args([
        "-c",
        "echo pre=${LD_PRELOAD:-none} aud=${LD_AUDIT:-none} keep=${KEEPME:-none}",
    ]);
    cmd.env("LD_PRELOAD", "/nonexistent.so")
        .env("LD_AUDIT", "/x.so")
        .env("KEEPME", "yes");
    let o = cmd.output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        "pre=none aud=none keep=yes"
    );
}

#[test]
fn killing_the_supervisor_does_not_open_exec() {
    let c = corpus("killsup");
    let sh = signed_sh(&c);
    let payload = c.build("payload", "payload", &[], &[]).unwrap();
    let script = format!(
        "kill -9 $PPID; sleep 0.2; {}; echo after=$?",
        payload.display()
    );
    let r = corpus::run_gated(&sxg(), &c.key_pub, &sh, &["-c", &script], false).unwrap();
    assert!(!r.pwned(), "stdout: {} stderr: {}", r.stdout(), r.stderr());
}

#[test]
fn gate_execs_exactly_the_verified_bytes() {
    // swap the file after signing: the gate reads it once into a sealed memfd
    // and verifies those bytes, so an on-disk swap can only cause a deny.
    let c = corpus("swap");
    let p = c.build("ok", "ok", &["TAG=\"SW\"".into()], &[]).unwrap();
    c.sign(&p).unwrap();
    let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &[], false).unwrap();
    assert!(r.stdout().contains("MARK:OK-SW"));
    let u = c.build("payload", "payload", &[], &[]).unwrap();
    std::fs::copy(&u, &p).unwrap();
    let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &[], false).unwrap();
    assert_eq!(r.code(), sxg::EXIT_DENIED);
    assert!(!r.pwned());
}

#[test]
fn measure_quick_meets_thresholds() {
    let work = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("measure-quick");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_sxg-measure"))
        .args(["--work"])
        .arg(&work)
        .args([
            "--signed",
            "4",
            "--unsigned",
            "4",
            "--tampered",
            "2",
            "--foreign",
            "2",
            "--timing",
            "2",
        ])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&o.stdout);
    assert!(
        o.status.success(),
        "{s}\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(s.contains("\"pass\": true"));
}

#[test]
fn bypass_second_notifier_cannot_override_supervisor() {
    let (c, p, payload) = bypass("bypass_notif_override", &["-pthread"]);
    assert!(
        corpus::run_direct(&p, &[&payload], false).unwrap().pwned(),
        "control: own notifier + CONTINUE runs the payload"
    );
    let r = corpus::run_gated(&sxg(), &c.key_pub, &p, &[&payload], false).unwrap();
    assert!(!r.pwned(), "stdout: {}", r.stdout());
    // kernel refuses a second listener in the same filter chain (EBUSY)
    assert!(
        r.stdout().contains("BLOCKED:notif_override errnos=16,1,1"),
        "stdout: {}",
        r.stdout()
    );
}
