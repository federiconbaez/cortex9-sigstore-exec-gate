//! Reproducible measurement: builds the corpus from fixtures/src, runs every
//! item through `sxg run`, and checks the acceptance thresholds.
//! Exit 0 only if every threshold holds; prints JSON to stdout.
//!
//! usage: sxg-measure [--sxg PATH] [--work DIR] [--signed N] [--unsigned N]
//!                    [--tampered N] [--foreign N] [--timing N]

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::time::Duration;
use sxg::corpus::{self, Corpus};

fn arg(args: &[String], k: &str, d: &str) -> String {
    args.iter()
        .position(|a| a == k)
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| d.to_string())
}

fn pct(v: &mut [Duration], p: f64) -> f64 {
    v.sort();
    if v.is_empty() {
        return f64::NAN;
    }
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v[i].as_secs_f64() * 1e3
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let here = std::env::current_exe()?;
    let default_sxg = here.with_file_name("sxg");
    let sxg = PathBuf::from(arg(&args, "--sxg", &default_sxg.to_string_lossy()));
    let work = PathBuf::from(arg(&args, "--work", "corpus"));
    let n_signed: usize = arg(&args, "--signed", "50").parse()?;
    let n_unsigned: usize = arg(&args, "--unsigned", "50").parse()?;
    let n_tampered: usize = arg(&args, "--tampered", "20").parse()?;
    let n_foreign: usize = arg(&args, "--foreign", "10").parse()?;
    let n_timing: usize = arg(&args, "--timing", "30").parse()?;
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/src");
    if work.exists() {
        std::fs::remove_dir_all(&work)?;
    }
    let c = Corpus::new(&work, &src)?;
    let key = c.key_pub.clone();

    // ---- build ----
    let mut signed = Vec::new();
    for i in 0..n_signed {
        let st = i % 2 == 1;
        let p = c.build(
            "ok",
            &format!("ok_{i:02}"),
            &[format!("TAG=\"{i:02}\"")],
            if st { &["-static"] } else { &[] },
        )?;
        c.sign(&p)?;
        signed.push((p, format!("MARK:OK-{i:02}")));
    }
    let mut unsigned = Vec::new();
    for i in 0..n_unsigned {
        let st = i % 2 == 1;
        let p = c.build(
            "ok",
            &format!("unsigned_{i:02}"),
            &[format!("TAG=\"U{i:02}\"")],
            if st { &["-static"] } else { &[] },
        )?;
        unsigned.push(p);
    }
    let mut tampered = Vec::new();
    for i in 0..n_tampered {
        let to = c.path(&format!("tampered_{i:02}"));
        corpus::tamper(&signed[i % signed.len()].0, &to)?;
        tampered.push(to);
    }
    let mut foreign = Vec::new();
    for i in 0..n_foreign {
        let p = c.build(
            "ok",
            &format!("foreign_{i:02}"),
            &[format!("TAG=\"F{i:02}\"")],
            &[],
        )?;
        c.sign_foreign(&p)?;
        foreign.push(p);
    }
    // positive controls: signature strip / empty / garbage, exec-stack ELF
    let strip = c.path("ctl_sigstrip");
    std::fs::copy(&signed[0].0, &strip)?;
    let empty = c.path("ctl_sigempty");
    std::fs::copy(&signed[0].0, &empty)?;
    std::fs::write(corpus::sig_path(&empty), "")?;
    let garbage = c.path("ctl_siggarbage");
    std::fs::copy(&signed[0].0, &garbage)?;
    std::fs::write(corpus::sig_path(&garbage), "MEUCIQDdeadbeef")?;
    let execstack = c.build("execstack", "ctl_execstack", &[], &["-z", "execstack"])?;
    c.sign(&execstack)?;
    let controls = vec![strip, empty, garbage, execstack];

    let payload = c.build("payload", "payload_unsigned", &[], &[])?;
    let payload_s = payload.to_string_lossy().into_owned();
    let mut bypass = Vec::new();
    for (name, extra) in [
        ("bypass_execve", vec![]),
        ("bypass_pkey", vec![]),
        ("bypass_int80", vec!["-no-pie"]),
        ("bypass_rie", vec![]),
        ("bypass_notif_override", vec!["-pthread"]),
    ] {
        let p = c.build(name, name, &[], &extra)?;
        c.sign(&p)?;
        bypass.push(p);
    }

    // ---- run ----
    let mut ok_runs = 0usize;
    let mut ok_fail = Vec::new();
    for (p, m) in &signed {
        let r = corpus::run_gated(&sxg, &key, p, &[], false)?;
        if r.code() == 0 && r.stdout().contains(m.as_str()) {
            ok_runs += 1;
        } else {
            ok_fail.push(format!(
                "{}: code {} {}",
                p.display(),
                r.code(),
                r.stderr().trim()
            ));
        }
    }
    let count_exec = |set: &[PathBuf]| -> Result<(usize, usize)> {
        let (mut executed, mut denied126) = (0, 0);
        for p in set {
            let r = corpus::run_gated(&sxg, &key, p, &[], false)?;
            if r.executed_marker() {
                executed += 1;
            }
            if r.code() == sxg::EXIT_DENIED {
                denied126 += 1;
            }
        }
        Ok((executed, denied126))
    };
    let (unsigned_exec, unsigned_denied) = count_exec(&unsigned)?;
    let (tampered_exec, tampered_denied) = count_exec(&tampered)?;
    let (foreign_exec, foreign_denied) = count_exec(&foreign)?;
    let (controls_exec, controls_denied) = count_exec(&controls)?;
    // direct-run controls: unattested binaries are runnable without the gate
    let tampered_direct_runs = tampered
        .iter()
        .filter(|p| {
            corpus::run_direct(p, &[], false)
                .map(|r| r.stdout().contains("MARK:TK-"))
                .unwrap_or(false)
        })
        .count();
    let unsigned_direct_runs = unsigned
        .iter()
        .filter(|p| {
            corpus::run_direct(p, &[], false)
                .map(|r| r.stdout().contains("MARK:OK-U"))
                .unwrap_or(false)
        })
        .count();

    // bypasses: (name, args, inherited RIE persona)
    let cases: Vec<(&str, &PathBuf, Vec<&str>, bool)> = vec![
        ("execve", &bypass[0], vec![payload_s.as_str()], false),
        ("pkey_mprotect", &bypass[1], vec![], false),
        ("int80", &bypass[2], vec![payload_s.as_str()], false),
        ("read_implies_exec", &bypass[3], vec![], false),
        (
            "read_implies_exec_inherited",
            &bypass[3],
            vec!["inherited"],
            true,
        ),
        (
            "seccomp_notif_override",
            &bypass[4],
            vec![payload_s.as_str()],
            false,
        ),
    ];
    let mut bypass_rows = Vec::new();
    let mut bypass_gated_pwned = 0;
    let mut bypass_direct_pwned = 0;
    for (name, p, a, rie) in &cases {
        let g = corpus::run_gated(&sxg, &key, p, a, *rie)?;
        let d = corpus::run_direct(p, a, *rie)?;
        if g.pwned() {
            bypass_gated_pwned += 1;
        }
        if d.pwned() {
            bypass_direct_pwned += 1;
        }
        bypass_rows.push(format!(
            "{{\"case\":\"{name}\",\"gated_pwned\":{},\"gated_exit\":{},\"gated_stdout\":{:?},\"direct_pwned\":{},\"direct_stdout\":{:?}}}",
            g.pwned(),
            g.code(),
            g.stdout().trim(),
            d.pwned(),
            d.stdout().trim()
        ));
    }

    // ---- timing: gate vs direct on the same signed binaries ----
    let mut tg = Vec::new();
    let mut td = Vec::new();
    for i in 0..n_timing {
        let (p, _) = &signed[i % signed.len()];
        td.push(corpus::run_direct(p, &[], false)?.wall);
        tg.push(corpus::run_gated(&sxg, &key, p, &[], false)?.wall);
    }

    let ok_rate = ok_runs as f64 / n_signed.max(1) as f64;
    let pass = ok_rate >= 0.95
        && unsigned_exec == 0
        && tampered_exec == 0
        && foreign_exec == 0
        && controls_exec == 0
        && bypass_gated_pwned == 0;
    let json = format!(
        "{{\n \"signed_ok\": \"{ok_runs}/{n_signed}\",\n \"unsigned_executed\": \"{unsigned_exec}/{n_unsigned}\", \"unsigned_denied_126\": {unsigned_denied}, \"unsigned_runnable_direct\": {unsigned_direct_runs},\n \"tampered_executed\": \"{tampered_exec}/{n_tampered}\", \"tampered_denied_126\": {tampered_denied}, \"tampered_runnable_direct\": {tampered_direct_runs},\n \"foreign_key_executed\": \"{foreign_exec}/{n_foreign}\", \"foreign_denied_126\": {foreign_denied},\n \"controls_executed\": \"{controls_exec}/{}\", \"controls_denied_126\": {controls_denied},\n \"bypass_gated_pwned\": \"{bypass_gated_pwned}/{}\", \"bypass_direct_control_pwned\": \"{bypass_direct_pwned}/{}\",\n \"bypass\": [\n  {}\n ],\n \"timing_ms\": {{\"n\": {n_timing}, \"direct_p50\": {:.2}, \"direct_p95\": {:.2}, \"gated_p50\": {:.2}, \"gated_p95\": {:.2}}},\n \"ok_failures\": {:?},\n \"pass\": {pass}\n}}",
        controls.len(),
        cases.len(),
        cases.len(),
        bypass_rows.join(",\n  "),
        pct(&mut td, 0.5),
        pct(&mut td, 0.95),
        pct(&mut tg, 0.5),
        pct(&mut tg, 0.95),
        ok_fail,
    );
    println!("{json}");
    std::fs::write(work.join("results.json"), &json).context("write results.json")?;
    if !pass {
        eprintln!("sxg-measure: THRESHOLDS NOT MET");
        std::process::exit(1);
    }
    Ok(())
}
