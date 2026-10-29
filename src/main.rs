use anyhow::{bail, Context, Result};
use sxg::{gate, sig, EXIT_DENIED, EXIT_SETUP};

const USAGE: &str = "usage:
  sxg keygen <prefix>                      writes <prefix>.key (PKCS#8) and <prefix>.pub (SPKI)
  sxg sign --key <k.key> <file> [--out <file.sig>]
  sxg verify --key <k.pub> [--sig <file.sig>] <file>
  sxg run --key <k.pub> [--sig <file.sig>] [--allow-jit] [--allow-exec-stack]
          [--keep-ld-env] [-v] -- <file> [args...]
  sxg probe                                report Landlock ABI / seccomp listener support
signature default: <file>.sig (cosign sign-blob --output-signature format)";

fn take(args: &mut Vec<String>, flag: &str) -> Result<Option<String>> {
    if let Some(i) = args.iter().position(|a| a == flag) {
        if i + 1 >= args.len() {
            bail!("{flag} needs a value");
        }
        let v = args.remove(i + 1);
        args.remove(i);
        return Ok(Some(v));
    }
    Ok(None)
}
fn flag(args: &mut Vec<String>, f: &str) -> bool {
    if let Some(i) = args.iter().position(|a| a == f) {
        args.remove(i);
        return true;
    }
    false
}

fn read_sig(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn real_main() -> Result<i32> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{USAGE}");
        return Ok(2);
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "keygen" => {
            let prefix = args.first().context("keygen needs <prefix>")?;
            let (k, p) = sig::keygen()?;
            std::fs::write(format!("{prefix}.key"), k)?;
            std::fs::write(format!("{prefix}.pub"), p)?;
            Ok(0)
        }
        "sign" => {
            let key = take(&mut args, "--key")?.context("--key required")?;
            let out = take(&mut args, "--out")?;
            let file = args.first().context("file required")?;
            let sk = sig::load_private_pem(&std::fs::read_to_string(&key)?)?;
            let s = sig::sign_blob(&sk, &std::fs::read(file)?);
            std::fs::write(out.unwrap_or(format!("{file}.sig")), s)?;
            Ok(0)
        }
        "verify" => {
            let key = take(&mut args, "--key")?.context("--key required")?;
            let sigp = take(&mut args, "--sig")?;
            let file = args.first().context("file required")?.clone();
            let pk = sig::load_public_pem(&std::fs::read_to_string(&key)?)?;
            let s = read_sig(&sigp.unwrap_or(format!("{file}.sig")));
            match s.map(|s| sig::verify_blob(&pk, &std::fs::read(&file)?, &s)) {
                Some(Ok(())) => {
                    println!("Verified OK");
                    Ok(0)
                }
                Some(Err(e)) => {
                    eprintln!("denied: {e:#}");
                    Ok(EXIT_DENIED)
                }
                None => {
                    eprintln!("denied: no signature");
                    Ok(EXIT_DENIED)
                }
            }
        }
        "run" => {
            let sep = args
                .iter()
                .position(|a| a == "--")
                .context("run needs -- <file> [args]")?;
            let rest: Vec<String> = args.split_off(sep + 1);
            args.pop();
            let key = take(&mut args, "--key")?.context("--key required")?;
            let sigp = take(&mut args, "--sig")?;
            let policy = gate::Policy {
                wx: !flag(&mut args, "--allow-jit"),
                require_nx_stack: !flag(&mut args, "--allow-exec-stack"),
                scrub_env: !flag(&mut args, "--keep-ld-env"),
                verbose: flag(&mut args, "-v"),
            };
            if !args.is_empty() {
                bail!("unknown arguments: {args:?}");
            }
            let file = rest.first().context("file required after --")?.clone();
            let pk = sig::load_public_pem(&std::fs::read_to_string(&key)?)?;
            let s = read_sig(&sigp.unwrap_or(format!("{file}.sig")));
            match gate::gate(&file, &pk, s.as_deref(), &rest, &policy) {
                Ok(r) => {
                    if r.denied_execs > 0 {
                        eprintln!("sxg: {} exec attempt(s) denied", r.denied_execs);
                    }
                    if let Some(sig) = r.signal {
                        eprintln!("sxg: program killed by signal {sig}");
                    }
                    Ok(r.exit_code)
                }
                Err((code, msg)) => {
                    eprintln!("sxg: {msg}");
                    Ok(code)
                }
            }
        }
        "probe" => {
            match sxg::landlock::abi_version() {
                Ok(v) => println!("landlock_abi={v}"),
                Err(e) => println!("landlock_abi=unavailable ({e})"),
            }
            Ok(0)
        }
        _ => {
            eprintln!("{USAGE}");
            Ok(2)
        }
    }
}

fn main() {
    let code = match real_main() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sxg: {e:#}");
            EXIT_SETUP
        }
    };
    std::process::exit(code);
}
