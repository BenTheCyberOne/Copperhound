//! Convert an LDIF dump into an AD Explorer-layout snapshot (via the test
//! writer) for benchmarking the snapshot reader:
//! `cargo run --release --example ldif_to_adx -- IN.ldif OUT.dat`
use ch_ingest::ldap::{self, adexplorer, A, NEED_ALL};
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1).map(PathBuf::from);
    let (src, dst) = (args.next().expect("IN.ldif"), args.next().expect("OUT.dat"));
    let kind = ch_ingest::scan::detect(&src).expect("not a recognised input");
    let tmp = std::env::temp_dir();
    let input = ldap::open(&src, kind, &tmp)?.expect("not LDIF");
    let mut objects: Vec<adexplorer::testing::Object> = Vec::new();
    for c in 0..input.chunks() {
        input.read(c, NEED_ALL, &mut |r| {
            let Ok(e) = r else { return };
            let mut attrs: Vec<(String, Vec<Vec<u8>>)> = Vec::new();
            for (a, v) in &e.vals {
                let name = A::name(*a);
                match attrs.iter_mut().find(|(n, _)| n == name) {
                    Some((_, vs)) => vs.push(v.to_vec()),
                    None => attrs.push((name.to_string(), vec![v.to_vec()])),
                }
            }
            objects.push((e.dn.into_owned(), attrs));
        });
    }
    adexplorer::testing::write(&dst, "bench", &objects)?;
    println!("{} objects → {}", objects.len(), dst.display());
    Ok(())
}
