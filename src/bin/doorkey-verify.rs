//! Checks Doorkey specs against the signing key built into this package: each spec must carry a
//! valid signature (`<spec>.sig` next to it) and load as a Doorkey.
//!
//!     cargo run --bin doorkey-verify -- doorkeys/github.doorkey.json

use anyhow::{bail, Context, Result};
use appdoorman_keyhole::{bundled_signing_key, verify_signature, Doorkey};

fn main() -> Result<()> {
    let specs: Vec<String> = std::env::args().skip(1).collect();
    if specs.is_empty() {
        bail!("usage: doorkey-verify <spec.json>...");
    }
    for spec in &specs {
        let bytes = std::fs::read(spec).with_context(|| format!("reading {spec}"))?;
        let signature = std::fs::read_to_string(format!("{spec}.sig")).with_context(|| format!("reading {spec}.sig"))?;
        verify_signature(&bytes, &signature, bundled_signing_key()).with_context(|| spec.clone())?;
        serde_json::from_slice::<Doorkey>(&bytes).with_context(|| format!("{spec} is not a valid Doorkey"))?;
        println!("ok {spec}");
    }
    Ok(())
}
