use std::time::{Duration, Instant};

use attic::nix_store::NixStore;
use futures::StreamExt;
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("expected store path")?;
    let delay = Duration::from_micros(args.next().unwrap_or_default().parse().unwrap_or(0));
    let cancel = args.next().as_deref() == Some("cancel");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async {
        let store = NixStore::connect()?;
        let path = store.parse_store_path(path)?;
        let mut stream = store.nar_from_path(path);
        let mut hash = Sha256::new();
        let mut bytes = 0_u64;
        let started = Instant::now();
        while let Some(block) = stream.next().await {
            let block = block?;
            bytes += block.len() as u64;
            hash.update(&block);
            if cancel {
                break;
            }
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
        println!(
            "bytes={bytes} elapsed_seconds={:.6} sha256={} cancelled={cancel}",
            started.elapsed().as_secs_f64(),
            hex::encode(hash.finalize()),
        );
        Ok::<_, attic::AtticError>(())
    })?;
    Ok(())
}
