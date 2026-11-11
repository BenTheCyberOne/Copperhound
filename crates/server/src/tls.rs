//! Built-in HTTPS (rustls, ring backend).
//!
//! * `COPPERHOUND_TLS_CERT` + `COPPERHOUND_TLS_KEY`: PEM certificate chain and
//!   private key. They are re-read when their modification time changes
//!   (checked at most every 30 s), so renewed certificates (certbot, ACME
//!   clients, cert-manager) apply without a restart.
//! * `COPPERHOUND_TLS=self-signed`: generate a self-signed certificate once into
//!   `<data>/tls/` (names: `localhost`, `127.0.0.1` and any in
//!   `COPPERHOUND_TLS_HOSTNAMES`, comma-separated). For labs; browsers warn.
//!
//! With TLS on, responses carry `Strict-Transport-Security`.

use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// TLS settings from the environment; `None` = plain HTTP.
pub fn from_env(data_dir: &Path) -> Result<Option<TlsFiles>> {
    let mode = std::env::var("COPPERHOUND_TLS").unwrap_or_default().trim().to_ascii_lowercase();
    let cert = std::env::var("COPPERHOUND_TLS_CERT").ok().filter(|s| !s.trim().is_empty());
    let key = std::env::var("COPPERHOUND_TLS_KEY").ok().filter(|s| !s.trim().is_empty());
    match (cert, key) {
        (Some(c), Some(k)) => Ok(Some(TlsFiles { cert: c.into(), key: k.into() })),
        (Some(_), None) | (None, Some(_)) => bail!("set both COPPERHOUND_TLS_CERT and COPPERHOUND_TLS_KEY"),
        (None, None) if mode == "self-signed" => {
            let names: Vec<String> = std::env::var("COPPERHOUND_TLS_HOSTNAMES")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            self_signed(&data_dir.join("tls"), &names).map(Some)
        }
        (None, None) if mode.is_empty() || mode == "off" => Ok(None),
        (None, None) => bail!("COPPERHOUND_TLS must be 'self-signed' or 'off' (or set COPPERHOUND_TLS_CERT / _KEY)"),
    }
}

/// Create (once) a self-signed certificate in `dir`.
pub fn self_signed(dir: &Path, extra: &[String]) -> Result<TlsFiles> {
    let files = TlsFiles { cert: dir.join("cert.pem"), key: dir.join("key.pem") };
    if files.cert.exists() && files.key.exists() {
        return Ok(files);
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    names.extend(extra.iter().cloned());
    let ck = rcgen::generate_simple_self_signed(names).context("generating a self-signed certificate")?;
    std::fs::write(&files.cert, ck.cert.pem())?;
    std::fs::write(&files.key, ck.key_pair.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&files.key, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!("generated a self-signed TLS certificate in {}", dir.display());
    Ok(files)
}

fn load(files: &TlsFiles) -> Result<Arc<ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&files.cert)
        .with_context(|| format!("reading {}", files.cert.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("parsing {}", files.cert.display()))?;
    if certs.is_empty() {
        bail!("no certificate in {}", files.cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(&files.key).with_context(|| format!("reading the private key {}", files.key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("certificate and key do not match")?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// TLS acceptor that picks up renewed certificate files.
pub struct Reloading {
    files: TlsFiles,
    state: Mutex<(Option<SystemTime>, Option<SystemTime>, Instant, TlsAcceptor)>,
}

impl Reloading {
    pub fn new(files: TlsFiles) -> Result<Reloading> {
        let acc = TlsAcceptor::from(load(&files)?);
        let st = (mtime(&files.cert), mtime(&files.key), Instant::now(), acc);
        Ok(Reloading { files, state: Mutex::new(st) })
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        let mut s = self.state.lock();
        if s.2.elapsed() >= Duration::from_secs(30) {
            s.2 = Instant::now();
            let (c, k) = (mtime(&self.files.cert), mtime(&self.files.key));
            if (c, k) != (s.0, s.1) {
                match load(&self.files) {
                    Ok(cfg) => {
                        tracing::info!("reloaded the TLS certificate from {}", self.files.cert.display());
                        s.3 = TlsAcceptor::from(cfg);
                        s.0 = c;
                        s.1 = k;
                    }
                    // Half-written renewal: keep serving the old one, retry later.
                    Err(e) => tracing::warn!("TLS certificate reload failed (keeping the current one): {e:#}"),
                }
            }
        }
        s.3.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_loads() {
        let d = std::env::temp_dir().join(format!("ch-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let f = self_signed(&d, &["ch.example.com".into()]).unwrap();
        assert!(load(&f).is_ok());
        let again = self_signed(&d, &[]).unwrap();
        assert_eq!(std::fs::read(&f.cert).unwrap(), std::fs::read(&again.cert).unwrap(), "kept, not regenerated");
        assert!(Reloading::new(f).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }
}
