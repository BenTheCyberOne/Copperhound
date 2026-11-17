//! Opt-in network probes for the built-in LDAP collector: the facts NTLM relay
//! edges need that LDAP does not hold. Each probe is unauthenticated (or uses
//! throwaway credentials) and makes one short connection per host:
//!
//! * **SMB signing** (TCP 445): an SMB2 NEGOTIATE request; the response's
//!   security mode says whether the server *requires* signing
//!   (`SMB2_NEGOTIATE_SIGNING_REQUIRED`). Stored as `smbsigning`, as
//!   SharpHound does (true = required).
//! * **LDAP signing** (domain controllers, TCP 389): a simple bind with a
//!   throwaway DN and random password. A DC that requires signing rejects it
//!   with `strongerAuthRequired` (8) before checking the credentials; one that
//!   does not answers `invalidCredentials` (49). The collector's own
//!   credentials are never sent without TLS.
//! * **LDAP / LDAPS available** (TCP 389 / 636): the port accepts connections.
//! * **AD CS web enrollment** (enterprise CA hosts): `GET http://<host>/certsrv/`
//!   without credentials. A 401 offering NTLM or Negotiate means the endpoint
//!   accepts relayed NTLM over HTTP (ESC8).
//!
//! Not probed (they need an authenticated NTLM exchange): the WebClient
//! service, LDAPS channel binding, HTTPS Extended Protection and CA RPC
//! encryption; and the outbound NTLM policy, which is in the registry. Collect
//! those with SharpHound; the target's "assume outgoing NTLM allowed" option
//! fills in the Windows default (allowed) for the last one.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(4);

/// What the probes found for one host. `None` means "not determined".
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostFacts {
    pub smb_signing_required: Option<bool>,
    pub ldap_signing_required: Option<bool>,
    pub ldap_available: Option<bool>,
    pub ldaps_available: Option<bool>,
    /// Web enrollment URLs that accept NTLM over plain HTTP.
    pub http_enrollment: Option<Vec<String>>,
}

async fn connect(host: &str, port: u16) -> Option<TcpStream> {
    let addr = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = tokio::time::timeout(TIMEOUT, tokio::net::lookup_host(addr)).await.ok()?.ok()?.collect();
    for a in addrs {
        if let Ok(Ok(s)) = tokio::time::timeout(TIMEOUT, TcpStream::connect(a)).await {
            return Some(s);
        }
    }
    None
}

/// A TCP connection to `host:port` succeeds.
pub async fn port_open(host: &str, port: u16) -> bool {
    connect(host, port).await.is_some()
}

/// SMB2 NEGOTIATE request (dialects 2.0.2 to 3.0.2), with the NetBIOS
/// session header.
pub fn smb2_negotiate() -> Vec<u8> {
    let dialects: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];
    let mut smb = Vec::with_capacity(64 + 36 + 8);
    // SMB2 header
    smb.extend_from_slice(b"\xfeSMB");
    smb.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    smb.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    smb.extend_from_slice(&0u32.to_le_bytes()); // Status
    smb.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
    smb.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    smb.extend_from_slice(&0u32.to_le_bytes()); // Flags
    smb.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    smb.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    smb.extend_from_slice(&0u32.to_le_bytes()); // Reserved (ProcessId)
    smb.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    smb.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    smb.extend_from_slice(&[0u8; 16]); // Signature
    // NEGOTIATE request
    smb.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    smb.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
    smb.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    smb.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    smb.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    smb.extend_from_slice(b"CopperHoundProbe"); // ClientGuid (16 bytes)
    smb.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime
    for d in dialects {
        smb.extend_from_slice(&d.to_le_bytes());
    }
    let mut out = vec![0u8, 0, 0, 0];
    out[1..4].copy_from_slice(&(smb.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&smb);
    out
}

/// Signing required, from an SMB2 NEGOTIATE response (with NetBIOS header);
/// `None` if it is not a successful SMB2 negotiate response.
pub fn smb2_signing_required(resp: &[u8]) -> Option<bool> {
    let smb = resp.get(4..)?;
    if smb.get(0..4)? != b"\xfeSMB" {
        return None;
    }
    let status = u32::from_le_bytes(smb.get(8..12)?.try_into().ok()?);
    let command = u16::from_le_bytes(smb.get(12..14)?.try_into().ok()?);
    if status != 0 || command != 0 {
        return None;
    }
    let body = smb.get(64..)?;
    let size = u16::from_le_bytes(body.get(0..2)?.try_into().ok()?);
    if size != 65 {
        return None;
    }
    let mode = u16::from_le_bytes(body.get(2..4)?.try_into().ok()?);
    Some(mode & 0x0002 != 0)
}

pub async fn smb_signing_required(host: &str) -> Option<bool> {
    let mut s = connect(host, 445).await?;
    tokio::time::timeout(TIMEOUT, s.write_all(&smb2_negotiate())).await.ok()?.ok()?;
    let mut head = [0u8; 4];
    tokio::time::timeout(TIMEOUT, s.read_exact(&mut head)).await.ok()?.ok()?;
    let len = u32::from_be_bytes([0, head[1], head[2], head[3]]) as usize;
    if !(64..=65_536).contains(&len) {
        return None;
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(TIMEOUT, s.read_exact(&mut body)).await.ok()?.ok()?;
    let mut full = head.to_vec();
    full.extend_from_slice(&body);
    smb2_signing_required(&full)
}

/// LDAP signing required on the DC, from a simple bind with throwaway credentials.
pub async fn ldap_signing_required(host: &str) -> Option<bool> {
    let settings = ldap3::LdapConnSettings::new().set_conn_timeout(TIMEOUT);
    let (conn, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &format!("ldap://{host}:389")).await.ok()?;
    ldap3::drive!(conn);
    let mut pw = [0u8; 18];
    getrandom::getrandom(&mut pw).ok()?;
    let pw: String = pw.iter().map(|b| format!("{b:02x}")).collect();
    let r = tokio::time::timeout(TIMEOUT, ldap.simple_bind("CN=CopperHound Signing Probe", &pw)).await.ok()?.ok()?;
    let _ = ldap.unbind().await;
    match r.rc {
        8 => Some(true),
        49 => Some(false),
        _ => None,
    }
}

/// The URL accepts NTLM without TLS: 401 with an NTLM or Negotiate challenge.
pub fn offers_ntlm(status: u16, www_authenticate: &[String]) -> bool {
    status == 401
        && www_authenticate.iter().any(|h| {
            let h = h.trim_start().to_ascii_lowercase();
            h.starts_with("ntlm") || h.starts_with("negotiate")
        })
}

pub async fn http_enrollment(host: &str) -> Option<Vec<String>> {
    let url = format!("http://{host}/certsrv/");
    let client = reqwest::Client::builder().timeout(TIMEOUT).redirect(reqwest::redirect::Policy::none()).build().ok()?;
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        // Nothing listening on HTTP: no vulnerable HTTP endpoint.
        Err(e) if e.is_connect() => return Some(Vec::new()),
        Err(_) => return None,
    };
    let auth: Vec<String> = resp.headers().get_all("www-authenticate").iter().filter_map(|v| v.to_str().ok().map(str::to_string)).collect();
    Some(if offers_ntlm(resp.status().as_u16(), &auth) { vec![url] } else { Vec::new() })
}

/// Probe one host for the facts that apply to its role.
pub async fn probe_host(host: &str, is_dc: bool, is_ca: bool) -> HostFacts {
    let mut f = HostFacts { smb_signing_required: smb_signing_required(host).await, ..Default::default() };
    if is_dc {
        f.ldap_available = Some(port_open(host, 389).await);
        f.ldaps_available = Some(port_open(host, 636).await);
        if f.ldap_available == Some(true) {
            f.ldap_signing_required = ldap_signing_required(host).await;
        }
    }
    if is_ca {
        f.http_enrollment = http_enrollment(host).await;
    }
    f
}

/// Run `probe_host` over many hosts with bounded concurrency.
pub async fn probe_all(hosts: Vec<(String, bool, bool)>, concurrency: usize) -> Vec<(String, HostFacts)> {
    use futures_util::stream::{self, StreamExt};
    stream::iter(hosts)
        .map(|(h, dc, ca)| async move {
            let f = probe_host(&h, dc, ca).await;
            (h, f)
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(mode: u16) -> Vec<u8> {
        let mut smb = Vec::new();
        smb.extend_from_slice(b"\xfeSMB");
        smb.extend_from_slice(&64u16.to_le_bytes());
        smb.extend_from_slice(&[0u8; 58]);
        smb.extend_from_slice(&65u16.to_le_bytes());
        smb.extend_from_slice(&mode.to_le_bytes());
        smb.extend_from_slice(&[0u8; 60]);
        let mut out = vec![0u8, 0, 0, smb.len() as u8];
        out.extend_from_slice(&smb);
        out
    }

    #[test]
    fn negotiate_request_layout() {
        let r = smb2_negotiate();
        assert_eq!(&r[4..8], b"\xfeSMB");
        let len = u32::from_be_bytes([0, r[1], r[2], r[3]]) as usize;
        assert_eq!(len, r.len() - 4);
        assert_eq!(len, 64 + 36 + 8);
        assert_eq!(u16::from_le_bytes([r[68], r[69]]), 36);
        assert_eq!(u16::from_le_bytes([r[70], r[71]]), 4);
    }

    #[test]
    fn signing_from_response() {
        assert_eq!(smb2_signing_required(&response(0x01)), Some(false));
        assert_eq!(smb2_signing_required(&response(0x03)), Some(true));
        let mut bad = response(0x03);
        bad[12] = 1; // status != 0
        assert_eq!(smb2_signing_required(&bad), None);
        assert_eq!(smb2_signing_required(b"\0\0\0\x04\xffSMB"), None);
    }

    #[test]
    fn ntlm_challenge() {
        assert!(offers_ntlm(401, &["NTLM".into()]));
        assert!(offers_ntlm(401, &["Basic realm=x".into(), "Negotiate".into()]));
        assert!(!offers_ntlm(401, &["Basic realm=x".into()]));
        assert!(!offers_ntlm(200, &["NTLM".into()]));
    }
}
