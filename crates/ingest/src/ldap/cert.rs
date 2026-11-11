//! Just enough X.509 for ADCS: SHA-1 thumbprints (what
//! `X509Certificate2.Thumbprint` returns) and the raw issuer / subject names
//! used to rebuild CA chains from the certificates published in AD.

/// SHA-1 (FIPS 180-4). Used only for certificate thumbprints.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, x) in w.iter_mut().enumerate().take(16) {
            *x = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, x) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

/// Uppercase hex SHA-1 of a DER certificate.
pub fn thumbprint(der: &[u8]) -> String {
    use std::fmt::Write;
    sha1(der).iter().fold(String::with_capacity(40), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

/// One DER TLV at `b[0..]`: `(tag, content, total length)`.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], usize)> {
    let tag = *b.first()?;
    let l0 = *b.get(1)? as usize;
    let (len, hdr) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = len << 8 | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let content = b.get(hdr..hdr + len)?;
    Some((tag, content, hdr + len))
}

/// Raw DER `(issuer, subject)` names of a certificate.
pub fn issuer_subject(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut p = 0;
    let mut fields = Vec::with_capacity(6);
    while p < tbs.len() && fields.len() < 6 {
        let (tag, _, n) = tlv(&tbs[p..])?;
        fields.push((tag, &tbs[p..p + n]));
        p += n;
    }
    // [0] version is optional: issuer is field 3 with it, 2 without.
    let base = usize::from(fields.first()?.0 == 0xA0);
    Some((fields.get(base + 2)?.1, fields.get(base + 4)?.1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_vectors() {
        assert_eq!(thumbprint(b"abc"), "A9993E364706816ABA3E25717850C26C9CD0D89D");
        assert_eq!(thumbprint(b""), "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
        let long = vec![b'a'; 1000];
        assert_eq!(thumbprint(&long), "291E9A6C66994949B57BA5E650361E98FC36B1BA");
    }

    #[test]
    fn names() {
        let c = fake_cert(b"ISS", b"SUB");
        let (i, s) = issuer_subject(&c).unwrap();
        assert!(i.ends_with(b"ISS") && s.ends_with(b"SUB"));
    }

    /// Minimal certificate-shaped DER with the given issuer / subject name bytes
    /// (structure only).
    fn fake_cert(issuer: &[u8], subject: &[u8]) -> Vec<u8> {
        fn wrap(tag: u8, c: &[u8]) -> Vec<u8> {
            let mut v = vec![tag];
            if c.len() < 0x80 {
                v.push(c.len() as u8);
            } else {
                v.push(0x82);
                v.extend_from_slice(&(c.len() as u16).to_be_bytes());
            }
            v.extend_from_slice(c);
            v
        }
        let mut tbs = wrap(0xA0, &wrap(0x02, &[2]));
        tbs.extend(wrap(0x02, &[1]));
        tbs.extend(wrap(0x30, &[]));
        tbs.extend(wrap(0x30, issuer));
        tbs.extend(wrap(0x30, &[]));
        tbs.extend(wrap(0x30, subject));
        let mut cert = wrap(0x30, &tbs);
        cert.extend(wrap(0x30, &[]));
        wrap(0x30, &cert)
    }
}
