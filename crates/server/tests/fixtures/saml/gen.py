"""Generate signed SAML test responses with an independent implementation:
libxml2's exclusive C14N (lxml) and `cryptography` for RSA. The Rust verifier
in crates/server/src/samlxml.rs must accept the valid ones and reject the rest.

    python crates/server/tests/fixtures/saml/gen.py

Keys are test-only and generated once (kept so the fixtures are stable).
"""

import base64
import datetime
import hashlib
import os
import copy

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from lxml import etree

HERE = os.path.dirname(os.path.abspath(__file__))
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
DS = "http://www.w3.org/2000/09/xmldsig#"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"
IDP = "https://idp.example.com/saml"
SP = "https://copperhound.example.com/api/v1/auth/saml/metadata"
ACS = "https://copperhound.example.com/api/v1/auth/saml/acs"
REQ = "_req-0123456789abcdef"


def key(name):
    path = os.path.join(HERE, name + "_key.pem")
    if os.path.exists(path):
        with open(path, "rb") as f:
            k = serialization.load_pem_private_key(f.read(), None)
    else:
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(path, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    t = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(cn)
        .issuer_name(cn)
        .public_key(k.public_key())
        .serial_number(1)
        .not_valid_before(t)
        .not_valid_after(t + datetime.timedelta(days=3650))
        .sign(k, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(os.path.join(HERE, name + "_cert.pem"), "wb") as f:
        f.write(pem)
    return k, base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def c14n(node, incl=None):
    return etree.tostring(node, method="c14n", exclusive=True, with_comments=False, inclusive_ns_prefixes=incl)


def sign(elem, k, after, sig_alg="rsa-sha256", digest="sha256", incl=None):
    """Enveloped signature on `elem`, inserted after child `after` (index)."""
    algs = {
        "sha256": ("http://www.w3.org/2001/04/xmlenc#sha256", hashlib.sha256, hashes.SHA256()),
        "sha1": ("http://www.w3.org/2000/09/xmldsig#sha1", hashlib.sha1, hashes.SHA1()),
    }
    sig_uri = {"rsa-sha256": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "rsa-sha1": "http://www.w3.org/2000/09/xmldsig#rsa-sha1"}[sig_alg]
    d_uri, d_fn, _ = algs[digest]
    dv = base64.b64encode(d_fn(c14n(elem, incl)).digest()).decode()
    E = lambda tag, **a: etree.Element("{%s}%s" % (DS, tag), nsmap={"ds": DS}, **a)
    sig = E("Signature")
    si = etree.SubElement(sig, "{%s}SignedInfo" % DS)
    etree.SubElement(si, "{%s}CanonicalizationMethod" % DS, Algorithm=EXC)
    etree.SubElement(si, "{%s}SignatureMethod" % DS, Algorithm=sig_uri)
    ref = etree.SubElement(si, "{%s}Reference" % DS, URI="#" + elem.get("ID"))
    ts = etree.SubElement(ref, "{%s}Transforms" % DS)
    etree.SubElement(ts, "{%s}Transform" % DS, Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    t = etree.SubElement(ts, "{%s}Transform" % DS, Algorithm=EXC)
    if incl:
        etree.SubElement(t, "{%s}InclusiveNamespaces" % EXC, PrefixList=" ".join(incl), nsmap={"ec": EXC})
    etree.SubElement(ref, "{%s}DigestMethod" % DS, Algorithm=d_uri)
    etree.SubElement(ref, "{%s}DigestValue" % DS).text = dv
    sv = etree.SubElement(sig, "{%s}SignatureValue" % DS)
    ki = etree.SubElement(sig, "{%s}KeyInfo" % DS)
    elem.insert(after, sig)
    h = hashes.SHA1() if sig_alg == "rsa-sha1" else hashes.SHA256()
    sv.text = base64.b64encode(k.sign(c14n(si), padding.PKCS1v15(), h)).decode()
    return sig


def response(assertion_id="_a-1", resp_id="_r-1", name="alice@example.com", groups=("CH-Admins", "Staff")):
    nsmap = {"samlp": SAMLP, "saml": SAML, "xs": "http://www.w3.org/2001/XMLSchema", "xsi": "http://www.w3.org/2001/XMLSchema-instance"}
    r = etree.Element("{%s}Response" % SAMLP, nsmap=nsmap, ID=resp_id, Version="2.0", IssueInstant="2026-01-01T00:00:00Z", Destination=ACS, InResponseTo=REQ)
    etree.SubElement(r, "{%s}Issuer" % SAML).text = IDP
    st = etree.SubElement(r, "{%s}Status" % SAMLP)
    etree.SubElement(st, "{%s}StatusCode" % SAMLP, Value="urn:oasis:names:tc:SAML:2.0:status:Success")
    a = etree.SubElement(r, "{%s}Assertion" % SAML, ID=assertion_id, Version="2.0", IssueInstant="2026-01-01T00:00:00Z")
    etree.SubElement(a, "{%s}Issuer" % SAML).text = IDP
    sub = etree.SubElement(a, "{%s}Subject" % SAML)
    etree.SubElement(sub, "{%s}NameID" % SAML, Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress").text = name
    sc = etree.SubElement(sub, "{%s}SubjectConfirmation" % SAML, Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
    etree.SubElement(sc, "{%s}SubjectConfirmationData" % SAML, InResponseTo=REQ, NotOnOrAfter="2026-01-01T00:05:00Z", Recipient=ACS)
    c = etree.SubElement(a, "{%s}Conditions" % SAML, NotBefore="2025-12-31T23:59:00Z", NotOnOrAfter="2026-01-01T00:05:00Z")
    ar = etree.SubElement(c, "{%s}AudienceRestriction" % SAML)
    etree.SubElement(ar, "{%s}Audience" % SAML).text = SP
    ast = etree.SubElement(a, "{%s}AttributeStatement" % SAML)
    at = etree.SubElement(ast, "{%s}Attribute" % SAML, Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")
    for g in groups:
        v = etree.SubElement(at, "{%s}AttributeValue" % SAML)
        v.set("{http://www.w3.org/2001/XMLSchema-instance}type", "xs:string")
        v.text = g
    at = etree.SubElement(ast, "{%s}Attribute" % SAML, Name="email", FriendlyName="mail")
    etree.SubElement(at, "{%s}AttributeValue" % SAML).text = name
    return r, a


def reparse(r):
    """Serialise and parse again. libxml2 canonicalises freshly built trees
    differently from parsed ones (inherited namespaces in the inclusive
    prefix list are skipped); receivers always see parsed documents."""
    r = etree.fromstring(etree.tostring(r))
    return r, r.find("{%s}Assertion" % SAML)


def write(name, tree):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(etree.tostring(tree, xml_declaration=True, encoding="UTF-8"))


def main():
    k, cert = key("idp")
    other, _ = key("other")
    md = """<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%s">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
%s
    </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIBogus</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso/post"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso/redirect"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
""" % (IDP, "\n".join(cert[i:i + 64] for i in range(0, len(cert), 64)))
    with open(os.path.join(HERE, "idp_metadata.xml"), "w") as f:
        f.write(md)

    # Assertion signed (namespaces declared on the Response only; xs used in values).
    r, a = reparse(response()[0])
    sign(a, k, 1, incl=["xs"])
    write("resp_assertion_signed.xml", r)

    # Response signed, assertion unsigned.
    r, a = reparse(response()[0])
    sign(r, k, 1)
    write("resp_response_signed.xml", r)

    # Both signed (assertion first, then the response over it).
    r, a = reparse(response(groups=("Analysts",))[0])
    sign(a, k, 1, incl=["xs"])
    r, a = reparse(r)
    sign(r, k, 1)
    write("resp_both_signed.xml", r)

    # Signed with another key.
    r, a = reparse(response()[0])
    sign(a, other, 1, incl=["xs"])
    write("resp_wrong_key.xml", r)

    # Tampered after signing: group list changed.
    r, a = reparse(response()[0])
    sign(a, k, 1, incl=["xs"])
    a.find(".//{%s}AttributeValue" % SAML).text = "CH-Admins-Evil"
    write("resp_tampered.xml", r)

    # Signature wrapping: an unsigned evil assertion as the response's
    # assertion, the genuine signed one hidden inside its Subject.
    r, a = reparse(response(name="victim@example.com", groups=("Staff",))[0])
    sign(a, k, 1, incl=["xs"])
    evil_r, evil = response(assertion_id="_evil", name="attacker@example.com", groups=("CH-Admins",))
    r.remove(a)
    evil.find("{%s}Subject" % SAML).append(a)
    r.append(evil)
    write("resp_wrapped.xml", r)

    # Signed with RSA-SHA1 / SHA-1 digest (refused).
    r, a = reparse(response()[0])
    sign(a, k, 1, sig_alg="rsa-sha1", digest="sha1")
    write("resp_sha1.xml", r)

    # Duplicate ID: a second element reusing the signed assertion's ID.
    r, a = reparse(response()[0])
    sign(a, k, 1, incl=["xs"])
    ext = etree.Element("{%s}Extensions" % SAMLP)
    ext.append(etree.Element("{urn:x}Other", ID="_a-1"))
    r.insert(1, ext)
    write("resp_duplicate_id.xml", r)


if __name__ == "__main__":
    main()
