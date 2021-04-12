from OpenSSL import crypto
from datetime import timedelta
from cryptography.x509.extensions import SubjectKeyIdentifier, AuthorityKeyIdentifier, KeyUsage, \
    ExtensionNotFound
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
from utils import *


def certificate_info(cert) -> str:
    return "[*] Subject: {} \n[*] Issuer: {}".format(cert.subject.rfc4514_string(), cert.issuer.rfc4514_string())


def certificate_is_expired(cert) -> str:
    if cert.not_valid_after < datetime.today():
        ret = "[!] Certificate is expired (since {})!".format(cert.not_valid_after.date())
        return ret
    else:
        return ""


def certificate_sig_algorithm_is_weak(cert) -> str:
    sig_algo = cert.signature_algorithm_oid._name
    try:
        is_strong = X509_SIG_ALGORITHMS[sig_algo.upper().replace("-", "")]
    except KeyError:
        ret = "[X] Unknown signature algorithm ({})!".format(sig_algo)
        ret += "\n {}".format(cert.signature_algorithm_oid)
        return ret

    ret = ""
    if not is_strong:
        ret = "[!] Certificate has a weak signature algorithm ({})!".format(sig_algo)

    return ret


def certificate_long_living(cert) -> str:
    span = cert.not_valid_after - cert.not_valid_before
    if span > timedelta(825):
        ret = "[!] Certificate has a long time to live ({} days)!".format(span.days)
        return ret
    return ""


def certificate_key_usage_not_restricted(cert) -> str:
    if cert.version.name == "v3":
        try:
            keyusage = cert.extensions.get_extension_for_oid(KeyUsage.oid)
        except ExtensionNotFound:
            ret = "[!] No usage for key defined!"
            return ret

        for item in keyusage.value.__dict__:
            if not keyusage.value.__dict__[item]:
                return ""

        ret = "[!] No usage for key defined!"
        return ret

    return ""


def certificate_is_selfsigned(cert) -> str:
    if cert.version.name == "v3":
        try:
            authority_key_identifier = cert.extensions.get_extension_for_oid(
                AuthorityKeyIdentifier.oid).value.key_identifier
        except ExtensionNotFound:
            ret = "[!] Certificate is self signed!"
            return ret

        subject_key_identifier = cert.extensions.get_extension_for_oid(SubjectKeyIdentifier.oid).value.digest

        if subject_key_identifier == authority_key_identifier:
            ret = "[!] Certificate is self signed!"
            return ret

    return ""


def certificate_key_lenght_short(cert) -> str:
    return key_length_short(cert.public_key())


def key_length_short(key) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            ret = "[!] The RSA key is too small ({} bytes)!".format(key.key_size)
            return ret

    if isinstance(key, ec.EllipticCurvePrivateKey):
        if key.key_size < 256:
            ret = "[!] The elliptic curve key is too small ({} bytes)!".format(key.key_size)
            return ret

    return ""


CECK_DICT = {
    CERT: [certificate_info,
           certificate_is_expired,
           certificate_sig_algorithm_is_weak,
           certificate_long_living,
           certificate_key_usage_not_restricted,
           certificate_is_selfsigned,
           certificate_key_lenght_short],
    PUBKEY: [key_length_short],
    PRIVKEY: [key_length_short]
}
