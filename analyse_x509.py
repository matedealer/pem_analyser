from OpenSSL import crypto
from datetime import timedelta
from cryptography.x509.extensions import SubjectKeyIdentifier, AuthorityKeyIdentifier, KeyUsage, \
    ExtensionNotFound
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa
from utils import *


def certificate_print_subject(cert):
    print(cert.subject.rfc4514_string())


def certificate_is_expired(cert) -> bool:
    if cert.not_valid_after < datetime.today():
        print("[!] Certificate is expired!")
        return True
    else:
        return False


def certificate_sig_algorithm_is_weak(cert) -> bool:
    sig_algo = cert.signature_algorithm_oid._name
    try:
        is_strong = X509_SIG_ALGORITHMS[sig_algo.upper().replace("-", "")]
    except KeyError:
        print("[X] Unknown signature algorithm: {} !".format(sig_algo))
        print(cert.signature_algorithm_oid)
        return False

    if not is_strong:
        print("[!] Certificate has a weak signature algorithm: {} !".format(sig_algo))

    return not is_strong


def certificate_long_living(cert) -> bool:
    span = cert.not_valid_after - cert.not_valid_before
    if span > timedelta(825):
        print("[!] Certificate has a long time to live ({} days)!".format(span.days))
        return True
    return False


def certificate_key_usage_not_restricted(cert) -> bool:
    if cert.version.name == "v3":
        try:
            keyusage = cert.extensions.get_extension_for_oid(KeyUsage.oid)
        except ExtensionNotFound:
            print("[!] No usage for key defined!")
            return True

        for item in keyusage.value.__dict__:
            if not keyusage.value.__dict__[item]:
                return False

        print("[!] No usage for key defined!")
        return True

    return False


def certificate_is_selfsigned(cert) -> bool:
    if cert.version.name == "v3":
        try:
            authority_key_identifier = cert.extensions.get_extension_for_oid(
                AuthorityKeyIdentifier.oid).value.key_identifier
        except ExtensionNotFound:
            print("[!] Certificate is self signed!")
            return True

        subject_key_identifier = cert.extensions.get_extension_for_oid(SubjectKeyIdentifier.oid).value.digest

        if subject_key_identifier == authority_key_identifier:
            print("[!] Certificate is self signed!")
            return True

    return False


def certificate_key_lenght_short(cert) -> bool:
    return key_length_short(cert.public_key())


def key_length_short(key) -> bool:
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            print("[!] The RSA key is to short: {} bytes".format(key.key_size))
            return True

    if isinstance(key, ec.EllipticCurvePrivateKey):
        if key.key_size < 256:
            print("[!] The elliptic curve key is to short: {}".format(key.key_size))
            return True

    return False


CECK_DICT = {
    CERT: [certificate_print_subject,
           certificate_is_expired,
           certificate_sig_algorithm_is_weak,
           certificate_long_living,
           certificate_key_usage_not_restricted,
           certificate_is_selfsigned,
           certificate_key_lenght_short],
    PUBKEY: [key_length_short],
    PRIVKEY: [key_length_short]
}
