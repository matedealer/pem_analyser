from datetime import datetime

CERT = "Certificate"
PUBKEY = "Public Key"
PRIVKEY = "Private Key"

# TODO: Replace dict with oid search
X509_SIG_ALGORITHMS = {
    "MD2WITHRSAENCRYPTION": False,
    "MD2WITHRSA": False,
    "MD5WITHRSAENCRYPTION": False,
    "MD5WITHRSA": False,
    "SHA1WITHRSAENCRYPTION": False,
    "SHA1WITHRSA": False,
    "SHA224WITHRSAENCRYPTION": True,
    "SHA224WITHRSA": True,
    "SHA256WITHRSAENCRYPTION": True,
    "SHA256WITHRSA": True,
    "SHA384WITHRSAENCRYPTION": True,
    "SHA384WITHRSA": True,
    "SHA512WITHRSAENCRYPTION": True,
    "SHA512WITHRSA": True,
    "SHA1WITHRSAANDMGF1": True,
    "SHA224WITHRSAANDMGF1": True,
    "SHA256WITHRSAANDMGF1": True,
    "SHA384WITHRSAANDMGF1": True,
    "SHA512WITHRSAANDMGF1": True,
    "RIPEMD160WITHRSAENCRYPTION": True,
    "RIPEMD160WITHRSA": True,
    "RIPEMD128WITHRSAENCRYPTION": False,
    "RIPEMD128WITHRSA": False,
    "RIPEMD256WITHRSAENCRYPTION": True,
    "RIPEMD256WITHRSA": True,
    "SHA1WITHDSA": False,
    "DSAWITHSHA1": False,
    "SHA224WITHDSA": True,
    "SHA256WITHDSA": True,
    "SHA1WITHECDSA": False,
    "ECDSAWITHSHA1": False,
    "SHA224WITHECDSA": True,
    "SHA256WITHECDSA": True,
    "ECDSAWITHSHA256": True,
    "SHA384WITHECDSA": True,
    "SHA512WITHECDSA": True,
    "GOST3411WITHGOST3410": True,
    "GOST3411WITHGOST3410-94": True,
    "GOST3411WITHECGOST3410": True,
    "GOST3411WITHECGOST3410-2001": True,
    "GOST3411WITHGOST3410-2001": True
}


def get_asn1_time(t: datetime) -> bytes:
    return bytes(t.strftime("%G%m%d%H%M%S") + "Z", "utf8")


def asn1_time_to_datetime(t: bytes) -> datetime:
    if str(t)[-2:-1] == "Z":
        try:
            return datetime.strptime(t.decode("utf8"), '%Y%m%d%H%M%SZ')
        except ValueError:
            print("[X] Could not translate string {} to datetime".format(str(t)))


class PemObject:
    def __init__(self, pem, pem_type):
        self.pem = pem
        self.pem_type = pem_type
