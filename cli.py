import click
import pem
from OpenSSL import crypto
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


from utils import *
from analyse_x509 import CECK_DICT


def import_pem_file(pem_file: str) -> []:
    pem_list = pem.parse_file(pem_file)
    pem_obj_list = []
    for pem_str in pem_list:
        if isinstance(pem_str, pem.Certificate):
            pem_obj = PemObject(load_pem_x509_certificate(pem_str.as_bytes()), CERT)
        elif isinstance(pem_str, pem.PublicKey):
            pem_obj = PemObject(load_pem_public_key(pem_str.as_bytes()), PUBKEY)
        elif isinstance(pem_str, pem.PrivateKey):
            try:
                pem_obj = PemObject(load_pem_private_key(pem_str.as_bytes(), None), PRIVKEY)
            except TypeError:
                print("This script cannot open encrypted private keys!")
                continue
        else:
            continue

        pem_obj_list.append(pem_obj)

    return pem_obj_list


@click.command()
@click.argument('pem_file', type=click.Path(exists=True))
def cli_read_pem_file(pem_file):
    """Read pem file and analyse it"""
    click.echo(">> Reading File {}".format(pem_file))
    pem_obj_list = import_pem_file(pem_file)

    for elem in pem_obj_list:
        click.echo(">> Analysing {}".format(elem.pem_type))
        for check in CECK_DICT[elem.pem_type]:
            check(elem.pem)


if __name__ == '__main__':
    cli_read_pem_file()
