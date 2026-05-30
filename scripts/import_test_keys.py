"""
Import known-material test keys into AWS Payment Cryptography via KEY_CRYPTOGRAM.

Each key's raw bytes are RSA-OAEP-SHA256 encrypted under APC's ephemeral RSA
public key (obtained via GetParametersForImport).  One import token is consumed
per key — APC enforces single-use tokens.

Run:
    python scripts/import_test_keys.py

Outputs an updated proxy.yaml snippet with key_mappings for every imported key.
"""

import base64
import boto3
import sys

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate

REGION = "us-east-1"

# ---------------------------------------------------------------------------
# Known test key material — safe for non-production use only.
# Labels are the exact strings sent in Thales wire payloads and must match
# the left-hand side of proxy.yaml key_mappings.
# ---------------------------------------------------------------------------
KEYS = [
    {
        "label":     "LTEST_P0SRC_0001",   # 16 chars (parse_legacy_key single)
        "key_hex":   "0123456789ABCDEF0123456789ABCDEF",
        "usage":     "TR31_P0_PIN_ENCRYPTION_KEY",
        "algorithm": "TDES_2KEY",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": False, "Sign": False, "Verify": False, "DeriveKey": False, "NoRestrictions": True},
        "kcv":       "ANSI_X9_24",
        "wrap_algo": "RSA_2048",
    },
    {
        "label":     "LTEST_P0DST_0001",   # 16 chars
        "key_hex":   "FEDCBA9876543210FEDCBA9876543210",
        "usage":     "TR31_P0_PIN_ENCRYPTION_KEY",
        "algorithm": "TDES_2KEY",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": False, "Sign": False, "Verify": False, "DeriveKey": False, "NoRestrictions": True},
        "kcv":       "ANSI_X9_24",
        "wrap_algo": "RSA_2048",
    },
    {
        "label":     "LTEST_V1PVK_0001",   # 16 chars (parse_legacy_key single)
        "key_hex":   "112233445566778811223344556677AA",
        "usage":     "TR31_V1_IBM3624_PIN_VERIFICATION_KEY",
        "algorithm": "TDES_2KEY",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": True,  "Sign": False, "Verify": True,  "DeriveKey": False, "NoRestrictions": False},
        "kcv":       "ANSI_X9_24",
        "wrap_algo": "RSA_2048",
    },
    {
        # parse_key_32 reads 32H with no prefix for DC/EC (Visa PVV PVK)
        "label":     "LTEST_V2PVK_0001LTEST_V2PVK_0001",   # 32 chars
        "key_hex":   "AABBCCDDEEFF00011122334455667788",
        "usage":     "TR31_V2_VISA_PIN_VERIFICATION_KEY",
        "algorithm": "TDES_2KEY",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": True,  "Sign": False, "Verify": True,  "DeriveKey": False, "NoRestrictions": False},
        "kcv":       "ANSI_X9_24",
        "wrap_algo": "RSA_2048",
    },
    {
        # parse_bdk reads 32H with no prefix for GW (DUKPT BDK)
        "label":     "LTEST_B0BDK_0001LTEST_B0BDK_0001",   # 32 chars
        "key_hex":   "0123456789ABCDEFFEDCBA9876543210",
        "usage":     "TR31_B0_BASE_DERIVATION_KEY",
        "algorithm": "TDES_2KEY",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": False, "Sign": False, "Verify": False, "DeriveKey": True, "NoRestrictions": False},
        "kcv":       "ANSI_X9_24",
        "wrap_algo": "RSA_2048",
    },
    {
        # AES-256 IMK for KQ ARQC verify — requires RSA_3072 wrapping (APC key-strength rule)
        "label":     "LTEST_E0IMK_0001",   # 16 chars (parse_legacy_key single)
        "key_hex":   "0123456789ABCDEF0123456789ABCDEFFEDCBA9876543210FEDCBA9876543210",
        "usage":     "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
        "algorithm": "AES_256",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": False, "Sign": False, "Verify": False, "DeriveKey": False, "NoRestrictions": True},
        "kcv":       "CMAC",
        "wrap_algo": "RSA_4096",
    },
]


def import_one(client, spec: dict) -> str:
    """Import a single key. Returns the APC key ARN."""
    label = spec["label"]
    print(f"  Importing {label} ({spec['algorithm']}, {spec['usage']})...", end="", flush=True)

    # Step 1 — get APC's ephemeral RSA public key + one-use import token
    params = client.get_parameters_for_import(
        KeyMaterialType="KEY_CRYPTOGRAM",
        WrappingKeyAlgorithm=spec["wrap_algo"],
    )

    # Step 2 — parse the PEM certificate to extract the RSA public key
    cert_pem = base64.b64decode(params["WrappingKeyCertificate"])
    cert = load_pem_x509_certificate(cert_pem)
    rsa_pub = cert.public_key()

    # Step 3 — RSA-OAEP-SHA256 encrypt the raw key bytes
    raw_key = bytes.fromhex(spec["key_hex"])
    encrypted = rsa_pub.encrypt(
        raw_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    wrapped = encrypted.hex().upper()

    # Step 4 — import
    # Note: Exportable and WrappedKeyCryptogram live inside KeyCryptogram, not at top level.
    result = client.import_key(
        KeyMaterial={
            "KeyCryptogram": {
                "ImportToken":      params["ImportToken"],
                "KeyAttributes": {
                    "KeyUsage":    spec["usage"],
                    "KeyClass":    "SYMMETRIC_KEY",
                    "KeyAlgorithm": spec["algorithm"],
                    "KeyModesOfUse": spec["modes"],
                },
                "Exportable":          False,
                "WrappedKeyCryptogram": wrapped,
                "WrappingSpec":        "RSA_OAEP_SHA_256",
            }
        },
        KeyCheckValueAlgorithm=spec["kcv"],
        Enabled=True,
    )
    key = result["Key"]
    arn = key["KeyArn"]
    kcv = key.get("KeyCheckValue", "N/A")
    print(f" {arn.split('/')[-1]} KCV={kcv}")
    return arn


def main():
    client = boto3.client("payment-cryptography", region_name=REGION)

    imported = {}
    errors = []

    print("Importing test keys into APC...")
    for spec in KEYS:
        try:
            arn = import_one(client, spec)
            imported[spec["label"]] = arn
        except Exception as exc:
            print(f" FAILED: {exc}")
            errors.append((spec["label"], str(exc)))

    print("\n--- proxy.yaml key_mappings snippet ---")
    for label, arn in imported.items():
        print(f'  "{label}": "{arn}"')

    if errors:
        print(f"\n{len(errors)} import(s) failed:", file=sys.stderr)
        for label, msg in errors:
            print(f"  {label}: {msg}", file=sys.stderr)
        sys.exit(1)

    print("\nDone. Add the snippet above to proxy.yaml key_mappings.")


if __name__ == "__main__":
    main()
