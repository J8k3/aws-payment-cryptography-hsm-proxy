"""
Provision the full test key set in AWS Payment Cryptography.

Two paths:

1. KEY_CRYPTOGRAM import — six keys whose clear material is fixed (so test
   vectors can be reproduced in CyberChef, etc.).  RSA-OAEP-SHA256 wrap; one
   APC import token per key (single-use).

2. CreateKey — six APC-generated keys for handlers that only need a key of the
   right type / algorithm and don't depend on specific clear material.
   M1, M3 (TDES MAC), M6 (AES CMAC), M7 (AES HMAC), C0 (TDES CVK), D0 (TDES DEK).

Run:
    python scripts/import_test_keys.py

Outputs the complete proxy.yaml key_mappings block (including the 32-char
duplicate labels several handlers consume) ready to paste in.
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
]

# ---------------------------------------------------------------------------
# APC-generated keys — no specific clear material required. Used by handlers
# whose tests only check round-trip success (error 00) rather than vector match.
# ---------------------------------------------------------------------------
CREATE_KEYS = [
    {
        "label":     "LTEST_M1_MAC_001",  # 16 chars
        "usage":     "TR31_M1_ISO_9797_1_MAC_KEY",
        "algorithm": "TDES_2KEY",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": True,  "Sign": False, "Verify": True,  "DeriveKey": False, "NoRestrictions": False},
        "kcv":       "ANSI_X9_24",
        # Additional labels in proxy.yaml that should resolve to the same ARN:
        "aliases":   ["LIVETEST_MAC_001", "LTEST_M1_MAC_001LTEST_M1_MAC_001"],
    },
    {
        "label":     "LTEST_M3_MAC_001",
        "usage":     "TR31_M3_ISO_9797_3_MAC_KEY",
        "algorithm": "TDES_2KEY",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": True,  "Sign": False, "Verify": True,  "DeriveKey": False, "NoRestrictions": False},
        "kcv":       "ANSI_X9_24",
        "aliases":   ["LTEST_M3_MAC_001LTEST_M3_MAC_001"],
    },
    {
        "label":     "LTEST_M6_MAC_001",
        "usage":     "TR31_M6_ISO_9797_5_CMAC_KEY",
        "algorithm": "AES_128",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": True,  "Sign": False, "Verify": True,  "DeriveKey": False, "NoRestrictions": False},
        "kcv":       "CMAC",
        "aliases":   [],
    },
    {
        "label":     "LTEST_HMAC_00001",
        "usage":     "TR31_M7_HMAC_KEY",
        "algorithm": "AES_128",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": True,  "Sign": False, "Verify": True,  "DeriveKey": False, "NoRestrictions": False},
        "kcv":       "CMAC",
        "aliases":   [],
    },
    {
        "label":     "LTEST_CVK_000001",
        "usage":     "TR31_C0_CARD_VERIFICATION_KEY",
        "algorithm": "TDES_2KEY",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": True,  "Sign": False, "Verify": True,  "DeriveKey": False, "NoRestrictions": False},
        "kcv":       "ANSI_X9_24",
        "aliases":   ["LTEST_CVK_000001LTEST_CVK_000001"],
    },
    {
        "label":     "LIVETEST_DEK_001",
        "usage":     "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "algorithm": "TDES_2KEY",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": False, "Sign": False, "Verify": False, "DeriveKey": False, "NoRestrictions": True},
        "kcv":       "ANSI_X9_24",
        "aliases":   [],
    },
    {
        # AES-128 IMK for KQ ARQC verify. AES_128 (not AES_256) because APC's
        # verify_auth_request_cryptogram does not accept AES_256 IMKs.
        # Created (not imported) since the test only needs round-trip behaviour.
        "label":     "LTEST_E0IMK_0001",
        "usage":     "TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS",
        "algorithm": "AES_128",
        "modes":     {"Encrypt": False, "Decrypt": False, "Wrap": False, "Unwrap": False,
                      "Generate": False, "Sign": False, "Verify": False, "DeriveKey": True, "NoRestrictions": False},
        "kcv":       "CMAC",
        "aliases":   [],
    },
]

# Extra label mappings for the imported (known-material) keys — handlers that
# read a 32-char key field use a duplicated form of the same 16-char label.
IMPORTED_ALIASES = {
    "LTEST_P0SRC_0001":                 ["ZPK_INBOUND",  "LTEST_P0SRC_0001_LTEST_P0SRC_001"],
    "LTEST_P0DST_0001":                 ["ZPK_OUTBOUND", "LTEST_P0DST_0001_LTEST_P0DST_001"],
}


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


def create_one(client, spec: dict) -> str:
    """Create an APC-generated key with no specific clear material."""
    label = spec["label"]
    print(f"  Creating {label} ({spec['algorithm']}, {spec['usage']})...", end="", flush=True)
    result = client.create_key(
        KeyAttributes={
            "KeyUsage":    spec["usage"],
            "KeyClass":    "SYMMETRIC_KEY",
            "KeyAlgorithm": spec["algorithm"],
            "KeyModesOfUse": spec["modes"],
        },
        KeyCheckValueAlgorithm=spec["kcv"],
        Exportable=False,
        Enabled=True,
    )
    key = result["Key"]
    arn = key["KeyArn"]
    kcv = key.get("KeyCheckValue", "N/A")
    print(f" {arn.split('/')[-1]} KCV={kcv}")
    return arn


def main():
    client = boto3.client("payment-cryptography", region_name=REGION)

    label_to_arn: dict[str, str] = {}
    errors: list[tuple[str, str]] = []

    print("Importing known-material test keys...")
    for spec in KEYS:
        try:
            arn = import_one(client, spec)
            label_to_arn[spec["label"]] = arn
            for alias in IMPORTED_ALIASES.get(spec["label"], []):
                label_to_arn[alias] = arn
        except Exception as exc:
            print(f" FAILED: {exc}")
            errors.append((spec["label"], str(exc)))

    print("\nCreating APC-generated test keys...")
    for spec in CREATE_KEYS:
        try:
            arn = create_one(client, spec)
            label_to_arn[spec["label"]] = arn
            for alias in spec.get("aliases", []):
                label_to_arn[alias] = arn
        except Exception as exc:
            print(f" FAILED: {exc}")
            errors.append((spec["label"], str(exc)))

    print("\n--- proxy.yaml key_mappings block (paste over existing) ---\n")
    print("key_mappings:")
    for label in sorted(label_to_arn):
        print(f'  "{label}": "{label_to_arn[label]}"')

    if errors:
        print(f"\n{len(errors)} provisioning step(s) failed:", file=sys.stderr)
        for label, msg in errors:
            print(f"  {label}: {msg}", file=sys.stderr)
        sys.exit(1)

    print("\nDone.")


if __name__ == "__main__":
    main()
