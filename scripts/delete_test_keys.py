"""
Schedule all integration-test APC keys for deletion.

Reads ARNs from the proxy.yaml key_mappings block and calls DeleteKey on each
unique ARN. APC schedules keys for deletion after a 7-day waiting period by
default; pass --delete-key-in-days 3 to shorten it.

Run:
    python scripts/delete_test_keys.py [--delete-key-in-days N]
"""

import argparse
import sys

import boto3
import yaml

PROXY_YAML = "proxy.yaml"
REGION = "us-east-1"
DEFAULT_DELETE_DAYS = 7


def load_arns(path: str) -> set[str]:
    with open(path) as fh:
        cfg = yaml.safe_load(fh)
    mappings = cfg.get("key_mappings", {})
    return set(mappings.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--delete-key-in-days",
        type=int,
        default=DEFAULT_DELETE_DAYS,
        help=f"Days until deletion (default: {DEFAULT_DELETE_DAYS})",
    )
    args = parser.parse_args()

    arns = load_arns(PROXY_YAML)
    print(f"Scheduling {len(arns)} unique key(s) for deletion in {args.delete_key_in_days} day(s)...")

    client = boto3.client("payment-cryptography", region_name=REGION)
    errors = []

    for arn in sorted(arns):
        key_id = arn.split("/")[-1]
        print(f"  {key_id} ... ", end="", flush=True)
        try:
            client.delete_key(
                KeyIdentifier=arn,
                DeleteKeyInDays=args.delete_key_in_days,
            )
            print("scheduled")
        except client.exceptions.ValidationException as exc:
            msg = str(exc)
            if "not in CREATE_COMPLETE state" in msg:
                print("already pending deletion")
            else:
                print(f"FAILED: {exc}")
                errors.append((arn, msg))
        except Exception as exc:
            print(f"FAILED: {exc}")
            errors.append((arn, str(exc)))

    if errors:
        print(f"\n{len(errors)} deletion(s) failed:", file=sys.stderr)
        for arn, msg in errors:
            print(f"  {arn}: {msg}", file=sys.stderr)
        sys.exit(1)

    print("\nDone. Keys will be deleted after the waiting period.")


if __name__ == "__main__":
    main()
