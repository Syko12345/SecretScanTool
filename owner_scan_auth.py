from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path


def _normalize_scan(scan_data: str) -> str:
    return " ".join(scan_data.strip().lower().split())


def create_scan_signature(scan_data: str) -> str:
    normalized = _normalize_scan(scan_data)
    if not normalized:
        raise ValueError("Scan data cannot be empty")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _load_database(database_path: str | Path) -> dict[str, str]:
    db_path = Path(database_path)
    if not db_path.exists():
        return {}
    with db_path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict):
        raise ValueError("Database must be a JSON object")
    return {str(account): str(signature) for account, signature in data.items()}


def _save_database(database_path: str | Path, database: dict[str, str]) -> None:
    db_path = Path(database_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with db_path.open("w", encoding="utf-8") as file:
        json.dump(database, file, indent=2)


def enroll_owner_scan(account_id: str, scan_data: str, database_path: str | Path) -> None:
    normalized_account = account_id.strip()
    if not normalized_account:
        raise ValueError("Account ID cannot be empty")

    database = _load_database(database_path)
    database[normalized_account] = create_scan_signature(scan_data)
    _save_database(database_path, database)


def verify_owner_scan(account_id: str, attempted_scan_data: str, database_path: str | Path) -> bool:
    normalized_account = account_id.strip()
    if not normalized_account:
        return False

    database = _load_database(database_path)
    expected_signature = database.get(normalized_account)
    if expected_signature is None:
        return False

    attempted_signature = create_scan_signature(attempted_scan_data)
    return hmac.compare_digest(expected_signature, attempted_signature)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secretly scan and verify whether a login attempt matches the account owner."
    )
    parser.add_argument(
        "--database",
        default="owner_scans.json",
        help="Path to the owner scan signature database (default: owner_scans.json)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    enroll_parser = subparsers.add_parser("enroll", help="Enroll or update an account owner's scan")
    enroll_parser.add_argument("account_id", help="Account identifier")
    enroll_parser.add_argument("scan_data", help="Trusted owner scan input")

    login_parser = subparsers.add_parser("login", help="Verify login scan against the account owner")
    login_parser.add_argument("account_id", help="Account identifier")
    login_parser.add_argument("scan_data", help="Scan input captured at login")

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "enroll":
        enroll_owner_scan(args.account_id, args.scan_data, args.database)
        print(f"Owner scan enrolled for account '{args.account_id}'.")
        return 0

    if verify_owner_scan(args.account_id, args.scan_data, args.database):
        print("Access granted.")
        return 0

    print("Access denied: account owner scan mismatch.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
