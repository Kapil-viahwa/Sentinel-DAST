"""Create an administrator account: python -m scripts.create_admin --email you@example.com"""
from __future__ import annotations

import argparse
import getpass
import sys

from app.auth import hash_password
from app.db import SessionLocal, init_db
from app.models import Organization, User


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an administrator account")
    parser.add_argument("--email", required=True)
    parser.add_argument("--organization", default="Default")
    parser.add_argument("--password", default=None,
                        help="Omit to be prompted (recommended for shell history safety)")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Password for the new admin: ")
    if len(password) < 10:
        print("Error: password must be at least 10 characters", file=sys.stderr)
        return 1

    init_db()
    db = SessionLocal()
    try:
        if db.query(User).filter_by(email=args.email.lower()).first():
            print(f"Error: user {args.email} already exists", file=sys.stderr)
            return 1
        org = db.query(Organization).filter_by(name=args.organization).first()
        if org is None:
            org = Organization(name=args.organization)
            db.add(org)
            db.flush()
        user = User(email=args.email.lower(), password_hash=hash_password(password),
                    role="admin", organization_id=org.id)
        db.add(user)
        db.commit()
        print(f"Created admin {user.email} in organization '{org.name}'")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())