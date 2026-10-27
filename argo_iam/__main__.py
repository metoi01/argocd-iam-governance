"""Command line entry point: ``python -m argo_iam <command>``."""

from __future__ import annotations

import argparse
import getpass
import sys

from argo_iam.argocd_adapter.policy import render_policy_csv
from argo_iam.common import IAMError
from argo_iam.config import Settings
from argo_iam.container import build_container
from argo_iam.seed import DEMO_PASSWORD, DEMO_USERS, seed_demo_users
from argo_iam.users.models import Role


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="argo_iam", description="Argo IAM Governance Layer")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="start the web server")
    run.add_argument("--host", default="127.0.0.1")
    run.add_argument("--port", type=int, default=8080)
    run.add_argument("--seed", action="store_true", help="create demo users first")

    sub.add_parser("seed", help="create the demo users")
    totp = sub.add_parser("totp", help="print a demo user's current TOTP code (demo mode only)")
    totp.add_argument("username")
    admin = sub.add_parser("create-admin", help="create an administrator interactively")
    admin.add_argument("username")
    admin.add_argument("--email", required=True)
    sub.add_parser("policy", help="print the generated Argo CD policy.csv")
    sub.add_parser("verify-audit", help="verify the audit log hash chain")

    args = parser.parse_args(argv)
    settings = Settings.from_env()

    if args.command == "policy":
        print(render_policy_csv(), end="")
        return 0

    c = build_container(settings)

    if args.command in ("seed", "run") and (args.command == "seed" or args.seed):
        created = seed_demo_users(c)
        if created:
            print(f"Created demo users: {', '.join(created)} (password: {DEMO_PASSWORD})")
            for d in DEMO_USERS:
                if d.username in created:
                    print(f"  {d.username:<6} {d.role.value:<8} "
                          f"{'MFA enrolled' if d.enrol_mfa else 'enrols MFA at first login'}")
        else:
            print("Demo users already exist.")
        if args.command == "seed":
            return 0

    if args.command == "totp":
        if not settings.demo_mode:
            print("Disabled: set ARGO_IAM_DEMO_MODE=1 to use demo helpers.", file=sys.stderr)
            return 2
        user = c.users_repo.get_by_username(args.username)
        code = c.auth.current_code(user) if user else None
        if not code:
            print(f"No enrolled authenticator for '{args.username}'.", file=sys.stderr)
            return 1
        print(code)
        return 0

    if args.command == "create-admin":
        password = getpass.getpass("Password: ")
        try:
            c.users.provision(args.username, args.username, args.email, password, Role.ADMIN)
        except IAMError as e:
            print(e.message, file=sys.stderr)
            return 1
        print(f"Administrator {args.username} created; MFA is enrolled at first sign-in.")
        return 0

    if args.command == "verify-audit":
        result = c.audit.verify_chain()
        print(f"{'VALID' if result.valid else 'BROKEN'}: {result.checked} events checked"
              + ("" if result.valid else f", first bad event #{result.broken_at}"))
        return 0 if result.valid else 1

    if args.command == "run":
        from argo_iam.web import create_app

        app = create_app(c)
        print(f"Argo IAM Governance on http://{args.host}:{args.port}  "
              f"(Argo CD backend: {c.argocd.adapter.describe()})")
        app.run(host=args.host, port=args.port, debug=False)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
