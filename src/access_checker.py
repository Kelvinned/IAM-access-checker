"""
IAM Access Checker (RBAC)

Goal:
- Take an access request: (user, action, resource)
- Look up the user's roles
- Check policies for those roles
- Return ALLOW or DENY
- Log the decision (audit trail) to logs/decisions.jsonl

Why this structure?
- Code = the "engine" (logic)
- JSON files = configuration (data you can change without editing code)
  - data/users.json    : user -> roles
  - data/policies.json : role -> rules
"""

# argparse:
#   Lets us read command-line arguments like:
#   python src/access_checker.py --user anya --action read --resource /reports/q1
import argparse

# json:
#   Read JSON config files (users.json, policies.json)
#   Write logs as JSON lines (one JSON object per line)
import json

# fnmatch:
#   Simple wildcard matching like "*" or "/reports/*"
#   (So policies can match many resources with one pattern.)
import fnmatch

# pathlib.Path:
#   Safe, cross-platform way to handle file paths.
#   Avoids issues with manual string paths.
from pathlib import Path

# datetime/timezone:
#   We log a timestamp for auditability (IAM systems usually have audit logs).
from datetime import datetime, timezone


# -------------------------
# File locations
# -------------------------
# We compute the repository root dynamically so the script works regardless of
# where you run it from (as long as repo structure is unchanged).
#
# src/access_checker.py  -> parents[1] is repo root
REPO_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = REPO_ROOT / "data"
LOGS_DIR = REPO_ROOT / "logs"

USERS_FILE = DATA_DIR / "users.json"
POLICIES_FILE = DATA_DIR / "policies.json"
LOG_FILE = LOGS_DIR / "decisions.jsonl"


def load_json(path: Path) -> dict:
    """
    Load and parse a JSON file.

    Why a function?
    - Avoid repeating the same open/read/parse code in multiple places.
    - Centralizes error handling (cleaner and easier to maintain).

    Raises:
    - FileNotFoundError if the file doesn't exist (helps debug setup issues).
    """
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def matches(pattern: str, value: str) -> bool:
    """
    Check whether 'value' matches a policy pattern.

    Why fnmatch?
    - It's a simple built-in wildcard matcher:
      "*" matches anything
      "/reports/*" matches anything under /reports/...

    Example:
    - matches("/reports/*", "/reports/q1") -> True
    - matches("read", "write") -> False
    """
    return fnmatch.fnmatch(value, pattern)


def decide(user: str, action: str, resource: str, users: dict, policies: dict) -> tuple[str, dict | None]:
    """
    Decide whether the request should be ALLOW or DENY.

    Inputs:
    - user: who is requesting
    - action: what they want to do (read/write)
    - resource: what they want to access (e.g., /reports/q1)
    - users: loaded from data/users.json
    - policies: loaded from data/policies.json

    Output:
    - decision: "ALLOW" or "DENY" (or default_effect)
    - matched_rule: the rule that caused the decision (useful for explanation/logging)

    Design decisions:
    1) RBAC: user -> roles, roles -> rules
    2) "Deny wins" rule:
       If any matching rule says deny, we immediately deny.
       This is a common security practice in access control.
    3) Default deny:
       If nothing matches, apply policies["default_effect"] (we set it to deny).
    """
    roles = users.get(user, [])  # if user not found, treat as no roles
    role_rules = policies.get("roles", {})
    default_effect = policies.get("default_effect", "deny").lower()

    matched_allow = None  # store first allow, but keep checking for denies

    # Evaluate rules role-by-role.
    # Note: in more advanced IAM, you might also have rule priorities.
    for role in roles:
        for rule in role_rules.get(role, []):

            # A rule matches only if BOTH the action and resource match.
            if matches(rule["action"], action) and matches(rule["resource"], resource):
                effect = rule["effect"].lower()

                # Security-first: if any deny matches, deny immediately.
                if effect == "deny":
                    return "DENY", {"role": role, **rule}

                # Record allow, but continue searching in case a deny appears later.
                if effect == "allow" and matched_allow is None:
                    matched_allow = {"role": role, **rule}

    # If we found at least one allow and no denies, allow.
    if matched_allow:
        return "ALLOW", matched_allow

    # Otherwise, apply default policy (usually deny).
    return default_effect.upper(), None


def log_decision(entry: dict) -> None:
    """
    Append a decision log entry to logs/decisions.jsonl

    Why JSONL (JSON Lines)?
    - Each log entry is one JSON object per line.
    - Easy to append new entries without rewriting the whole file.
    - Easy to parse later for analysis.

    Why create logs directory here?
    - So the script works even if logs/ doesn't exist yet.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main():
    """
    Main entry point: handles CLI input, loads config, computes decision, logs it.

    Why argparse?
    - It gives a clean interface for users:
      --user, --action, --resource
    - It auto-generates --help documentation.
    """
    parser = argparse.ArgumentParser(description="RBAC IAM Access Checker")
    parser.add_argument("--user", required=True)
    parser.add_argument("--action", required=True, help="e.g., read, write")
    parser.add_argument("--resource", required=True, help="e.g., /reports/q1")
    args = parser.parse_args()

    # Load configuration data from JSON files.
    users = load_json(USERS_FILE)
    policies = load_json(POLICIES_FILE)

    # Make the access decision.
    decision, matched_rule = decide(args.user, args.action, args.resource, users, policies)

    # For logs/explanations, include user's roles and a timestamp.
    roles = users.get(args.user, [])
    ts = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

    log_entry = {
        "ts": ts,
        "user": args.user,
        "roles": roles,
        "action": args.action,
        "resource": args.resource,
        "decision": decision,
        "matched_rule": matched_rule
    }
    log_decision(log_entry)

    # Print a human-friendly result to the terminal.
    if matched_rule:
        print(
            f"{decision} (matched: {matched_rule['role']} "
            f"{matched_rule['effect']} {matched_rule['action']} {matched_rule['resource']})"
        )
    else:
        print(f"{decision} (no rule matched; default applied)")


# This makes the file runnable as a script:
# python src/access_checker.py --user ... --action ... --resource ...
# If someone imports this file as a module, main() won't auto-run.
if __name__ == "__main__":
    main()
