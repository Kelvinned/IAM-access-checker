## What is this?
This project is a small IAM-style access checker. You provide:
- a user
- an action (e.g., read/write)
- a resource (e.g., /reports/q1)

It returns **ALLOW** or **DENY** based on role-based rules and logs the decision.

## Key Concepts (IAM & RBAC)
### IAM (Identity and Access Management)
IAM is about:
- **Identity**: who a user is (accounts, login, authentication)
- **Access**: what the user is allowed to do (authorization)

This project focuses on the **access/authorization** part.

### RBAC (Role-Based Access Control)
RBAC assigns permissions to **roles**, and users get one or more roles.

Example:
- `viewer` can read but cannot write
- `finance` can read/write reports
- `admin` can do everything

RBAC is used widely because it’s easier to manage than setting permissions per user.

## Why JSON for policies/users?
Policies and users are stored as JSON because:
- it keeps **rules separate from code** (edit rules without changing Python)
- it’s **easy to read and share**
- most languages/tools support JSON, so the config is portable

## Project Structure
- `src/` - Python code (the “engine”)
- `data/` - JSON configuration (users + policies)
- `logs/` - decision logs (audit trail)

## How to run (codespaces)
Open the terminal and run :

```bash
python3 src/access_checker.py --user annya --action read --resource /reports/q1
python3 src/access_checker.py --user annya --action write --resource /reports/q1
python3 src/access_checker.py --user kelvin --action read --resource /iam/users