import subprocess
import os
import tempfile


def dump_local_security_policy():
    user_rights = {}
    audit_policy = {}

    with tempfile.NamedTemporaryFile(delete=False, suffix=".inf") as tmpfile:
        inf_path = tmpfile.name

    try:
        result = subprocess.run(
            ["secedit", "/export", "/cfg", inf_path],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            return {
                "User Rights Assignments": {"Error": result.stderr.strip()},
                "Audit Policy Settings": {"Error": result.stderr.strip()}
            }

        with open(inf_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_privileges = in_audit = False

        for line in lines:
            if "[Privilege Rights]" in line:
                in_privileges = True
                in_audit = False
                continue
            elif "[Event Audit]" in line:
                in_audit = True
                in_privileges = False
                continue
            elif "[" in line:
                in_privileges = in_audit = False
                continue

            if in_privileges and "=" in line:
                key, val = line.strip().split("=", 1)
                user_rights[key.strip()] = val.strip()

            if in_audit and "=" in line:
                key, val = line.strip().split("=", 1)
                audit_policy[key.strip()] = val.strip()

    finally:
        os.remove(inf_path)

    return {
        "User Rights Assignments": user_rights,
        "Audit Policy Settings": audit_policy
    }


def get_password_policy():
    result = []
    try:
        output = subprocess.run(["net", "accounts"], capture_output=True, text=True)
        result = output.stdout.strip().splitlines()
    except Exception as e:
        result.append(f"Error retrieving password policy: {e}")
    return result


def run():
    policy = dump_local_security_policy()
    policy["Password Policy"] = get_password_policy()
    return policy


def main():
    dump_local_security_policy()
    get_password_policy()


if __name__ == "__main__":
    main()
