import win32net
import win32netcon

def list_local_users():
    users = []
    resume = 0

    while True:
        try:
            user_data, total, resume = win32net.NetUserEnum(
                None,
                0,
                win32netcon.FILTER_NORMAL_ACCOUNT,
                resume,
                1000
            )
            for user in user_data:
                users.append(user['name'])
            if not resume:
                break
        except Exception:
            break
    return users


def list_local_groups():
    groups = []
    resume = 0

    while True:
        try:
            group_data, total, resume = win32net.NetLocalGroupEnum(
                None,
                0,
                resume,
                1000
            )
            for group in group_data:
                groups.append(group['name'])
            if not resume:
                break
        except Exception:
            break
    return groups


def list_group_memberships(groups):
    memberships = {}
    for group in groups:
        try:
            members, _, _ = win32net.NetLocalGroupGetMembers(None, group, 2)
            memberships[group] = [member['name'] for member in members]
        except Exception:
            memberships[group] = ["<error retrieving members>"]
    return memberships


def run():
    users = list_local_users()
    groups = list_local_groups()
    memberships = list_group_memberships(groups)

    return {
        "Local Users": users,
        "Local Groups": groups,
        "Group Memberships": memberships
    }

def main():
    users = list_local_users()
    groups = list_local_groups()
    list_group_memberships(groups)


if __name__ == "__main__":
    main()
