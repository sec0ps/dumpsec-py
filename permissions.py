import win32security
import ntsecuritycon


def decode_access_mask(mask, resource_type="file"):
    permissions = []

    if resource_type == "file":
        if mask & ntsecuritycon.FILE_GENERIC_READ:
            permissions.append("READ")
        if mask & ntsecuritycon.FILE_GENERIC_WRITE:
            permissions.append("WRITE")
        if mask & ntsecuritycon.FILE_GENERIC_EXECUTE:
            permissions.append("EXECUTE")
        if mask & ntsecuritycon.DELETE:
            permissions.append("DELETE")
    elif resource_type == "registry":
        if mask & ntsecuritycon.KEY_READ:
            permissions.append("READ")
        if mask & ntsecuritycon.KEY_WRITE:
            permissions.append("WRITE")
        if mask & ntsecuritycon.KEY_EXECUTE:
            permissions.append("EXECUTE")
        if mask & ntsecuritycon.DELETE:
            permissions.append("DELETE")

    if mask & ntsecuritycon.WRITE_DAC:
        permissions.append("WRITE_DAC")
    if mask & ntsecuritycon.WRITE_OWNER:
        permissions.append("WRITE_OWNER")

    return "|".join(permissions) if permissions else f"RAW: {mask}"


def print_acl(dacl):
    if dacl is None:
        print("    - No DACL found.")
        return

    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        sid = ace[2]
        try:
            user, domain, _ = win32security.LookupAccountSid(None, sid)
            access_mask = ace[1]
            print(f"    - {domain}\\{user} => Access: {access_mask}")
        except Exception as e:
            print(f"    - [!] Failed to resolve SID: {e}")
