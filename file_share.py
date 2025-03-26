import win32net
import win32netcon
import os
import win32security
import ntsecuritycon
from permissions import decode_access_mask


def get_shared_folders():
    shared = []
    resume = 0

    while True:
        try:
            shares, total, resume = win32net.NetShareEnum(None, 2, resume, 1000)
            for share in shares:
                shared.append({
                    "Share Name": share['netname'],
                    "Path": share['path'],
                    "Remark": share.get('remark', '')
                })
            if not resume:
                break
        except Exception:
            break

    return shared


def get_ntfs_permissions(paths):
    results = {}

    for path in paths:
        perms = []
        try:
            sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()
            if dacl is None:
                perms.append("No DACL found.")
            else:
                for i in range(dacl.GetAceCount()):
                    ace = dacl.GetAce(i)
                    sid = ace[2]
                    user, domain, _ = win32security.LookupAccountSid(None, sid)
                    access_mask = ace[1]
                    perms.append(f"{domain}\\{user} => {decode_access_mask(access_mask, 'file')}")
        except Exception as e:
            perms.append(f"<error retrieving permissions: {e}>")

        results[path] = perms

    return results


def run():
    shared = get_shared_folders()

    paths_to_check = [r"C:\Users", r"C:\Program Files", r"C:\Windows\System32"]
    ntfs = get_ntfs_permissions([path for path in paths_to_check if os.path.exists(path)])

    return {
        "Shared Folders": shared,
        "NTFS Permissions": ntfs
    }

def decode_access_mask(mask):
    permissions = []
    if mask & ntsecuritycon.FILE_GENERIC_READ:
        permissions.append("READ")
    if mask & ntsecuritycon.FILE_GENERIC_WRITE:
        permissions.append("WRITE")
    if mask & ntsecuritycon.FILE_GENERIC_EXECUTE:
        permissions.append("EXECUTE")
    if mask & ntsecuritycon.DELETE:
        permissions.append("DELETE")
    if mask & ntsecuritycon.WRITE_DAC:
        permissions.append("WRITE_DAC")
    if mask & ntsecuritycon.WRITE_OWNER:
        permissions.append("WRITE_OWNER")
    return "|".join(permissions) if permissions else f"RAW: {mask}"


def main():
    list_shared_folders()

    # Example NTFS permission target — change this path to test others
    paths_to_check = [
        r"C:\Users",
        r"C:\Program Files",
        r"C:\Windows\System32"
    ]

    for path in paths_to_check:
        if os.path.exists(path):
            get_ntfs_permissions(path)


if __name__ == "__main__":
    main()
