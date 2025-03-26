import winreg
import win32security
import ntsecuritycon
from permissions import decode_access_mask


# Registry hives mapping
HIVES = {
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
    "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    "HKEY_USERS": winreg.HKEY_USERS,
    "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT
}


def get_key_permissions(hive_name, subkey):
    results = []
    try:
        hive = HIVES[hive_name]
        reg_key = win32security.RegOpenKeyEx(hive, subkey, 0, win32security.KEY_READ | win32security.READ_CONTROL)
        sd = win32security.GetSecurityInfo(
            reg_key,
            win32security.SE_REGISTRY_KEY,
            win32security.DACL_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()

        if dacl is None:
            results.append("No DACL found.")
        else:
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                sid = ace[2]
                user, domain, _ = win32security.LookupAccountSid(None, sid)
                access_mask = ace[1]
                results.append(f"{domain}\\{user} => {decode_access_mask(access_mask, 'registry')}")
    except Exception as e:
        results.append(f"<error retrieving permissions: {e}>")

    return results


def run():
    keys_to_check = [
        ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services"),
        ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]

    output = {}

    for hive, key in keys_to_check:
        full_path = f"{hive}\\{key}"
        output[full_path] = get_key_permissions(hive, key)

    return output

def decode_access_mask(mask):
    permissions = []
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


def main():
    # You can change these keys to target others
    test_keys = [
        ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKEY_LOCAL_MACHINE", r"SYSTEM\CurrentControlSet\Services"),
        ("HKEY_CURRENT_USER", r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]

    for hive_name, subkey in test_keys:
        get_key_permissions(hive_name, subkey)


if __name__ == "__main__":
    main()
