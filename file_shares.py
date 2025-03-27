import win32net
import win32netcon
import os
import win32security
import ntsecuritycon
from permissions import decode_access_mask
from risk_engine import RiskEngine

risk = RiskEngine()

def get_shared_folders():
    shared = []
    risks = []
    resume = 0

    while True:
        try:
            shares, total, resume = win32net.NetShareEnum(None, 2, resume, 1000)
            for share in shares:
                share_name = share['netname']
                share_path = share['path']
                share_remark = share.get('remark', '')

                # Risk evaluation for the share
                risks.extend(risk.evaluate_share(share_name, share_path))

                shared.append({
                    "Share Name": share_name,
                    "Path": share_path,
                    "Remark": share_remark
                })
            if not resume:
                break
        except Exception as e:
            shared.append({"Error": f"Failed to enumerate shares: {str(e)}"})
            break

    return shared, risks


def get_ntfs_permissions(paths):
    results = {}
    risks = []

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
                    access_mask = ace[1]
                    try:
                        user, domain, _ = win32security.LookupAccountSid(None, sid)
                        user_str = f"{domain}\\{user}"
                        perms.append(f"{user_str} => {decode_access_mask(access_mask, 'file')}")
                        # Evaluate the risk for the file permissions
                        risks.extend(risk.evaluate_permissions(access_mask, str(sid), user_str, resource_type="file"))
                    except Exception:
                        perms.append(f"<unresolved SID: {sid}>")
                        risks.extend(risk.evaluate_orphaned_sid(str(sid)))
        except Exception as e:
            perms.append(f"<error retrieving permissions: {e}>")

        results[path] = perms

    return results, risks


def run():
    # Get shared folders and evaluate risks
    shared_folders, share_risks = get_shared_folders()

    # Define paths to check for NTFS permissions
    paths_to_check = [r"C:\Users", r"C:\Program Files", r"C:\Windows\System32"]
    
    # Check NTFS permissions and evaluate risks
    ntfs_permissions, ntfs_risks = get_ntfs_permissions([path for path in paths_to_check if os.path.exists(path)])

    # Return both shared folder details and NTFS permissions with associated risks
    return {
        "Shared Folders": shared_folders,
        "NTFS Permissions": ntfs_permissions,
        "_risks": share_risks + ntfs_risks
    }


def main():
    # Call the run function and display results
    result = run()

    for section, content in result.items():
        print(f"\n=== {section} ===")
        if isinstance(content, dict):
            for key, value in content.items():
                print(f"{key}:")
                for entry in value:
                    print(f"  - {entry}")
        elif isinstance(content, list):
            for line in content:
                print(f"  - {line}")
        else:
            print(content)


if __name__ == "__main__":
    main()
