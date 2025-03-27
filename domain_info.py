import win32net
import win32netcon
from risk_engine import RiskEngine

risk = RiskEngine()

def list_domain_trusts():
    trusts = []
    try:
        dc_name = win32net.NetGetAnyDCName(None, None)
        trusts.append(f"Trusted domain controller: {dc_name}")
    except Exception as e:
        trusts.append(f"<error: {e}>")
    return trusts


def list_sessions():
    sessions = []
    resume = 0
    try:
        while True:
            results, total, resume = win32net.NetSessionEnum(None, None, None, 10)
            for session in results:
                sessions.append({
                    "User": session.get("user_name", ""),
                    "Client": session.get("client_name", "")
                })
            if not resume:
                break
    except Exception as e:
        sessions.append({"Error": str(e)})
    return sessions


def list_open_files():
    open_files = []
    resume = 0
    try:
        while True:
            results, total, resume = win32net.NetFileEnum(None, None, None, 3)
            for file in results:
                open_files.append({
                    "File": file.get("path_name", ""),
                    "Opened By": file.get("user_name", "")
                })
            if not resume:
                break
    except Exception as e:
        open_files.append({"Error": str(e)})
    return open_files


def run():
    trusts = list_domain_trusts()
    sessions = list_sessions()
    open_files = list_open_files()

    return {
        "Domain Trusts": trusts,
        "Active Sessions": sessions,
        "Open Files": open_files,
        "_risks": []  # Placeholder for future logic
    }


def main():
    list_domain_trusts()
    list_sessions()
    list_open_files()


if __name__ == "__main__":
    main()
