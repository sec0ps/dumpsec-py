import win32net
import win32netcon

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
            results, total, resume = win32net.NetSessionEnum(None, None, None, 10, resume, 1000)
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
            results, total, resume = win32net.NetFileEnum(None, None, None, 3, resume, 1000)
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
    return {
        "Domain Trusts": list_domain_trusts(),
        "Active Sessions": list_sessions(),
        "Open Files": list_open_files()
    }


def main():
    list_domain_trusts()
    list_sessions()
    list_open_files()


if __name__ == "__main__":
    main()
