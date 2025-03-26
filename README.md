DumpSec-Py

DumpSec-Py is a modern Python-based clone of the classic Windows DumpSec utility, used by security professionals and system administrators to audit system permissions and configurations.

This tool provides full visibility into local Windows system security settings, group memberships, services, scheduled tasks, file share permissions, registry permissions, local security policies, and domain trust information — all in one place, written entirely in Python.

---

## 🚀 Features

- Enumerate **local users** and **groups**
- Map **group memberships**, including nested resolution
- Audit **NTFS file and folder permissions**
- List **shared folders** and their access controls
- Extract **registry permissions** for critical keys
- List **services**, startup types, and logon accounts
- Dump **scheduled tasks** with run-as user info
- Retrieve **local security policies**, user rights, and audit settings
- Get **password policies** and lockout settings
- Show **domain trust info**, **open sessions**, and **open files**

---

## ⚙️ Requirements

- Windows OS (PowerShell or CMD)
- Python 3.8+
- Run as Administrator for full access
- Install required libraries:

pip install -r requirements.txt
