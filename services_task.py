import win32service
import win32serviceutil
import win32con
import win32api
import win32security
import win32com.client


def get_services():
    services = []

    try:
        scm_handle = win32service.OpenSCManager(None, None, win32con.SC_MANAGER_ENUMERATE_SERVICE)
        statuses = win32service.EnumServicesStatusEx(
            scm_handle,
            win32service.SC_ENUM_PROCESS_INFO,
            win32service.SERVICE_WIN32,
            win32service.SERVICE_STATE_ALL,
            None
        )

        for service in statuses:
            name = service['ServiceName']
            display_name = service['DisplayName']
            try:
                config = win32service.QueryServiceConfig(
                    win32service.OpenService(scm_handle, name, win32con.SC_MANAGER_ALL_ACCESS)
                )
                start_type = decode_start_type(config[1])
                logon_user = config[7]
                status = "Running" if service['CurrentState'] == win32service.SERVICE_RUNNING else "Stopped"

                services.append({
                    "Service Name": name,
                    "Display Name": display_name,
                    "Status": status,
                    "Start Type": start_type,
                    "Logon User": logon_user
                })
            except Exception as e:
                services.append({
                    "Service Name": name,
                    "Display Name": display_name,
                    "Status": "<error>",
                    "Start Type": "<error>",
                    "Logon User": f"<error: {e}>"
                })

    except Exception as e:
        services.append({"Error": str(e)})

    return services


def decode_start_type(code):
    return {
        win32service.SERVICE_AUTO_START: "Automatic",
        win32service.SERVICE_DEMAND_START: "Manual",
        win32service.SERVICE_DISABLED: "Disabled"
    }.get(code, f"Unknown ({code})")


def get_scheduled_tasks():
    tasks = []
    try:
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folders = [scheduler.GetFolder("\\")]
        while folders:
            folder = folders.pop()
            for task in folder.GetTasks(0):
                name = task.Name
                try:
                    user_id = task.Definition.Principal.UserId
                    tasks.append({
                        "Task Name": name,
                        "Run As": user_id
                    })
                except Exception as e:
                    tasks.append({
                        "Task Name": name,
                        "Run As": f"<error: {e}>"
                    })
            folders.extend(folder.GetFolders(0))
    except Exception as e:
        tasks.append({"Error": str(e)})

    return tasks


def run():
    return {
        "Services": get_services(),
        "Scheduled Tasks": get_scheduled_tasks()
    }


def main():
    get_services()
    get_scheduled_tasks()


if __name__ == "__main__":
    main()
