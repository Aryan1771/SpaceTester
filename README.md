# Space Tester

Space Tester (the repository's original project name is ProcessVault) is a free, open-source cybersecurity PBL that demonstrates lightweight Windows application isolation. It starts programs in Windows AppContainers. Website sessions start the Windows default browser with a separate temporary profile and keep the browser's native site-renderer sandbox enabled. A Windows Job Object tracks each session's process tree, applies process-count and memory limits, and can stop the tree. Website sessions have normal browser internet access.

The desktop app and executable are named Space Tester. Its colors follow the Windows app theme automatically and update when the Windows light/dark setting changes. There is no in-app theme switch.

This is an educational project and a defense-in-depth demonstration. It is not a secure boundary for serious malware, kernel exploits, or sensitive production systems. Windows still supplies the AppContainer enforcement primitives. A custom UI or source code does not make a new security boundary stronger by itself.

## Build and run

Requirements: Windows 10/11 and .NET 8 SDK. No administrator privileges, Windows Sandbox optional feature, QEMU, or guest OS image is required. Website sessions need a default browser that supports a temporary profile and its built-in renderer sandbox. The default browser is read from the Windows HTTPS association.

```powershell
dotnet build ProcessVault.sln
dotnet run --project src/ProcessVault.Desktop
dotnet run --project tests/ProcessVault.Tests
```

The test command exercises a harmless process, the included child-process/file-write fixture, HTTPS access from a network-enabled AppContainer probe, and host-file denial. To also open the default browser visibly on `https://example.org` for a 60-second smoke check, run:

```powershell
$env:PROCESSVAULT_BROWSER_SMOKE = "1"
$env:PROCESSVAULT_BROWSER_SMOKE_SECONDS = "60"
dotnet run --project tests/ProcessVault.Tests
Remove-Item Env:PROCESSVAULT_BROWSER_SMOKE
Remove-Item Env:PROCESSVAULT_BROWSER_SMOKE_SECONDS
```

Keep the browser window open for the full smoke check; closing it early makes the final visibility check fail by design. The smoke test stops its temporary browser session when it finishes. For normal use, start the desktop app and open a website there; the browser stays open until you close it or press **Stop isolated process**.

### Run a program

1. Drag one `.exe` into the Space Tester window, or choose **File → Open…** (also `Ctrl+O`). You can also use **Browse** beside the program path.
2. Enter optional Windows command-line arguments and click **Isolate program**. Dropping a file or choosing File → Open fills the program field and shows the launch confirmation.
3. Review the warning and launch. Space Tester copies the executable and common same-name runtime sidecars into the new AppContainer's local profile.
4. The program runs with no network capability. Its writable AppContainer profile is deleted after its process tree exits or you click **Stop isolated process**.

Managed programs that need additional dependency DLLs may not run because this version stages only the executable and common same-name sidecars. The app does not copy the entire source directory.

### Open a website

1. Enter a complete HTTP or HTTPS address and click **Isolate website**.
2. Review the notice. Space Tester starts the Windows default browser with a new, temporary profile and without its normal browser cookies, history, or extensions.
3. The site uses the browser's normal internet connection. Anything you submit is sent to the site, so do not use personal accounts or sensitive information.
4. Close the browser window or press **Stop isolated process**. Stop also terminates browser helper processes in the session Job Object and removes the temporary profile.

The website uses the browser's built-in renderer/content sandbox. The browser controller itself runs as the signed-in Windows user and is not in ProcessVault's AppContainer; it can access files that user permissions allow if the browser controller is compromised. The job limits the process tree to 64 processes and 2 GB of committed memory. Space Tester does not inspect page behavior or monitor network traffic.

## What the isolation does

- Program sessions use an AppContainer security token and low integrity.
- A per-session AppContainer profile provides temporary writable storage. The selected executable is copied into that profile.
- Program sessions receive no AppContainer capabilities. Website sessions use the browser's native renderer isolation and normal network path.
- A Windows Job Object groups descendant processes, caps the tree at 64 processes and 2 GB of committed memory, and terminates it when Space Tester closes the job.
- The browser is launched with a separate temporary user-data profile; the host browser profile is not reused.

Windows documents that AppContainer access combines the normal user/group permissions with the AppContainer package SID and capability SIDs. See [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer), [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation), and [network capability behavior](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831418%28v%3Dws.11%29).

## Limitations and intended use

- This is process isolation inside the same Windows kernel, not a virtual machine. A kernel vulnerability or unsupported application behavior may cross the intended boundary.
- AppContainer is not a full filesystem overlay. Reads depend on Windows ACLs and AppContainer rules; only writes granted by Windows are contained. Do not run samples that need assurance of host confidentiality or integrity.
- Website sessions depend on each browser's own renderer sandbox. The browser controller runs as the signed-in user, so a browser vulnerability could expose host files available to that account.
- Some browsers may handle temporary-profile command-line options differently. Windows policy, browser version, and installation can affect startup.
- The app does not monitor file, registry, browser, or network activity and does not assign a malware verdict.
- CPU is observed but not capped. The Job Object applies process-count and memory ceilings as well as process-tree cleanup.
- Reports and local history are mutable local observations, not forensic evidence.
- If Space Tester crashes, the job handle closes and stops contained processes, but the per-session profile may remain under `%LOCALAPPDATA%\Packages` for manual cleanup.

Use this for a supervised class demonstration of process isolation and native browser sandboxing. For serious malware, use a patched disposable VM or managed analysis environment.

## Project layout

- `src/ProcessVault.Core`: AppContainer process creation, argument validation, process inventory, and reports.
- `src/ProcessVault.Desktop`: WPF interface.
- `tests/ProcessVault.Tests`: validation and harmless isolation checks.
- `fixtures/HarmlessProbe`: benign process and file-write demonstration.

## License

GNU General Public License version 3. See [LICENSE](LICENSE).
