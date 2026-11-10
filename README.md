# ProcessVault

ProcessVault is a free, open-source cybersecurity PBL that demonstrates **lightweight Windows app isolation**. It starts a selected Windows program or Microsoft Edge as a low-integrity Windows AppContainer process, assigns it a unique temporary profile, and groups its child processes in a cleanup job. Programs receive no network capability. Website sessions receive the `internetClient` capability only; the private-network capability is not granted. The project uses Windows AppContainer APIs directly; it does not use Windows Sandbox, a VM, or a hypervisor.

This is an educational project and a defense-in-depth demonstration. It is not a secure boundary for serious malware, kernel exploits, or sensitive production systems. Windows still supplies the AppContainer enforcement primitives. A custom UI or source code does not make a new security boundary stronger by itself.

## Build and run

Requirements: Windows 10/11 and .NET 8 SDK. No administrator privileges, Windows Sandbox optional feature, QEMU, or guest OS image is required. Microsoft Edge is needed for website sessions.

```powershell
dotnet build ProcessVault.sln
dotnet run --project src/ProcessVault.Desktop
dotnet run --project tests/ProcessVault.Tests
```

The test command exercises a harmless process and the included child-process/file-write fixture under AppContainer. To also smoke-test Edge launch and cleanup against `https://example.org`, run:

```powershell
$env:PROCESSVAULT_BROWSER_SMOKE = "1"
dotnet run --project tests/ProcessVault.Tests
Remove-Item Env:PROCESSVAULT_BROWSER_SMOKE
```

### Run a program

1. Drag one `.exe` into the ProcessVault window, or choose **File → Open…** (also `Ctrl+O`). You can also use **Browse** beside the program path.
2. Enter optional Windows command-line arguments and click **Isolate program**. Dropping a file or choosing File → Open fills the program field and shows the launch confirmation.
3. Review the warning and launch. ProcessVault copies the executable and common same-name runtime sidecars into the new AppContainer's local profile.
4. The program runs with no network capability. Its writable AppContainer profile is deleted after its process tree exits or you click **Stop isolated process**.

Managed programs that need additional dependency DLLs may not run because this version stages only the executable and common same-name sidecars. The app does not copy the entire source directory.

### Open a website

1. Enter a complete HTTP or HTTPS address and click **Isolate website**.
2. Review and accept the notice. ProcessVault starts Edge with an InPrivate, no-sync profile inside a new AppContainer.
3. Edge receives the `internetClient` capability for outbound internet access. The app does not grant `privateNetworkClientServer` or server-listening capabilities. The site still receives ordinary browser requests and anything you submit. Do not use sensitive accounts or data on untrusted sites.
4. Close the Edge window or use **Stop isolated process** to stop the contained process tree and remove its profile.

AppContainer network isolation is enforced by Windows Filtering Platform. Network classifications, firewall policy, VPNs, and Windows version can affect connectivity. ProcessVault does not monitor traffic, provide anonymity, or prove that every internal destination is unreachable.

## What the isolation does

- The child process is created with an AppContainer security token and low integrity.
- A per-session AppContainer profile provides temporary writable storage. The selected executable is copied into that profile.
- Program sessions receive no AppContainer capabilities. Website sessions receive `internetClient` only.
- A Windows Job Object groups descendant processes, caps the tree at 64 processes and 2 GB of committed memory, and terminates it when ProcessVault closes the job.
- The browser is launched with a separate user data directory, InPrivate mode, and sync disabled.

Windows documents that AppContainer access combines the normal user/group permissions with the AppContainer package SID and capability SIDs. See [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer), [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation), and [network capability behavior](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831418%28v%3Dws.11%29).

## Limitations and intended use

- This is process isolation inside the same Windows kernel, not a virtual machine. A kernel vulnerability or unsupported application behavior may cross the intended boundary.
- AppContainer is not a full filesystem overlay. Reads depend on Windows ACLs and AppContainer rules; only writes granted by Windows are contained. Do not run samples that need assurance of host confidentiality or integrity.
- Some desktop programs and browsers may refuse to run or may have reduced functionality in an AppContainer. Microsoft Edge installation and Windows policy can affect browser launch.
- The app does not monitor file, registry, browser, or network activity and does not assign a malware verdict.
- CPU is observed but not capped. The Job Object applies process-count and memory ceilings as well as process-tree cleanup.
- Reports and local history are mutable local observations, not forensic evidence.
- If ProcessVault crashes, the job handle closes and stops contained processes, but the per-session profile may remain under `%LOCALAPPDATA%\Packages` for manual cleanup.

Use this for a supervised class demonstration of process isolation and capability-based networking. For serious malware, use a patched disposable VM or managed analysis environment.

## Project layout

- `src/ProcessVault.Core`: AppContainer process creation, argument validation, process inventory, and reports.
- `src/ProcessVault.Desktop`: WPF interface.
- `tests/ProcessVault.Tests`: validation and harmless isolation checks.
- `fixtures/HarmlessProbe`: benign process and file-write demonstration.

## License

GNU General Public License version 3. See [LICENSE](LICENSE).
