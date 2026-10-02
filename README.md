# ProcessVault

ProcessVault is a small Windows desktop panel for launching a user-selected program, opening a user-entered website, and observing host process activity. It is a local testing utility, **not a sandbox**. Programs run with the current Windows account's permissions. Websites open in the default browser with its normal profile, cookies, extensions, and network access. Do not use ProcessVault to run malware or software you do not trust.

## Features

- Choose an `.exe` through a file picker and launch it with optional parsed arguments. Arguments are passed as structured process arguments; no shell command is assembled.
- Open HTTP or HTTPS addresses after an explicit confirmation. URLs containing embedded credentials and non-web schemes are rejected.
- Browse the host process inventory with PID, parent PID, memory, sampled CPU, and executable path when permissions allow.
- Observe a selected process read-only. Stop is limited to a program ProcessVault launched and terminates its currently reachable process tree.
- Collect bounded stdout/stderr for launched console programs, calculate the executable SHA-256, keep a local report history, and export JSON on request.
- Run a harmless fixture that writes only into a unique directory under the current user's LocalAppData and starts a child process.

## Build and run

Requirements: 64-bit Windows 10/11 and the .NET 8 SDK. No virtualization feature, administrator privilege, external package, or third-party prebuilt testing application is required.

```powershell
dotnet build ProcessVault.sln
dotnet run --project src/ProcessVault.Desktop
dotnet run --project tests/ProcessVault.Tests
dotnet publish src/ProcessVault.Desktop -c Release -r win-x64 --self-contained false
```

To demonstrate the process flow, publish and select the included harmless fixture:

```powershell
dotnet publish fixtures/HarmlessProbe -c Release -r win-x64 --self-contained false
```

Select `fixtures/HarmlessProbe/bin/Release/net8.0/win-x64/publish/HarmlessProbe.exe`, confirm the host-execution warning, and review its output and child PID in the activity pane. The fixture writes one marker in `%LOCALAPPDATA%\ProcessVaultFixture\<run-id>`. Remove the fixture directory after inspecting it.

## Architecture and trust model

- **Desktop UI:** WPF control panel, program/file picker, URL input, process list, safety confirmation, activity timeline, and explicit report export.
- **Launch and validation core:** URL scheme checks, Windows argument parsing, executable SHA-256, direct process launch, and local process inventory.
- **Process observer:** Windows Toolhelp parent-PID enumeration plus `System.Diagnostics` CPU-time and working-set samples. Access-denied fields remain unavailable rather than inferred.
- **Local data:** `%LOCALAPPDATA%\ProcessVault\history.json` stores recent run metadata locally. Exported JSON contains host-observed events only. Website history stores only the site authority, not its path or query string.
- **Fixture:** a benign executable demonstrates stdout, child-process creation, and a confined example file write. It is a demonstration of ordinary host behavior, not a security test harness.

The selected executable is untrusted input but is launched directly on the host. The panel is not an isolation boundary, does not lower the token, does not restrict filesystem or registry access, and does not constrain network connections. The host process inventory is observational and may omit protected processes. Website navigation uses the user's existing browser profile. ProcessVault does not inject code or modify observed processes. It does not monitor system-wide file changes, DNS, sockets, or browser network activity. A child's descendants may escape ordinary parent-tree tracking by detaching or using another broker; stop is best-effort process cleanup, not containment.

## Supported platform

The current implementation targets Windows 10/11 x64 and .NET 8 WPF. Other desktop operating systems are not implemented. Process metrics and parent-process enumeration use Windows APIs. The project uses only the .NET platform libraries; no external runtime or guest image is downloaded.

## Test coverage

The automated console suite checks HTTP(S) URL validation, rejects embedded URL credentials and unsafe schemes, checks executable path validation, exercises Windows argument parsing, confirms process inventory visibility, and ensures reports redact URL paths and query strings. It does not establish that arbitrary programs are safe. The harmless fixture is for a supervised demonstration only.

## Verified guarantees and limitations

Implemented behaviors include explicit user launch, direct argument passing without a shell, URL scheme validation, executable hashing, read-only process snapshots, bounded in-memory log history, a visible host-execution warning, JSON reporting, and a harmless fixture. These are application behaviors, not security containment guarantees. CPU and memory are observed; they are not capped. The website is opened by the system browser. Process activity can affect the host and its files, devices, accounts, and network. Use a separate disposable test machine or a properly configured virtualization product when isolation is required.

## Demonstration outline

1. Start ProcessVault and point out the permanent host-execution warning.
2. Filter the process table and select a process to observe it read-only.
3. Select the harmless fixture executable, review the warning, then watch stdout and the child process in the process table.
4. Stop the launched fixture if needed; export its JSON report.
5. Open a trusted local test page or public demo URL and explain that it uses the normal browser profile and is not isolated.

## License

ProcessVault is distributed under the GNU General Public License version 3, consistent with the repository's existing `LICENSE`.
