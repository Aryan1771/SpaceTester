# ProcessVault

ProcessVault is a Windows desktop launcher for running one selected executable in a disposable **Windows Sandbox** guest. It creates a `.wsb` configuration that disables networking, clipboard sharing, GPU, audio, video, and printer redirection; maps a temporary folder containing a copy of the selected executable and launch script as read-only; then starts the executable inside the guest. Closing the guest discards its state.

ProcessVault is a convenience front end to Microsoft's Windows Sandbox, not a custom hypervisor or antivirus. It does not determine whether a file is malicious or observe guest file, registry, process, or network activity. No software sandbox can guarantee protection against every vulnerability or escape.

## Requirements

- Windows 10 version 1903 or later, or Windows 11, on a supported edition: Pro, Enterprise, Education, or Pro Education/SE. Windows Home is not supported by Windows Sandbox.
- Windows Sandbox optional feature enabled, hardware virtualization enabled, and adequate memory and disk. Windows may require a restart after enabling the feature.
- 64-bit Windows and .NET 8 SDK to build the application.

Enable **Windows Sandbox** in *Turn Windows features on or off*, then restart. Microsoft documents edition and hardware prerequisites in [Windows Sandbox overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview) and [installation instructions](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install).

## Build and run

```powershell
dotnet build ProcessVault.sln
dotnet run --project src/ProcessVault.Desktop
```

Choose an `.exe`, optionally enter its Windows-style arguments, and select **Run in Sandbox**. A copy of that executable and a generated launch script are placed in a unique temporary staging directory. The guest receives read-only access to that directory at `C:\ProcessVault`. The executable's SHA-256 is calculated from the staged copy. ProcessVault's process table shows host processes only; guest process output and resource usage are not collected.

The selected executable is staged by itself. Programs that require adjacent DLLs, data files, installers, or other dependencies may fail to start. This version does not provide a writable result export channel. Use a purpose-built disposable VM for applications that need dependencies, network, persistent results, or deeper inspection.

## Isolation behavior

- Windows Sandbox supplies the VM-backed guest environment. ProcessVault does not emulate or implement that boundary itself.
- Networking and clipboard redirection are disabled. GPU, audio input, video input, and printer redirection are disabled; Protected Client mode is enabled. Guest memory is set to 4 GB.
- Only the staged executable and script folder is mapped into the guest, read-only. Do not map folders containing secrets.
- Guest changes are discarded when the Sandbox closes. The host staging folder is removed after the Sandbox process exits; cleanup may need manual attention if Windows Sandbox crashes.
- **Close Sandbox** closes the Windows Sandbox launcher process. Confirm any close prompt in Windows if shown.

These settings reduce exposure but do not prove a sample is harmless. Sandbox implementation flaws, vulnerabilities in Windows or hypervisor components, and policy restrictions remain possible. For high-risk malware analysis, use a dedicated, fully patched machine or professionally managed analysis environment with no sensitive accounts or network access.

## Other features

The process explorer lists host process metadata and supports read-only observation. It cannot see processes inside the guest. JSON reports and local history contain host-observed events only. They are not forensic records or malware verdicts. The old website-opening flow has been removed because it used the normal browser profile rather than an isolated browser guest.

## Development

Projects are organized under `src/ProcessVault.Core`, `src/ProcessVault.Desktop`, and `tests/ProcessVault.Tests`. `fixtures/HarmlessProbe` is a harmless process behavior sample, not a threat or containment test.

## License

GNU General Public License version 3. See [LICENSE](LICENSE).
