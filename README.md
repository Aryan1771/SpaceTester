# ProcessVault

ProcessVault is a Windows desktop launcher for running a selected executable or opening a website in a disposable **Windows Sandbox** guest. Program guests have networking disabled. Website guests enable networking so public pages can load, and open Microsoft Edge in InPrivate mode. Both disable clipboard sharing, GPU, audio, video, and printer redirection and discard guest state when closed.

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
dotnet run --project tests/ProcessVault.Tests
```

Choose an `.exe`, optionally enter its Windows-style arguments, and select **Run program** to launch it in the offline guest. To browse, enter a complete HTTP or HTTPS address and choose **Open site in Sandbox**. Review the warning and confirm. This starts Edge inside a separate, temporary guest with no host browser profile, cookies, clipboard, or mapped personal files. It does not open the site in your host browser. Close the guest window when finished; ProcessVault will also ask whether to close an active guest when you exit.

The browser guest has network access. The website necessarily receives the requests your browser makes and any form data, credentials, or files you submit. A network-enabled Sandbox may also reach internal network services; this app does not add a network proxy, URL allowlist, or private-network firewall. Avoid signing into personal accounts or entering sensitive information, and use only sites you intend to contact. InPrivate mode prevents reuse of a persistent browser profile; it does not hide traffic from the site, network operator, or host network.

Program guests receive a read-only staging directory containing a copy of the executable and generated launch script. The executable's SHA-256 is calculated from the staged copy. Website guests receive a separate read-only folder containing only the generated browser launch script. ProcessVault's process table shows host processes only; guest page activity, browser traffic, process output, and resource usage are not collected.

The selected executable is staged by itself. Programs that require adjacent DLLs, data files, installers, or other dependencies may fail to start. This version does not provide a writable result export channel. Use a purpose-built disposable VM for applications that need dependencies, persistent results, controlled network policy, or deeper inspection.

## Isolation behavior

- Windows Sandbox supplies the VM-backed guest environment. ProcessVault does not emulate or implement that boundary itself.
- Program guests disable networking; website guests enable networking. Clipboard redirection remains disabled in both. GPU, audio input, video input, and printer redirection are disabled; Protected Client mode is enabled. Guest memory is set to 4 GB.
- Only the staged executable and generated script are mapped into the guest, read-only. No host browser profile, cookies, clipboard, or user files are mapped.
- Guest changes are discarded when the Sandbox closes. The host staging folder is removed after the Sandbox launcher exits; cleanup may need manual attention if Windows Sandbox crashes.
- **Close Sandbox** asks Windows to close the Sandbox launcher window. If Windows does not confirm closure, close the guest window directly. The host process table cannot verify guest shutdown.

These settings reduce exposure but do not prove a sample is harmless. Sandbox implementation flaws, vulnerabilities in Windows or hypervisor components, and policy restrictions remain possible. For high-risk malware analysis, use a dedicated, fully patched machine or professionally managed analysis environment with no sensitive accounts or network access.

## Other features

The process explorer lists host process metadata and supports read-only observation. It cannot see processes inside the guest. JSON reports and local history contain host-observed events only. They are not forensic records or malware verdicts.

## Development

Projects are organized under `src/ProcessVault.Core`, `src/ProcessVault.Desktop`, and `tests/ProcessVault.Tests`. `fixtures/HarmlessProbe` is a harmless process behavior sample, not a threat or containment test.

## License

GNU General Public License version 3. See [LICENSE](LICENSE).
