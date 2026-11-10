# ProcessVault Threat Model

## Purpose and security boundary

ProcessVault prepares a Windows Sandbox configuration and asks the Windows Sandbox feature to start an executable in a disposable guest. The actual isolation boundary is implemented by Windows Sandbox and its Hyper-V architecture, not by ProcessVault. The selected program is treated as untrusted.

## Flow and exposed host data

ProcessVault validates an existing `.exe`, parses the optional Windows argument line, copies the executable to a unique temporary directory, hashes the staged copy, and writes a PowerShell launch script plus a `.wsb` file. The guest maps that directory as `C:\ProcessVault` with `ReadOnly=true`. It contains only the selected executable and generated script. ProcessVault passes the `.wsb` path to `WindowsSandbox.exe`.

The configuration disables networking, clipboard redirection, vGPU, audio input, video input, and printer redirection, enables Protected Client mode, and requests 4096 MB guest memory. Windows Sandbox starts the script on guest logon. Guest filesystem changes are discarded when its session closes. ProcessVault removes the host staging directory after the Sandbox launcher exits.

## Assets and trust

The host OS, user data, credentials, devices, and network are sensitive. The mapped folder contains the selected executable and launch script and is shared read-only. The selected program can read its mapped contents. Its own guest output cannot be exported by this app.

## What the application does not guarantee

- Windows Sandbox is not supported on Windows Home and must be installed, enabled, and operational. Group policy can restrict features or mapped folders.
- No sandbox is guaranteed escape-proof. Windows, hypervisor, guest image, drivers, and hardware vulnerabilities remain relevant.
- Networking disabled prevents ordinary guest network access, but no independent network monitoring is performed.
- The app cannot observe guest stdout/stderr, filesystem or registry activity, child processes, or resource usage. The host process list does not show guest process details.
- Only one executable is staged. Adjacent dependencies, data files, installers, and writable result export are unsupported.
- The hash identifies the staged copy at launch, not publisher trust or safety.
- A selected executable can still exercise any vulnerability in the guest or Sandbox boundary. The host staging directory remains present during the session and is removed on launcher exit; a crash can leave it behind.
- ProcessVault history and exported JSON are mutable local observations, not sealed evidence.
- Website isolation is not implemented. Website launch was removed rather than opening an untrusted page in the host's normal browser profile.

## Safer operation

Keep Windows and its virtualization components patched. Do not map folders containing sensitive data. For high-risk malware, use a dedicated disposable machine or a managed analysis environment separated from personal accounts and networks. Treat results as observations, not a malware verdict.

## References

- [Windows Sandbox overview and supported editions](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview)
- [Windows Sandbox configuration files](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
