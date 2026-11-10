# ProcessVault Threat Model

## Purpose and security boundary

ProcessVault prepares Windows Sandbox configurations for a program or a website browser session. The actual VM-backed isolation boundary is implemented by Windows Sandbox and its Hyper-V architecture, not by ProcessVault. The selected program and website are treated as untrusted.

## Program flow

ProcessVault validates an existing `.exe`, parses the optional Windows argument line, copies the executable to a unique temporary directory, hashes the staged copy, and writes a PowerShell launch script plus a `.wsb` file. The guest maps that directory as `C:\ProcessVault` with `ReadOnly=true`. Networking is disabled. Guest filesystem changes are discarded when its session closes.

## Website flow

ProcessVault accepts only absolute HTTP or HTTPS URLs without embedded credentials. It writes a generated PowerShell script to a unique temporary directory and launches a Windows Sandbox guest with that script folder mapped read-only. The script starts Microsoft Edge with `--inprivate`, `--no-first-run`, and `--disable-sync`. No host browser profile, cookies, clipboard, or personal files are mapped. Networking is enabled so the browser can load the requested website. The guest has no persistent browser profile, and the Sandbox discards its state on close.

## Website privacy and network exposure

Website isolation protects the host browser profile and files from ordinary guest access; it does not hide browser traffic from the destination site or network operator. The site receives the URL and normal HTTP requests and can receive data the user submits, including credentials and uploaded files. InPrivate mode is not anonymity and does not prevent a site from tracking the current session.

Windows Sandbox networking may expose the guest to internal network services. This implementation does not use a controlled proxy, hostname allowlist, egress firewall, DNS pinning, or a mechanism that guarantees the guest can reach public Internet sites while being unable to reach private/LAN addresses. A malicious page may exploit the browser or attempt access to reachable services. For untrusted sites, do not sign in or enter sensitive data. For strict egress controls or malware detonation, use a dedicated analysis VM/network with explicit policy.

## Shared configuration

Clipboard redirection, vGPU, audio input, video input, and printer redirection are disabled. Protected Client mode is enabled and guest memory is set to 4096 MB. The staging folder is read-only and removed when the Sandbox launcher exits; a crash may leave it behind. ProcessVault cannot observe guest browser traffic, page behavior, filesystem, registry, child processes, or resource usage. Reports are host-side session metadata, not forensic evidence or a malware verdict. Closing the launcher from ProcessVault is a best-effort window close request; the user may need to close the Sandbox guest window directly.

## Limitations

- Windows Sandbox is not supported on Windows Home and must be installed, enabled, and operational. Group policy can restrict features or mapped folders.
- No sandbox is guaranteed escape-proof. Windows, hypervisor, guest image, drivers, and hardware vulnerabilities remain relevant.
- Only one executable is staged for program tests. Adjacent dependencies and writable result export are unsupported.
- The website session depends on Microsoft Edge being present in the guest Windows image.
- Networking enabled for a website session is broad; this app does not constrain destinations to public websites.
- The process list contains host processes only. Exported JSON and local history are mutable observations.

## Safer operation

Keep Windows and its virtualization components patched. Only browse to sites you intend to contact. Do not enter personal credentials or sensitive information into untrusted sites. For high-risk analysis, use a dedicated disposable machine or a managed environment with network egress controls and no personal accounts.

## References

- [Windows Sandbox overview and supported editions](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview)
- [Windows Sandbox configuration files](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
