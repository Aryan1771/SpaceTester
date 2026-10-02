# ProcessVault Threat Model

## Purpose

ProcessVault is a desktop testing panel for inspecting ordinary Windows program and process behavior. It is not designed to contain malicious code. A user who needs containment must use a separate disposable VM or another independently validated security boundary.

## Assets and actors

- The Windows host, current user files, credentials, devices, browser profile, and network are in scope as assets that a launched program could reach.
- The operator selects a local executable, an HTTP(S) address, or an existing PID.
- A selected program or website is treated as untrusted for purposes of the UI warning, but ProcessVault launches it with the operator's normal account context.

## Trust boundaries

- The process inventory API supplies partial host observations. Paths and metrics can be unavailable due to access control, process exit races, or protected processes.
- Program stdout/stderr and process names are untrusted text. They are displayed as text, bounded, and never interpreted as markup or commands.
- Website addresses are limited to HTTP/HTTPS and reject user-info credentials. DNS resolution, redirects, private-network access, and browser behavior are delegated to the user's normal browser and network.
- Exported reports are created only after an explicit save action. Reports are local evidence, not tamper-proof forensic records.

## Security properties implemented

- Program paths are selected through a native file picker and validated as existing `.exe` files.
- Program arguments are parsed using Windows argument rules and passed through `ProcessStartInfo.ArgumentList`; no command shell is used.
- URL schemes are validated before opening in the default browser.
- Executable SHA-256 and host process metrics are recorded where available.
- A prominent confirmation describes the host permissions and browser profile exposure before launch.
- Observing an existing process is read-only. A stop action applies only to a process started by this panel.

## Explicit non-goals and residual risk

- No VM, container, restricted token, job memory/CPU policy, filesystem boundary, network boundary, device boundary, clipboard boundary, or credential protection is provided.
- Starting a program can modify or delete host data, access credentials, install persistence, communicate over the network, or launch detached descendants.
- Opening a site can expose existing cookies, extensions, signed-in accounts, and LAN access through the normal browser.
- Process-tree termination is best effort and does not guarantee that detached or brokered descendants are terminated.
- Process enumeration, CPU sampling, and executable paths are incomplete observations and can be spoofed or omitted.
- Reports and local history are mutable by the current user and are not cryptographically sealed.
- The tool does not determine whether activity is malicious and does not claim to detect malware.

## Safe use

Use only with software and sites you trust, or in a disposable test machine that has no sensitive data or accounts. For isolation requirements, use a properly configured VM and verify its network, device, sharing, and cleanup policy independently. ProcessVault is a convenience observer, not a replacement for that boundary.
