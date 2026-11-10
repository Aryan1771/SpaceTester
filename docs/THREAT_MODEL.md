# ProcessVault Threat Model

## Purpose

ProcessVault is a supervised educational demonstration of Windows AppContainer process isolation. It starts a selected executable or Edge in a unique AppContainer and uses a Windows Job Object for descendant cleanup and basic resource ceilings. It is not a VM and is not suitable for serious malware containment.

## Isolation model

ProcessVault creates a unique AppContainer profile per session. It copies the selected executable and common same-name sidecars into the profile's local data directory, then launches it with `STARTUPINFOEX` and `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`. Program sessions receive no capabilities. Website sessions receive the `internetClient` capability, but not `privateNetworkClientServer` or `internetClientServer`. The process tree is assigned to a Job Object configured to terminate processes when its handle closes, with a 64-process limit and 2 GB memory limit.

The app uses the documented Windows AppContainer mechanism; it does not use Windows Sandbox or implement a new kernel/hypervisor. The OS still enforces AppContainer token, integrity, resource ACL, and network isolation rules.

## Assets and trust

The host user's files, credentials, devices, processes, and network are sensitive. The selected executable is untrusted. Its staged copy is placed in the AppContainer profile. AppContainer processes can access system resources that Windows explicitly allows; this is not an empty guest OS. Profile cleanup removes per-session app data when the launched process tree exits.

## Network behavior

Program sessions have no explicit AppContainer network capability. Website sessions get outbound Internet capability so Edge can load pages. The destination receives ordinary requests and any submitted data. The app does not provide traffic interception, destination allowlisting, anonymity, or a proof of non-reachability for all local network destinations. Windows Filtering Platform, network classification, firewall rules, VPN policy, and OS version affect actual behavior.

## Limitations

- AppContainer is process isolation within the host kernel, not a virtual-machine boundary. Kernel vulnerabilities and unsupported behaviors can defeat intended isolation.
- AppContainer is capability and ACL based, not a complete filesystem overlay. Do not assume every host read or write is blocked.
- Some desktop applications and browser configurations will not run correctly in an AppContainer.
- The selected executable and common same-name sidecars are staged; arbitrary dependency trees are not.
- ProcessVault does not observe file, registry, network, browser, or guest activity and does not identify malware.
- CPU is not capped. The Job Object applies process-tree cleanup and count/memory ceilings, but those are resource controls, not an escape boundary.
- Local reports and history can be changed by the user and are not forensic records.

## Intended use

Use this for a supervised cybersecurity class project that demonstrates restricted tokens, capability-based network access, per-session storage, and descendant cleanup. Use a patched disposable VM or managed lab for serious malware analysis.

## References

- [Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- [AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
- [Network capability behavior](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831418%28v%3Dws.11%29)
