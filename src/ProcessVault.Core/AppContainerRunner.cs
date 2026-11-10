using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProcessVault.Core;

/// <summary>Educational, per-process isolation using Windows AppContainer security tokens.</summary>
public sealed class AppContainerRunner : IDisposable
{
    private const uint ProcThreadAttributeSecurityCapabilities = 0x00020009;
    private const uint ExtendedStartupInfoPresent = 0x00080000;
    private const uint CreateSuspended = 0x00000004;
    private const uint JobObjectExtendedLimitInformationClass = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x00002000 | 0x00000200 | 0x00000008;
    private readonly List<TestEvent> _events = [];
    private readonly object _jobSync = new();
    private Process? _process;
    private SafeFileHandle? _job;
    private bool _jobTreeStopped;
    private string? _profileName;
    private string _state = "Ready";
    private string _kind = "Program";
    private string _targetName = "";
    private string? _hash;
    private DateTimeOffset _startedAt;
    private DateTimeOffset? _endedAt;

    public string Id { get; } = Guid.NewGuid().ToString("N");
    public int? ProcessId => _process is { HasExited: false } ? _process.Id : _process?.Id;
    public bool IsRunning => _process is { HasExited: false };
    public event Action<TestEvent>? EventAdded;
    public event Action? StateChanged;

    public static IReadOnlyList<string> CapabilitiesFor(bool internet) => internet ? ["internetClient"] : [];
    public static string QuoteArgument(string value) => Quote(value);

    public Task LaunchProgramAsync(string executable, string argumentLine, CancellationToken token = default)
    {
        var args = LaunchValidation.ParseWindowsArguments(argumentLine);
        return LaunchAsync(executable, args, network: false, kind: "Program", target: Path.GetFileName(executable), token);
    }

    public Task LaunchWebsiteAsync(string address, CancellationToken token = default)
    {
        var uri = LaunchValidation.ValidateWebAddress(address);
        var edge = FindEdge();
        var profileArgs = new[] { "--inprivate", "--no-first-run", "--disable-sync", "--disable-features=msEdgeSidebarV2", uri.AbsoluteUri };
        _websiteUri = uri;
        return LaunchAsync(edge, profileArgs, network: true, kind: "Website", target: LaunchValidation.RedactAddress(uri), token);
    }

    private Uri? _websiteUri;

    private async Task LaunchAsync(string executable, IReadOnlyList<string> arguments, bool network, string kind, string target, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("AppContainer isolation is available only on Windows.");
        if (IsRunning) throw new InvalidOperationException("Stop the current isolated session before starting another.");
        var fullPath = LaunchValidation.NormalizeExecutable(executable);
        _kind = kind;
        _targetName = target;
        _hash = null;
        var profile = CreateProfile(network);
        _profileName = profile.Name;
        var work = Path.Combine(profile.LocalDataPath, "Work");

        try
        {
            Directory.CreateDirectory(work);
            var staged = Path.Combine(work, Path.GetFileName(fullPath));
            if (kind == "Program")
            {
                File.Copy(fullPath, staged);
                await using var stream = File.OpenRead(staged);
                _hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, token));
                CopySidecars(fullPath, work);
            }

            var launchArgs = arguments.ToList();
            if (kind == "Website")
            {
                launchArgs = ["--inprivate", "--no-first-run", "--disable-sync", "--user-data-dir=" + Path.Combine(profile.LocalDataPath, "BrowserProfile"), _websiteUri!.AbsoluteUri];
            }
            var launchPath = kind == "Website" ? fullPath : staged;
            var commandLine = Quote(launchPath) + " " + string.Join(" ", launchArgs.Select(Quote));
            using var attributes = new StartupAttributes(profile.Sid, network ? "internetClient" : null);
            _job = CreateKillOnCloseJob();
            var created = CreateSuspendedAppContainerProcess(launchPath, commandLine, Path.GetDirectoryName(launchPath)!, attributes);
            using (created.ProcessHandle)
            using (created.ThreadHandle)
            {
                if (!AssignProcessToJobObject(_job, created.ProcessHandle))
                {
                    var error = Marshal.GetLastWin32Error();
                    TerminateProcess(created.ProcessHandle, 1);
                    WaitForSingleObject(created.ProcessHandle, 5000);
                    throw new Win32Exception(error, "Could not place the isolated process in its cleanup job.");
                }
                if (ResumeThread(created.ThreadHandle) == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not resume the isolated process.");
                _process = Process.GetProcessById(created.ProcessId);
            }
            _process.EnableRaisingEvents = true;
            _process.Exited += (_, _) => OnExited();
        }
        catch
        {
            var treeStopped = StopJobTree();
            if (treeStopped && _profileName is not null) DeleteAppContainerProfile(_profileName);
            _profileName = null;
            throw;
        }

        _startedAt = DateTimeOffset.UtcNow;
        _endedAt = null;
        _state = network ? "Running in AppContainer (internet capability only)" : "Running in AppContainer (network disabled)";
        AddEvent("isolation", $"Started {_targetName} in a low-integrity AppContainer. Network capability: {(network ? "internetClient" : "none")}. Writes are scoped to the temporary AppContainer profile; clipboard and host browser profile are not shared.");
        StateChanged?.Invoke();
    }

    public void ObserveProcess(ProcessSnapshot process)
    {
        _kind = "Observed process";
        _targetName = $"{process.Name} (PID {process.ProcessId})";
        _hash = null;
        _startedAt = DateTimeOffset.UtcNow;
        _endedAt = null;
        _state = "Observing (read-only)";
        AddEvent("observe", $"Attached read-only observation to host PID {process.ProcessId}. No process injection or modification is used.");
        StateChanged?.Invoke();
    }

    public void Stop()
    {
        if (_process is not { HasExited: false }) return;
        _state = "Stopping isolated process tree";
        StateChanged?.Invoke();
        var treeStopped = StopJobTree();
        try { _process.WaitForExit(5000); } catch { }
        if (!_process.HasExited)
        {
            try { _process.Kill(entireProcessTree: true); _process.WaitForExit(5000); }
            catch (Exception ex) { AddEvent("stop-error", ex.Message); }
        }
        _endedAt = DateTimeOffset.UtcNow;
        _state = treeStopped ? "Stopped; temporary AppContainer profile is being removed" : "Stopped; profile cleanup deferred because process-tree exit could not be confirmed";
        StateChanged?.Invoke();
        if (treeStopped) CleanupProfile();
    }

    public LaunchRecord ToReport() => new(Id, _startedAt, _endedAt, _kind, _targetName, ProcessId, _hash, _state, _events.ToArray());

    private void OnExited()
    {
        var treeStopped = StopJobTree();
        _endedAt = DateTimeOffset.UtcNow;
        _state = treeStopped ? $"Exited (code {_process?.ExitCode}); temporary profile removed" : $"Exited (code {_process?.ExitCode}); profile cleanup deferred";
        if (treeStopped) CleanupProfile();
        else AddEvent("cleanup-warning", "Could not confirm all child processes exited; the AppContainer profile was left in place.");
        AddEvent("exit", _state);
        StateChanged?.Invoke();
    }

    private void CleanupProfile()
    {
        if (_profileName is null) return;
        var name = _profileName;
        _profileName = null;
        var hr = DeleteAppContainerProfile(name);
        if (hr < 0)
        {
            _state += " (temporary profile cleanup failed)";
            AddEvent("cleanup-warning", $"AppContainer profile cleanup returned 0x{hr:X8}; after confirming the process tree has exited, check %LOCALAPPDATA%\\Packages for a ProcessVault-* folder.");
        }
    }

    private bool StopJobTree()
    {
        lock (_jobSync)
        {
            if (_job is null) return _jobTreeStopped;
            var job = _job;
            _job = null;
            try
            {
                TerminateJobObject(job, 0);
                _jobTreeStopped = WaitForSingleObject(job, 5000) == 0;
                return _jobTreeStopped;
            }
            finally { job.Dispose(); }
        }
    }

    private void AddEvent(string type, string message)
    {
        var item = new TestEvent(DateTimeOffset.UtcNow, type, message, "ProcessVault observed");
        lock (_events) { _events.Add(item); if (_events.Count > 500) _events.RemoveAt(0); }
        EventAdded?.Invoke(item);
    }

    private static (string Name, string Sid, string LocalDataPath) CreateProfile(bool internet)
    {
        var name = "ProcessVault-" + Guid.NewGuid().ToString("N");
        IntPtr sidArray = IntPtr.Zero, sid = IntPtr.Zero;
        IntPtr capability = IntPtr.Zero;
        try
        {
            var count = 0;
            if (internet)
            {
                if (!DeriveCapabilitySidsFromName("internetClient", out var groups, out var groupCount, out sidArray, out count))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not resolve the internetClient capability.");
                FreeSidArray(groups, groupCount);
                if (count != 1) throw new InvalidOperationException("Expected one internetClient capability SID.");
                capability = Marshal.ReadIntPtr(sidArray);
            }

            var capabilityArray = IntPtr.Zero;
            if (internet)
            {
                capabilityArray = Marshal.AllocHGlobal(Marshal.SizeOf<SidAndAttributes>());
                Marshal.StructureToPtr(new SidAndAttributes { Sid = capability, Attributes = 0x4 }, capabilityArray, false);
            }
            var hr = CreateAppContainerProfile(name, "ProcessVault temporary session", "Temporary per-session application isolation", capabilityArray, internet ? 1u : 0u, out sid);
            if (capabilityArray != IntPtr.Zero) Marshal.FreeHGlobal(capabilityArray);
            if (hr == unchecked((int)0x800700B7)) hr = DeriveAppContainerSidFromAppContainerName(name, out sid);
            if (hr < 0) Marshal.ThrowExceptionForHR(hr);
            var sidText = ConvertSidToString(sid);
            var folderResult = GetAppContainerFolderPath(sidText, out var folderPtr);
            if (folderResult < 0) Marshal.ThrowExceptionForHR(folderResult);
            try
            {
                var folder = Marshal.PtrToStringUni(folderPtr) ?? throw new InvalidOperationException("Windows returned an empty AppContainer path.");
                Directory.CreateDirectory(folder);
                LocalFree(sid);
                sid = IntPtr.Zero;
                return (name, sidText, folder);
            }
            finally { CoTaskMemFree(folderPtr); }
        }
        catch
        {
            DeleteAppContainerProfile(name);
            if (sid != IntPtr.Zero) LocalFree(sid);
            throw;
        }
        finally
        {
            if (capability != IntPtr.Zero) LocalFree(capability);
            if (sidArray != IntPtr.Zero) LocalFree(sidArray);
        }
    }

    private static string ConvertSidToString(IntPtr sid)
    {
        if (!ConvertSidToStringSid(sid, out var text)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return Marshal.PtrToStringUni(text) ?? throw new InvalidOperationException("Could not convert AppContainer SID."); }
        finally { LocalFree(text); }
    }

    private static void FreeSidArray(IntPtr array, int count)
    {
        if (array == IntPtr.Zero) return;
        for (var i = 0; i < count; i++) { var sid = Marshal.ReadIntPtr(array, i * IntPtr.Size); if (sid != IntPtr.Zero) LocalFree(sid); }
        LocalFree(array);
    }

    private static string FindEdge()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft", "Edge", "Application", "msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Microsoft", "Edge", "Application", "msedge.exe")
        };
        return candidates.FirstOrDefault(File.Exists) ?? throw new FileNotFoundException("Microsoft Edge was not found. Install Edge or use the program launcher with a browser executable.");
    }

    private static void CopySidecars(string executable, string destination)
    {
        var source = Path.GetDirectoryName(executable)!;
        var stem = Path.GetFileNameWithoutExtension(executable);
        var sidecars = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var extension in new[] { ".dll", ".deps.json", ".runtimeconfig.json", ".config" })
        {
            var sidecar = Path.Combine(source, stem + extension);
            if (File.Exists(sidecar)) sidecars.Add(sidecar);
        }
        var deps = Path.Combine(source, stem + ".deps.json");
        if (File.Exists(deps))
        {
            try
            {
                using var json = JsonDocument.Parse(File.ReadAllText(deps));
                if (json.RootElement.TryGetProperty("targets", out var targets))
                    foreach (var target in targets.EnumerateObject())
                        foreach (var library in target.Value.EnumerateObject())
                            if (library.Value.TryGetProperty("runtime", out var runtime))
                                foreach (var asset in runtime.EnumerateObject())
                                {
                                    var candidate = Path.Combine(source, Path.GetFileName(asset.Name));
                                    if (Path.GetExtension(candidate).Equals(".dll", StringComparison.OrdinalIgnoreCase) && File.Exists(candidate)) sidecars.Add(candidate);
                                }
            }
            catch (JsonException) { }
        }
        foreach (var sidecar in sidecars) File.Copy(sidecar, Path.Combine(destination, Path.GetFileName(sidecar)), overwrite: true);
    }

    private static string Quote(string value)
    {
        var result = new StringBuilder("\"");
        var slashes = 0;
        foreach (var ch in value)
        {
            if (ch == '\\') { slashes++; continue; }
            if (ch == '"') { result.Append('\\', slashes * 2 + 1).Append('"'); slashes = 0; continue; }
            result.Append('\\', slashes).Append(ch);
            slashes = 0;
        }
        result.Append('\\', slashes * 2).Append('"');
        return result.ToString();
    }

    private static SafeFileHandle CreateKillOnCloseJob()
    {
        var job = CreateJobObject(IntPtr.Zero, null);
        if (job.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create process cleanup job.");
        var limits = new JobObjectExtendedLimitInformation();
        limits.BasicLimitInformation.LimitFlags = JobObjectLimitKillOnJobClose;
        limits.BasicLimitInformation.ActiveProcessLimit = 64;
        limits.JobMemoryLimit = new UIntPtr(2UL * 1024 * 1024 * 1024);
        var size = Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(limits, ptr, false);
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformationClass, ptr, (uint)size)) throw new Win32Exception(Marshal.GetLastWin32Error());
            return job;
        }
        catch { job.Dispose(); throw; }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    private static CreatedProcess CreateSuspendedAppContainerProcess(string executable, string commandLine, string workingDirectory, StartupAttributes attributes)
    {
        var startup = new StartupInfoEx { StartupInfo = new StartupInfo(), AttributeList = attributes.List };
        startup.StartupInfo.Size = (uint)Marshal.SizeOf<StartupInfoEx>();
        var mutable = new StringBuilder(commandLine);
        if (!CreateProcess(executable, mutable, IntPtr.Zero, IntPtr.Zero, false, ExtendedStartupInfoPresent | CreateSuspended, IntPtr.Zero, workingDirectory, ref startup, out var info))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows could not start the AppContainer process.");
        return new CreatedProcess(new SafeFileHandle(info.Process, ownsHandle: true), new SafeFileHandle(info.Thread, ownsHandle: true), info.ProcessId);
    }

    public void Dispose()
    {
        if (IsRunning) Stop();
        _process?.Dispose();
        _job?.Dispose();
    }

    private sealed class StartupAttributes : IDisposable
    {
        private readonly IntPtr _capabilities;
        private readonly IntPtr _list;
        private readonly IntPtr _sid;
        private readonly IntPtr _capabilityArray;
        private readonly IntPtr _capabilitySid;
        public IntPtr List => _list;

        public StartupAttributes(string appContainerSid, string? capabilityName)
        {
            var sid = IntPtr.Zero;
            var capabilitySid = IntPtr.Zero;
            IntPtr capabilityArray = IntPtr.Zero;
            IntPtr groupArray = IntPtr.Zero;
            try
            {
                if (!ConvertStringSidToSid(appContainerSid, out sid)) throw new Win32Exception(Marshal.GetLastWin32Error());
                var count = 0;
                if (capabilityName is not null)
                {
                    if (!DeriveCapabilitySidsFromName(capabilityName, out groupArray, out var groupCount, out var caps, out count)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    FreeSidArray(groupArray, groupCount); groupArray = IntPtr.Zero;
                    if (count != 1) throw new InvalidOperationException("Expected one capability SID.");
                    capabilitySid = Marshal.ReadIntPtr(caps);
                    LocalFree(caps);
                    capabilityArray = Marshal.AllocHGlobal(Marshal.SizeOf<SidAndAttributes>());
                    Marshal.StructureToPtr(new SidAndAttributes { Sid = capabilitySid, Attributes = 0x4 }, capabilityArray, false);
                }

                var security = new SecurityCapabilities { AppContainerSid = sid, Capabilities = capabilityArray, CapabilityCount = (uint)count };
                _capabilities = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityCapabilities>());
                Marshal.StructureToPtr(security, _capabilities, false);
                nuint size = 0;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                _list = Marshal.AllocHGlobal(checked((int)size));
                if (!InitializeProcThreadAttributeList(_list, 1, 0, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                if (!UpdateProcThreadAttribute(_list, 0, ProcThreadAttributeSecurityCapabilities, _capabilities, (nuint)Marshal.SizeOf<SecurityCapabilities>(), IntPtr.Zero, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                _sid = sid; sid = IntPtr.Zero;
                _capabilityArray = capabilityArray; capabilityArray = IntPtr.Zero;
                _capabilitySid = capabilitySid; capabilitySid = IntPtr.Zero;
            }
            catch
            {
                if (_list != IntPtr.Zero) Marshal.FreeHGlobal(_list);
                if (_capabilities != IntPtr.Zero) Marshal.FreeHGlobal(_capabilities);
                throw;
            }
            finally
            {
                if (sid != IntPtr.Zero) LocalFree(sid);
                if (capabilityArray != IntPtr.Zero) Marshal.FreeHGlobal(capabilityArray);
                if (capabilitySid != IntPtr.Zero) LocalFree(capabilitySid);
                if (groupArray != IntPtr.Zero) LocalFree(groupArray);
            }
        }

        public void Dispose()
        {
            if (_list != IntPtr.Zero) { DeleteProcThreadAttributeList(_list); Marshal.FreeHGlobal(_list); }
            if (_capabilities != IntPtr.Zero) Marshal.FreeHGlobal(_capabilities);
            if (_sid != IntPtr.Zero) LocalFree(_sid);
            if (_capabilityArray != IntPtr.Zero) Marshal.FreeHGlobal(_capabilityArray);
            if (_capabilitySid != IntPtr.Zero) LocalFree(_capabilitySid);
        }
    }

    private readonly record struct CreatedProcess(SafeFileHandle ProcessHandle, SafeFileHandle ThreadHandle, int ProcessId);
    [StructLayout(LayoutKind.Sequential)] private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct SecurityCapabilities { public IntPtr AppContainerSid; public IntPtr Capabilities; public uint CapabilityCount; public uint Reserved; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInfo { public uint Size; public string? Reserved; public string? Desktop; public string? Title; public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags; public ushort ShowWindow, Reserved2; public IntPtr Reserved2Ptr, StdInput, StdOutput, StdError; }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo StartupInfo; public IntPtr AttributeList; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation { public IntPtr Process, Thread; public int ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] private struct JobBasicLimitInformation { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct JobObjectExtendedLimitInformation { public JobBasicLimitInformation BasicLimitInformation; public IoCounters IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int CreateAppContainerProfile(string name, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr appContainerSid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr appContainerSid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int GetAppContainerFolderPath(string appContainerSid, out IntPtr path);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int DeleteAppContainerProfile(string name);
    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool DeriveCapabilitySidsFromName(string capabilityName, out IntPtr groupSids, out int groupSidCount, out IntPtr capabilitySids, out int capabilitySidCount);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSidToSid(string stringSid, out IntPtr sid);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("ole32.dll")] private static extern void CoTaskMemFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, int flags, ref nuint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, uint attribute, IntPtr value, nuint size, IntPtr previousValue, IntPtr returnSize);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcess(string? applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInfoEx startupInfo, out ProcessInformation processInformation);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeFileHandle CreateJobObject(IntPtr jobAttributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(SafeFileHandle job, uint infoClass, IntPtr info, uint infoLength);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(SafeFileHandle job, SafeFileHandle process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);
}
