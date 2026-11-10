using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Runtime.Versioning;
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
    private readonly object _completionSync = new();
    private Process? _process;
    private SafeFileHandle? _job;
    private bool _jobTreeStopped;
    private bool _sessionCompleted;
    private string? _profileName;
    private string _state = "Ready";
    private string _kind = "Program";
    private string _targetName = "";
    private string? _hash;
    private DateTimeOffset _startedAt;
    private DateTimeOffset? _endedAt;

    public string Id { get; } = Guid.NewGuid().ToString("N");
    public int? ProcessId => _process is { HasExited: false } ? _process.Id : _process?.Id;
    public bool IsRunning => GetActiveProcessCount() > 0;
    public event Action<TestEvent>? EventAdded;
    public event Action? StateChanged;

    internal int[] GetJobProcessIds()
    {
        lock (_jobSync)
        {
            if (_job is null || _job.IsInvalid || _job.IsClosed) return [];
            const int capacity = 64;
            var size = 8 + capacity * IntPtr.Size;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (!QueryInformationJobObject(_job, 3, buffer, (uint)size, out _)) return [];
                var count = Math.Min(Marshal.ReadInt32(buffer, 4), capacity);
                var ids = new int[count];
                for (var index = 0; index < count; index++)
                    ids[index] = checked((int)Marshal.ReadIntPtr(buffer, 8 + index * IntPtr.Size).ToInt64());
                return ids;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
    }

    internal bool HasSandboxedBrowserChild()
    {
        var rootPid = ProcessId;
        return rootPid is not null && GetJobProcessIds().Any(pid => pid != rootPid && IsSandboxedProcess(pid));
    }

    public static IReadOnlyList<string> CapabilitiesFor(bool internet) => internet ? ["internetClient"] : [];
    public static string QuoteArgument(string value) => Quote(value);

    [SupportedOSPlatform("windows")]
    public Task LaunchProgramAsync(string executable, string argumentLine, CancellationToken token = default)
    {
        var args = LaunchValidation.ParseWindowsArguments(argumentLine);
        return LaunchAsync(executable, args, network: false, kind: "Program", target: Path.GetFileName(executable), token);
    }

    [SupportedOSPlatform("windows")]
    internal Task LaunchNetworkProbeAsync(string executable, string argumentLine, CancellationToken token = default)
    {
        var args = LaunchValidation.ParseWindowsArguments(argumentLine);
        return LaunchAsync(executable, args, network: true, kind: "Network probe", target: Path.GetFileName(executable), token);
    }

    [SupportedOSPlatform("windows")]
    public Task LaunchWebsiteAsync(string address, CancellationToken token = default)
    {
        var uri = LaunchValidation.ValidateWebAddress(address);
        var (browser, browserName, browserKind) = FindDefaultBrowser();
        return LaunchWebsiteWithBrowserAsync(uri, browser, browserName, browserKind, token);
    }

    [SupportedOSPlatform("windows")]
    public Task LaunchWebsiteWithBrowserAsync(string address, string browserExecutable, CancellationToken token = default)
    {
        var uri = LaunchValidation.ValidateWebAddress(address);
        var executable = LaunchValidation.NormalizeExecutable(browserExecutable);
        var name = Path.GetFileNameWithoutExtension(executable);
        var kind = GetBrowserKind(name);
        return LaunchWebsiteWithBrowserAsync(uri, executable, name, kind, token);
    }

    [SupportedOSPlatform("windows")]
    private Task LaunchWebsiteWithBrowserAsync(Uri uri, string browser, string browserName, BrowserKind browserKind, CancellationToken token)
    {
        _websiteUri = uri;
        _websiteName = browserName;
        _websiteKind = browserKind;
        return LaunchAsync(browser, [uri.AbsoluteUri], network: true, kind: "Website", target: LaunchValidation.RedactAddress(uri), token);
    }

    private Uri? _websiteUri;
    private string _websiteName = "default browser";
    private BrowserKind _websiteKind;
    public string WebsiteBrowserName => _websiteName;
    private enum BrowserKind { Edge, Chrome, Opera, Firefox, Chromium }

    [SupportedOSPlatform("windows")]
    private async Task LaunchAsync(string executable, IReadOnlyList<string> arguments, bool network, string kind, string target, CancellationToken token)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("AppContainer isolation is available only on Windows.");
        if (IsRunning) throw new InvalidOperationException("Stop the current isolated session before starting another.");
        var fullPath = LaunchValidation.NormalizeExecutable(executable);
        _kind = kind;
        _targetName = target;
        _sessionCompleted = false;
        _hash = null;
        var profile = CreateProfile(network && kind != "Website");
        _profileName = profile.Name;
        var work = Path.Combine(profile.LocalDataPath, "Work");

        try
        {
            Directory.CreateDirectory(work);
            Directory.CreateDirectory(Path.Combine(profile.LocalDataPath, "Local"));
            Directory.CreateDirectory(Path.Combine(profile.LocalDataPath, "Temp"));
            Directory.CreateDirectory(Path.Combine(profile.LocalDataPath, "Roaming"));
            var staged = Path.Combine(work, Path.GetFileName(fullPath));
            if (kind != "Website")
            {
                File.Copy(fullPath, staged);
                if (kind == "Program")
                {
                    await using var stream = File.OpenRead(staged);
                    _hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, token));
                }
                CopySidecars(fullPath, work);
            }

            var launchArgs = arguments.ToList();
            string? browserProfilePath = null;
            if (kind == "Website")
            {
                browserProfilePath = Path.Combine(profile.LocalDataPath, "BrowserProfile");
                Directory.CreateDirectory(browserProfilePath);
                launchArgs = _websiteKind switch
                {
                    BrowserKind.Firefox => ["-no-remote", "-profile", browserProfilePath, _websiteUri!.AbsoluteUri],
                    _ => ["--user-data-dir=" + browserProfilePath, "--no-first-run", _websiteUri!.AbsoluteUri],
                };
            }
            var launchPath = kind == "Website" ? fullPath : staged;
            var commandLine = Quote(launchPath) + " " + string.Join(" ", launchArgs.Select(Quote));
            _job = CreateKillOnCloseJob();
            var workingDirectory = browserProfilePath ?? Path.GetDirectoryName(launchPath)!;
            CreatedProcess created;
            if (kind == "Website")
                created = CreateSuspendedBrowserProcess(launchPath, commandLine, workingDirectory, profile.LocalDataPath);
            else
            {
                using var attributes = new StartupAttributes(profile.Sid, network ? "internetClient" : null);
                created = CreateSuspendedAppContainerProcess(launchPath, commandLine, workingDirectory, profile.LocalDataPath, attributes);
            }
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
            if (treeStopped)
            {
                if (_profileName is not null) DeleteAppContainerProfile(_profileName);
                _profileName = null;
            }
            else AddEvent("cleanup-warning", "Launch failed and the AppContainer process tree could not be confirmed stopped; temporary profile permissions were left in place for safety.");
            throw;
        }

        _startedAt = DateTimeOffset.UtcNow;
        _endedAt = null;
        _state = kind == "Website"
            ? "Running with the browser's native renderer sandbox and a private profile"
            : network ? "Running in AppContainer (internet capability only)" : "Running in AppContainer (network disabled)";
        var isolationMessage = kind == "Website"
            ? $"Started {_targetName} in {_websiteName} with a separate temporary browser profile and its native site-renderer sandbox. The browser controller runs as the current Windows user; website sessions do not use ProcessVault's AppContainer."
            : $"Started {_targetName} in a low-integrity AppContainer. Network capability: {(network ? "internetClient" : "none")} .";
        AddEvent("isolation", isolationMessage);
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
        if (!IsRunning) return;
        _state = "Stopping isolated process tree";
        StateChanged?.Invoke();
        var treeStopped = StopJobTree();
        if (_process is { } process)
        {
            try { process.WaitForExit(5000); } catch { }
            if (!process.HasExited)
            {
                try { process.Kill(entireProcessTree: true); process.WaitForExit(5000); }
                catch (Exception ex) { AddEvent("stop-error", ex.Message); }
            }
        }
        _endedAt = DateTimeOffset.UtcNow;
        _state = treeStopped ? "Stopped; temporary session profile is being removed" : "Stopped; profile cleanup deferred because process-tree exit could not be confirmed";
        StateChanged?.Invoke();
        if (treeStopped) CleanupProfile();
    }

    public LaunchRecord ToReport() => new(Id, _startedAt, _endedAt, _kind, _targetName, ProcessId, _hash, _state, _events.ToArray());

    private void OnExited()
    {
        if (GetActiveProcessCount() > 0)
        {
            _state = _kind == "Website"
            ? "Running with browser helper processes active"
                : "Running in AppContainer (child processes active)";
            AddEvent("launcher-exit", $"The initial process exited with code {_process?.ExitCode} while processes in its isolated job remain active; keeping the session open.");
            StateChanged?.Invoke();
            _ = MonitorJobUntilEmptyAsync();
            return;
        }
        CompleteSession();
    }

    private async Task MonitorJobUntilEmptyAsync()
    {
        while (GetActiveProcessCount() > 0) await Task.Delay(500);
        CompleteSession();
    }

    private void CompleteSession()
    {
        lock (_completionSync)
        {
            if (_sessionCompleted) return;
            _sessionCompleted = true;
        }
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

    private uint GetActiveProcessCount()
    {
        lock (_jobSync)
        {
            if (_job is null || _job.IsInvalid || _job.IsClosed) return 0;
            var info = new JobObjectBasicAccountingInformation();
            var size = (uint)Marshal.SizeOf<JobObjectBasicAccountingInformation>();
            var pointer = Marshal.AllocHGlobal((int)size);
            try
            {
                if (!QueryInformationJobObject(_job, 1, pointer, size, out _)) return 0;
                info = Marshal.PtrToStructure<JobObjectBasicAccountingInformation>(pointer);
                return info.ActiveProcesses;
            }
            finally { Marshal.FreeHGlobal(pointer); }
        }
    }

    private static bool IsSandboxedProcess(int processId)
    {
        using var process = OpenProcess(0x1000, false, (uint)processId);
        if (process.IsInvalid) return false;
        if (!OpenProcessToken(process, 0x0008, out var token)) return false;
        using (token)
        {
            var length = 0;
            _ = GetTokenInformation(token, 29, IntPtr.Zero, 0, out length);
            if (length >= sizeof(int))
            {
                var appContainer = Marshal.AllocHGlobal(length);
                try
                {
                    if (GetTokenInformation(token, 29, appContainer, length, out _) && Marshal.ReadInt32(appContainer) != 0) return true;
                }
                finally { Marshal.FreeHGlobal(appContainer); }
            }

            length = 0;
            _ = GetTokenInformation(token, 25, IntPtr.Zero, 0, out length);
            if (length < IntPtr.Size) return false;
            var integrity = Marshal.AllocHGlobal(length);
            try
            {
                if (!GetTokenInformation(token, 25, integrity, length, out _)) return false;
                var sid = Marshal.ReadIntPtr(integrity);
                var subAuthorityCount = GetSidSubAuthorityCount(sid);
                if (subAuthorityCount == IntPtr.Zero) return false;
                var count = Marshal.ReadByte(subAuthorityCount);
                if (count == 0) return false;
                var lastAuthority = GetSidSubAuthority(sid, (uint)(count - 1));
                return lastAuthority != IntPtr.Zero && Marshal.ReadInt32(lastAuthority) < 0x2000;
            }
            finally { Marshal.FreeHGlobal(integrity); }
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

    private static (string Executable, string Name, BrowserKind Kind) FindDefaultBrowser()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Default browser lookup is available only on Windows.");
        var progId = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice", "ProgId", null) as string;
        if (string.IsNullOrWhiteSpace(progId)) throw new InvalidOperationException("Windows did not report a default HTTPS browser.");
        var command = Registry.GetValue($@"HKEY_CLASSES_ROOT\{progId}\shell\open\command", null, null) as string;
        if (string.IsNullOrWhiteSpace(command)) throw new InvalidOperationException($"Could not read the open command for {progId}.");
        var match = System.Text.RegularExpressions.Regex.Match(command, @"^\s*""(?<path>[^""]+\.exe)""|^\s*(?<plain>[^\s]+\.exe)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        var executable = match.Groups["path"].Success ? match.Groups["path"].Value : match.Groups["plain"].Value;
        if (!match.Success || !File.Exists(executable)) throw new FileNotFoundException($"Could not locate the default browser executable for {progId}.");
        var name = Path.GetFileNameWithoutExtension(executable);
        return (executable, name, GetBrowserKind(name));
    }

    private static BrowserKind GetBrowserKind(string name) => name.ToLowerInvariant() switch
    {
        var n when n.Contains("firefox") => BrowserKind.Firefox,
        var n when n.Contains("msedge") => BrowserKind.Edge,
        var n when n.Contains("opera") => BrowserKind.Opera,
        var n when n.Contains("chrome") => BrowserKind.Chrome,
        _ => BrowserKind.Chromium,
    };

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

    private static CreatedProcess CreateSuspendedAppContainerProcess(string executable, string commandLine, string workingDirectory, string localDataPath, StartupAttributes attributes)
    {
        var startupInfo = new StartupInfo { Flags = 0x00000001, ShowWindow = 1 };
        var startup = new StartupInfoEx { StartupInfo = startupInfo, AttributeList = attributes.List };
        startup.StartupInfo.Size = (uint)Marshal.SizeOf<StartupInfoEx>();
        var mutable = new StringBuilder(commandLine);
        var environment = BuildIsolatedEnvironment(localDataPath);
        try
        {
            if (!CreateProcess(executable, mutable, IntPtr.Zero, IntPtr.Zero, false, ExtendedStartupInfoPresent | CreateSuspended | 0x00000400, environment, workingDirectory, ref startup, out var info))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows could not start the AppContainer process.");
            return new CreatedProcess(new SafeFileHandle(info.Process, ownsHandle: true), new SafeFileHandle(info.Thread, ownsHandle: true), info.ProcessId);
        }
        finally { Marshal.FreeHGlobal(environment); }
    }

    private static CreatedProcess CreateSuspendedBrowserProcess(string executable, string commandLine, string workingDirectory, string localDataPath)
    {
        var startup = new StartupInfo { Size = (uint)Marshal.SizeOf<StartupInfo>(), Flags = 0x00000001, ShowWindow = 1 };
        var mutable = new StringBuilder(commandLine);
        var environment = BuildBrowserEnvironment(localDataPath);
        try
        {
            const uint flags = CreateSuspended | 0x00000400;
            if (!CreateStandardProcess(executable, mutable, IntPtr.Zero, IntPtr.Zero, false, flags, environment, workingDirectory, ref startup, out var info))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not start the default browser in its private profile.");
            return new CreatedProcess(new SafeFileHandle(info.Process, ownsHandle: true), new SafeFileHandle(info.Thread, ownsHandle: true), info.ProcessId);
        }
        finally { Marshal.FreeHGlobal(environment); }
    }

    private static IntPtr BuildIsolatedEnvironment(string localDataPath)
    {
        var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ALLUSERSPROFILE", "COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "COMPUTERNAME", "HOMEDRIVE", "HOMEPATH",
            "NUMBER_OF_PROCESSORS", "OS", "PATH", "PATHEXT", "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER",
            "PROCESSOR_LEVEL", "PROCESSOR_REVISION", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "PUBLIC",
            "SYSTEMDRIVE", "SYSTEMROOT", "WINDIR"
        };
        var values = Environment.GetEnvironmentVariables().Keys.Cast<string>()
            .Where(allowed.Contains)
            .ToDictionary(key => key, key => Environment.GetEnvironmentVariable(key) ?? "", StringComparer.OrdinalIgnoreCase);
        var hostProfilePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var drive = Path.GetPathRoot(hostProfilePath) ?? Environment.GetEnvironmentVariable("SystemDrive") ?? "C:\\";
        values["APPDATA"] = Path.Combine(localDataPath, "Roaming");
        values["LOCALAPPDATA"] = localDataPath;
        values["TEMP"] = Path.Combine(localDataPath, "Temp");
        values["TMP"] = values["TEMP"];
        values["USERPROFILE"] = hostProfilePath;
        values["HOMEDRIVE"] = drive.TrimEnd('\\');
        values["HOMEPATH"] = hostProfilePath.StartsWith(drive, StringComparison.OrdinalIgnoreCase) ? hostProfilePath[drive.Length..] : hostProfilePath;
        var block = string.Join("\0", values.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => $"{pair.Key}={pair.Value}")) + "\0\0";
        return Marshal.StringToHGlobalUni(block);
    }

    private static IntPtr BuildBrowserEnvironment(string localDataPath)
    {
        var values = Environment.GetEnvironmentVariables().Keys.Cast<string>()
            .Where(key => key.StartsWith('=') || key.Equals("PATH", StringComparison.OrdinalIgnoreCase)
                || key.Equals("PATHEXT", StringComparison.OrdinalIgnoreCase)
                || key.Equals("SYSTEMROOT", StringComparison.OrdinalIgnoreCase)
                || key.Equals("WINDIR", StringComparison.OrdinalIgnoreCase)
                || key.Equals("SYSTEMDRIVE", StringComparison.OrdinalIgnoreCase)
                || key.Equals("PROGRAMFILES", StringComparison.OrdinalIgnoreCase)
                || key.Equals("PROGRAMFILES(X86)", StringComparison.OrdinalIgnoreCase)
                || key.Equals("COMMONPROGRAMFILES", StringComparison.OrdinalIgnoreCase)
                || key.Equals("COMMONPROGRAMFILES(X86)", StringComparison.OrdinalIgnoreCase)
                || key.Equals("COMPUTERNAME", StringComparison.OrdinalIgnoreCase)
                || key.Equals("USERNAME", StringComparison.OrdinalIgnoreCase)
                || key.Equals("USERDOMAIN", StringComparison.OrdinalIgnoreCase)
                || key.Equals("OS", StringComparison.OrdinalIgnoreCase)
                || key.Equals("PROCESSOR_ARCHITECTURE", StringComparison.OrdinalIgnoreCase)
                || key.Equals("NUMBER_OF_PROCESSORS", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(key => key, key => Environment.GetEnvironmentVariable(key) ?? "", StringComparer.OrdinalIgnoreCase);
        values["APPDATA"] = Path.Combine(localDataPath, "Roaming");
        values["LOCALAPPDATA"] = Path.Combine(localDataPath, "Local");
        values["TEMP"] = Path.Combine(localDataPath, "Temp");
        values["TMP"] = values["TEMP"];
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        values["USERPROFILE"] = userProfile;
        var drive = Path.GetPathRoot(userProfile) ?? "C:\\";
        values["HOMEDRIVE"] = drive.TrimEnd('\\');
        values["HOMEPATH"] = userProfile.StartsWith(drive, StringComparison.OrdinalIgnoreCase) ? userProfile[drive.Length..] : userProfile;
        var block = string.Join("\0", values.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => $"{pair.Key}={pair.Value}")) + "\0\0";
        return Marshal.StringToHGlobalUni(block);
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
    [StructLayout(LayoutKind.Sequential)] private struct JobObjectBasicAccountingInformation { public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime; public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses; }
    [StructLayout(LayoutKind.Sequential)] private struct JobBasicLimitInformation { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct JobObjectExtendedLimitInformation { public JobBasicLimitInformation BasicLimitInformation; public IoCounters IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int CreateAppContainerProfile(string name, string displayName, string description, IntPtr capabilities, uint capabilityCount, out IntPtr appContainerSid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr appContainerSid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int GetAppContainerFolderPath(string appContainerSid, out IntPtr path);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)] private static extern int DeleteAppContainerProfile(string name);
    [DllImport("kernelbase.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool DeriveCapabilitySidsFromName(string capabilityName, out IntPtr groupSids, out int groupSidCount, out IntPtr capabilitySids, out int capabilitySidCount);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertStringSidToSid(string stringSid, out IntPtr sid);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(SafeFileHandle process, uint desiredAccess, out SafeFileHandle token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(SafeFileHandle token, int informationClass, IntPtr information, int informationLength, out int returnLength);
    [DllImport("advapi32.dll")] private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")] private static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthorityIndex);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("ole32.dll")] private static extern void CoTaskMemFree(IntPtr memory);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, int flags, ref nuint size);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, uint attribute, IntPtr value, nuint size, IntPtr previousValue, IntPtr returnSize);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool CreateProcess(string? applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInfoEx startupInfo, out ProcessInformation processInformation);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateProcessW")] private static extern bool CreateStandardProcess(string applicationName, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInfo startupInfo, out ProcessInformation processInformation);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeFileHandle OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(SafeFileHandle thread);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeFileHandle CreateJobObject(IntPtr jobAttributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(SafeFileHandle job, uint infoClass, IntPtr info, uint infoLength);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool QueryInformationJobObject(SafeFileHandle job, uint infoClass, IntPtr info, uint infoLength, out uint returnLength);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(SafeFileHandle job, SafeFileHandle process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);
}
