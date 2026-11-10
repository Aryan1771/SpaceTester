using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace ProcessVault.Core;

public sealed class HostTestRunner : IDisposable
{
    private readonly List<TestEvent> _events = [];
    private Process? _process;
    private DateTimeOffset? _endedAt;
    private string _state = "Ready";
    private DateTimeOffset _startedAt;
    private string _kind = "Program";
    private string _targetName = "";
    private string? _hash;

    public string Id { get; } = Guid.NewGuid().ToString("N");
    public int? ProcessId => _process is { HasExited: false } ? _process.Id : _process?.Id;
    public bool IsRunning => _process is { HasExited: false };
    public event Action<TestEvent>? EventAdded;
    public event Action? StateChanged;

    public async Task LaunchProgramAsync(string executable, string argumentLine, CancellationToken token = default)
    {
        if (IsRunning) throw new InvalidOperationException("Stop the current test before starting another.");
        var fullPath = LaunchValidation.NormalizeExecutable(executable);
        var args = LaunchValidation.ParseWindowsArguments(argumentLine);
        _kind = "Program";
        _targetName = Path.GetFileName(fullPath);
        var sandboxExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsSandbox.exe");
        if (!File.Exists(sandboxExe))
            throw new PlatformNotSupportedException("Windows Sandbox is not installed or enabled. Enable the Windows Sandbox optional feature on a supported Windows edition and restart.");

        var staging = Path.Combine(Path.GetTempPath(), "ProcessVault", Id);
        Directory.CreateDirectory(staging);
        var stagedExecutable = Path.Combine(staging, Path.GetFileName(fullPath));
        try
        {
            File.Copy(fullPath, stagedExecutable, overwrite: false);
            await using (var stream = File.OpenRead(stagedExecutable)) _hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, token));
            await File.WriteAllTextAsync(Path.Combine(staging, "launch.ps1"), BuildGuestScript(Path.GetFileName(fullPath), args), new UTF8Encoding(false), token);
            var config = BuildSandboxConfig(staging);
            var configPath = Path.Combine(staging, "ProcessVault.wsb");
            await File.WriteAllTextAsync(configPath, config, new UTF8Encoding(false), token);
            var start = new ProcessStartInfo(sandboxExe) { UseShellExecute = false };
            start.ArgumentList.Add(configPath);
            _process = new Process { StartInfo = start, EnableRaisingEvents = true };
            _process.Exited += (_, _) => OnExited(staging);
            if (!_process.Start()) throw new InvalidOperationException("Windows Sandbox failed to start.");
        }
        catch
        {
            try { Directory.Delete(staging, recursive: true); } catch { }
            throw;
        }
        _startedAt = DateTimeOffset.UtcNow;
        _endedAt = null;
        _state = "Running";
        AddEvent("sandbox", $"Started Windows Sandbox for {_targetName}. Network and clipboard are disabled; the staged executable is read-only inside the guest. Guest activity is not visible to the host process table.");
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
        if (_process is not { HasExited: false } process) return;
        _state = "Stopping";
        StateChanged?.Invoke();
        try
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit(5000);
            _state = "Stopped by user";
            AddEvent("stop", "Stopped the selected process and currently reachable child processes.");
        }
        catch (Exception ex)
        {
            _state = "Stop failed";
            AddEvent("stop-error", $"Could not stop process tree: {ex.Message}");
        }
        _endedAt = DateTimeOffset.UtcNow;
        StateChanged?.Invoke();
    }

    public LaunchRecord ToReport() => new(Id, _startedAt, _endedAt, _kind, _targetName, ProcessId, _hash, _state, _events.ToArray());

    private void OnExited(string? staging = null)
    {
        try
        {
            _endedAt = DateTimeOffset.UtcNow;
            _state = $"Exited (code {_process?.ExitCode})";
            AddEvent("exit", _state);
            if (staging is not null) try { Directory.Delete(staging, recursive: true); } catch { AddEvent("cleanup", "Temporary staging folder could not be removed automatically."); }
            StateChanged?.Invoke();
        }
        catch (InvalidOperationException) { }
    }

    private static string BuildGuestScript(string executable, IReadOnlyList<string> args)
    {
        static string Quote(string value)
        {
            var output = new StringBuilder("\"");
            var slashes = 0;
            foreach (var c in value)
            {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') { output.Append('\\', slashes * 2 + 1).Append('"'); slashes = 0; continue; }
                output.Append('\\', slashes).Append(c);
                slashes = 0;
            }
            output.Append('\\', slashes * 2).Append('"');
            return output.ToString();
        }
        static string Ps(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
        var argumentLine = string.Join(" ", args.Select(Quote));
        return "$ErrorActionPreference = 'Stop'\r\n$exe = 'C:\\ProcessVault\\" + executable.Replace("'", "''", StringComparison.Ordinal) + "'\r\n$psi = New-Object System.Diagnostics.ProcessStartInfo\r\n$psi.FileName = $exe\r\n$psi.Arguments = " + Ps(argumentLine) + "\r\n$psi.WorkingDirectory = 'C:\\ProcessVault'\r\n$p = [System.Diagnostics.Process]::Start($psi)\r\n$p.WaitForExit()\r\nexit $p.ExitCode\r\n";
    }

    private static string BuildSandboxConfig(string hostFolder)
    {
        var escaped = SecurityElement.Escape(hostFolder) ?? throw new InvalidOperationException("Could not encode the staging path.");
        return "<Configuration>\r\n" +
               "  <VGpu>Disable</VGpu>\r\n  <Networking>Disable</Networking>\r\n" +
               "  <AudioInput>Disable</AudioInput>\r\n  <VideoInput>Disable</VideoInput>\r\n" +
               "  <PrinterRedirection>Disable</PrinterRedirection>\r\n  <ClipboardRedirection>Disable</ClipboardRedirection>\r\n" +
               "  <ProtectedClient>Enable</ProtectedClient>\r\n  <MemoryInMB>4096</MemoryInMB>\r\n" +
               "  <MappedFolders><MappedFolder><HostFolder>" + escaped + "</HostFolder><SandboxFolder>C:\\ProcessVault</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder></MappedFolders>\r\n" +
               "  <LogonCommand><Command>powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\ProcessVault\\launch.ps1</Command></LogonCommand>\r\n" +
               "</Configuration>\r\n";
    }

    private void AddEvent(string type, string message)
    {
        var evt = new TestEvent(DateTimeOffset.UtcNow, type, message);
        lock (_events)
        {
            _events.Add(evt);
            if (_events.Count > 500) _events.RemoveAt(0);
        }
        EventAdded?.Invoke(evt);
    }

    public void Dispose() => _process?.Dispose();
}
