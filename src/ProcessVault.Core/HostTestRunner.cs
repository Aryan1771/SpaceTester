using System.Diagnostics;
using System.Security.Cryptography;

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
        await using (var stream = File.OpenRead(fullPath)) _hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, token));

        var start = new ProcessStartInfo(fullPath) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(fullPath)! };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        _process = new Process { StartInfo = start, EnableRaisingEvents = true };
        _process.OutputDataReceived += (_, e) => { if (e.Data is not null) AddEvent("stdout", Bound(e.Data)); };
        _process.ErrorDataReceived += (_, e) => { if (e.Data is not null) AddEvent("stderr", Bound(e.Data)); };
        _process.Exited += (_, _) => OnExited();
        if (!_process.Start()) throw new InvalidOperationException("Program failed to start.");
        _process.BeginOutputReadLine();
        _process.BeginErrorReadLine();
        _startedAt = DateTimeOffset.UtcNow;
        _endedAt = null;
        _state = "Running";
        AddEvent("launch", $"Started {_targetName} (PID {_process.Id}) on the host. This is not isolated.");
        StateChanged?.Invoke();
    }

    public void OpenWebsite(string address)
    {
        if (IsRunning) throw new InvalidOperationException("Stop the current program test first.");
        var uri = LaunchValidation.ValidateWebAddress(address);
        Process.Start(new ProcessStartInfo(uri.AbsoluteUri) { UseShellExecute = true });
        _kind = "Website";
        _targetName = LaunchValidation.RedactAddress(uri);
        _hash = null;
        _startedAt = DateTimeOffset.UtcNow;
        _endedAt = DateTimeOffset.UtcNow;
        _state = "Opened in default browser";
        AddEvent("website", $"Opened {_targetName} in the default browser. Existing browser profile, cookies and host network are available.");
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

    private void OnExited()
    {
        try
        {
            _endedAt = DateTimeOffset.UtcNow;
            _state = $"Exited (code {_process?.ExitCode})";
            AddEvent("exit", _state);
            StateChanged?.Invoke();
        }
        catch (InvalidOperationException) { }
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

    private static string Bound(string line)
    {
        var safe = new string(line.Where(c => !char.IsControl(c) || c is '\t').ToArray());
        return safe.Length > 2000 ? safe[..2000] + " [truncated]" : safe;
    }

    public void Dispose() => _process?.Dispose();
}
