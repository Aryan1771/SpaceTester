using Microsoft.Win32;
using ProcessVault.Core;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace ProcessVault.Desktop;

public partial class MainWindow : Window
{
    private readonly string _data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ProcessVault");
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(2) };
    private readonly Dictionary<int, (TimeSpan Cpu, DateTime At)> _previous = [];
    private readonly List<ProcessRow> _all = [];
    private HostTestRunner? _runner;
    private ProcessRow? _selected;
    private Pending _pending;
    private DateTime _lastSample = DateTime.MinValue;
    public ObservableCollection<ProcessRow> Processes { get; } = [];
    public ObservableCollection<EventRow> Events { get; } = [];

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        Directory.CreateDirectory(_data);
        _timer.Tick += async (_, _) => await RefreshAsync();
        _timer.Start();
        Add("ready", "ProcessVault ready. Program launches and website browsing occur directly on this host.");
        _ = RefreshAsync();
    }

    private void Browse_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Choose a Windows program", Filter = "Programs (*.exe)|*.exe", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true) ProgramPathBox.Text = Path.GetFullPath(dialog.FileName);
    }

    private void Run_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(ProgramPathBox.Text)) { Warn("Choose a program first."); return; }
        _pending = Pending.Program;
        Warning.Visibility = Visibility.Visible;
    }

    private void Website_Click(object sender, RoutedEventArgs e)
    {
        try { _ = LaunchValidation.ValidateWebAddress(WebsiteBox.Text); }
        catch (Exception ex) { Warn(ex.Message); return; }
        _pending = Pending.Website;
        Warning.Visibility = Visibility.Visible;
    }

    private async void Confirm_Click(object sender, RoutedEventArgs e)
    {
        Warning.Visibility = Visibility.Collapsed;
        if (_runner?.IsRunning == true)
        {
            Warn("Stop the current launched program before starting another test. This keeps process monitoring attached to the correct target.");
            _pending = Pending.None;
            return;
        }
        try
        {
            ArchiveRunner();
            _runner = NewRunner();
            if (_pending == Pending.Program)
            {
                await _runner.LaunchProgramAsync(ProgramPathBox.Text, ArgumentsBox.Text);
                SessionTarget.Text = _runner.ToReport().TargetName;
                HashText.Text = $"SHA-256  {_runner.ToReport().Sha256}";
            }
            else
            {
                _runner.OpenWebsite(WebsiteBox.Text);
                SessionTarget.Text = _runner.ToReport().TargetName;
                HashText.Text = "Executable hash not applicable to a website.";
            }
            RenderRunner();
        }
        catch (Exception ex) { Warn(ex.Message); Add("error", $"Launch failed: {ex.Message}"); }
        _pending = Pending.None;
    }

    private HostTestRunner NewRunner()
    {
        var runner = new HostTestRunner();
        runner.EventAdded += evt => Dispatcher.Invoke(() => Add(evt.Type, $"{evt.Evidence}: {evt.Message}"));
        runner.StateChanged += () => Dispatcher.Invoke(RenderRunner);
        return runner;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) { Warning.Visibility = Visibility.Collapsed; _pending = Pending.None; }
    private void Stop_Click(object sender, RoutedEventArgs e) { _runner?.Stop(); RenderRunner(); }

    private void Observe_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is null) { Warn("Select a process from the table first."); return; }
        ArchiveRunner();
        _runner = NewRunner();
        _runner.ObserveProcess(_selected.Snapshot);
        SessionTarget.Text = _runner.ToReport().TargetName;
        HashText.Text = "No executable hash collected for read-only observation.";
        RenderRunner();
    }

    private void ArchiveRunner()
    {
        if (_runner is null) return;
        try
        {
            var historyPath = Path.Combine(_data, "history.json");
            var history = File.Exists(historyPath) ? JsonSerializer.Deserialize<List<LaunchRecord>>(File.ReadAllText(historyPath)) ?? [] : [];
            history.Insert(0, _runner.ToReport());
            if (history.Count > 100) history.RemoveRange(100, history.Count - 100);
            File.WriteAllText(historyPath, JsonSerializer.Serialize(history, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception ex) { Add("history", $"Local history write failed: {ex.Message}"); }
        _runner.Dispose();
        _runner = null;
    }

    private async void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_runner is null) { Warn("Start a test or observe a process first."); return; }
        var dialog = new SaveFileDialog { Filter = "JSON report (*.json)|*.json", FileName = $"processvault-{_runner.Id}.json", DefaultExt = ".json" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var export = new { ExportedAt = DateTimeOffset.UtcNow, Platform = Environment.OSVersion.ToString(), Isolation = "None - host execution", Report = _runner.ToReport(), Limitations = new[] { "The target was not isolated.", "System-wide file and network changes are not monitored.", "Process inventory may omit details without elevated permissions.", "Website activity occurs in the user's current browser profile." } };
            await File.WriteAllTextAsync(dialog.FileName, JsonSerializer.Serialize(export, new JsonSerializerOptions { WriteIndented = true }));
            Add("report", $"JSON report exported as {Path.GetFileName(dialog.FileName)}.");
        }
        catch (Exception ex) { Warn($"Report export failed: {ex.Message}"); }
    }

    private async Task RefreshAsync()
    {
        if (!IsLoaded) return;
        IReadOnlyList<ProcessSnapshot> snapshot;
        try { snapshot = await Task.Run(ProcessInventory.Read); }
        catch (Exception ex) { ProcessCount.Text = $"Inventory unavailable: {ex.Message}"; return; }
        var now = DateTime.Now;
        var dt = _lastSample == DateTime.MinValue ? 0 : Math.Max(.1, (now - _lastSample).TotalSeconds);
        var rows = snapshot.Select(p =>
        {
            var cpu = dt > 0 && _previous.TryGetValue(p.ProcessId, out var old) ? Math.Clamp((p.CpuTime - old.Cpu).TotalSeconds / dt / Environment.ProcessorCount * 100, 0, 100) : 0;
            _previous[p.ProcessId] = (p.CpuTime, now);
            return new ProcessRow(p, cpu);
        }).ToArray();
        var alive = rows.Select(p => p.ProcessId).ToHashSet();
        foreach (var pid in _previous.Keys.Where(pid => !alive.Contains(pid)).ToArray()) _previous.Remove(pid);
        _all.Clear(); _all.AddRange(rows); _lastSample = now;
        ApplyFilter();
        ProcessCount.Text = $"{rows.Length:N0} host processes   Refreshed {now:HH:mm:ss}";
        RefreshSelected();
        if (_runner?.ProcessId is int pidNow && rows.FirstOrDefault(r => r.ProcessId == pidNow) is { } monitored)
            SessionState.Text = $"{_runner.ToReport().State}   |   {monitored.CpuLabel} CPU   |   {monitored.MemoryLabel} RAM";
    }

    private void ApplyFilter()
    {
        if (Processes is null) return;
        var q = SearchBox.Text.Trim();
        var selectedId = _selected?.ProcessId;
        Processes.Clear();
        foreach (var p in _all.Where(p => q.Length == 0 || p.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || p.ProcessId.ToString().Contains(q, StringComparison.OrdinalIgnoreCase))) Processes.Add(p);
        if (selectedId.HasValue) ProcessGrid.SelectedItem = Processes.FirstOrDefault(p => p.ProcessId == selectedId.Value);
    }

    private void SearchChanged(object sender, TextChangedEventArgs e) => ApplyFilter();
    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();
    private void ProcessSelected(object sender, SelectionChangedEventArgs e) { _selected = ProcessGrid.SelectedItem as ProcessRow; RefreshSelected(); }

    private void RefreshSelected()
    {
        if (_selected is null) return;
        _selected = _all.FirstOrDefault(p => p.ProcessId == _selected.ProcessId) ?? _selected;
        SelectedName.Text = _selected.Name;
        SelectedDetails.Text = $"PID {_selected.ProcessId}  |  Parent {_selected.ParentLabel}\n{_selected.MemoryLabel} RAM  |  {_selected.CpuLabel} CPU\n{_selected.Path ?? "Executable path unavailable"}";
    }

    private void RenderRunner()
    {
        if (_runner is null) return;
        SessionState.Text = _runner.ToReport().State;
        if (_runner.ProcessId is int pid) SessionTarget.Text = $"{_runner.ToReport().TargetName} (PID {pid})";
    }

    private void Add(string type, string message)
    {
        Events.Insert(0, new EventRow(DateTime.Now.ToString("HH:mm:ss"), type, message));
        while (Events.Count > 250) Events.RemoveAt(Events.Count - 1);
        EventCount.Text = $"{Events.Count} events  |  host-observed";
    }

    private static void Warn(string message) => System.Windows.MessageBox.Show(message, "ProcessVault", MessageBoxButton.OK, MessageBoxImage.Warning);

    private async void Window_Closing(object? sender, CancelEventArgs e)
    {
        _timer.Stop();
        if (_runner?.IsRunning == true && _runner.ToReport().Kind == "Program")
        {
            var answer = System.Windows.MessageBox.Show("A launched program is still running. Stop it and its reachable child processes before closing?", "Program still running", MessageBoxButton.YesNoCancel, MessageBoxImage.Warning);
            if (answer == MessageBoxResult.Cancel) { e.Cancel = true; _timer.Start(); return; }
            if (answer == MessageBoxResult.Yes) _runner.Stop();
        }
        ArchiveRunner();
        await Task.CompletedTask;
    }

    private enum Pending { None, Program, Website }
    public sealed record EventRow(string Time, string Type, string Message);
    public sealed class ProcessRow
    {
        public ProcessSnapshot Snapshot { get; }
        public int ProcessId => Snapshot.ProcessId;
        public string Name => Snapshot.Name;
        public string ParentLabel => Snapshot.ParentProcessId?.ToString() ?? "-";
        public string MemoryLabel => $"{Snapshot.MemoryBytes / 1048576d:N0} MB";
        public string CpuLabel { get; }
        public string? Path => Snapshot.Path;
        public ProcessRow(ProcessSnapshot snapshot, double cpu) { Snapshot = snapshot; CpuLabel = $"{cpu:N1}%"; }
    }
}
