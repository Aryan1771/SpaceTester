using ProcessVault.Core;
using System.Diagnostics;

if (args.Contains("--pv-appcontainer-probe", StringComparer.Ordinal)) return 0;

var failures = new List<string>();
void Check(bool condition, string name) { if (condition) Console.WriteLine($"PASS {name}"); else { failures.Add(name); Console.WriteLine($"FAIL {name}"); } }
void Throws<T>(Action action, string name) where T : Exception { try { action(); failures.Add(name); Console.WriteLine($"FAIL {name}"); } catch (T) { Console.WriteLine($"PASS {name}"); } }

Check(LaunchValidation.ValidateWebAddress("https://example.org/path").Host == "example.org", "accepts https address");
Check(LaunchValidation.ValidateWebAddress("http://localhost:8080").Port == 8080, "accepts local http test service");
Throws<ArgumentException>(() => LaunchValidation.ValidateWebAddress("javascript:alert(1)"), "rejects non-http URL scheme");
Throws<ArgumentException>(() => LaunchValidation.ValidateWebAddress("https://user:secret@example.org"), "rejects credentials in URL");
var parsed = LaunchValidation.ParseWindowsArguments("--label \"two words\" --count 3");
Check(parsed.Count == 4 && parsed[0] == "--label" && parsed[1] == "two words" && parsed[2] == "--count" && parsed[3] == "3", "Windows argument parser preserves tokens without shell expansion");
Check(LaunchValidation.NormalizeExecutable(Environment.ProcessPath!).EndsWith(".exe", StringComparison.OrdinalIgnoreCase), "validates an existing executable path");
var invalidPath = Path.Combine(Path.GetTempPath(), $"processvault-test-{Guid.NewGuid():N}.txt");
File.WriteAllText(invalidPath, "test");
Throws<ArgumentException>(() => LaunchValidation.NormalizeExecutable(invalidPath), "rejects a non-executable file");
File.Delete(invalidPath);
Throws<FileNotFoundException>(() => LaunchValidation.NormalizeExecutable(Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.exe")), "rejects a missing program");
var inventory = ProcessInventory.Read();
Check(inventory.Any(p => p.ProcessId == Environment.ProcessId), "process inventory includes current test process");
Check(inventory.All(p => p.MemoryBytes >= 0 && p.CpuTime >= TimeSpan.Zero), "process metrics are non-negative");
Check(LaunchValidation.RedactAddress(new Uri("https://example.org/private?token=secret")).Equals("https://example.org"), "website report omits path and query credentials");
Check(AppContainerRunner.CapabilitiesFor(internet: false).Count == 0, "program app container receives no capabilities");
Check(AppContainerRunner.CapabilitiesFor(internet: true).SequenceEqual(["internetClient"]), "website app container receives only internetClient capability");
Check(AppContainerRunner.QuoteArgument("two words") == "\"two words\"", "AppContainer launch quotes arguments with spaces");

if (OperatingSystem.IsWindows())
{
    using var runner = new AppContainerRunner();
    var finished = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    runner.StateChanged += () => { if (runner.ToReport().State.StartsWith("Exited", StringComparison.Ordinal)) finished.TrySetResult(true); };
    await runner.LaunchProgramAsync(Environment.ProcessPath!, "--pv-appcontainer-probe");
    await finished.Task.WaitAsync(TimeSpan.FromSeconds(15));
    Check(runner.ToReport().Events.Any(e => e.Type == "exit"), "harmless program starts and exits under AppContainer");
    Check(!runner.ToReport().Events.Any(e => e.Type == "cleanup-warning"), "temporary AppContainer profile is cleaned up");

    var repository = new DirectoryInfo(AppContext.BaseDirectory);
    while (repository is not null && !File.Exists(Path.Combine(repository.FullName, "ProcessVault.sln"))) repository = repository.Parent;
    if (repository is not null)
    {
        var fixture = Path.Combine(repository.FullName, "fixtures", "HarmlessProbe", "bin", "Debug", "net8.0", "HarmlessProbe.exe");
        if (File.Exists(fixture))
        {
            using var harmless = new AppContainerRunner();
            var harmlessDone = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            harmless.StateChanged += () => { if (harmless.ToReport().State.StartsWith("Exited", StringComparison.Ordinal)) harmlessDone.TrySetResult(true); };
            await harmless.LaunchProgramAsync(fixture, "");
            await harmlessDone.Task.WaitAsync(TimeSpan.FromSeconds(20));
            Check(harmless.ToReport().State.StartsWith("Exited (code 0)", StringComparison.Ordinal), "harmless fixture can write to its AppContainer profile and run a child");
            Check(!harmless.ToReport().Events.Any(e => e.Type == "cleanup-warning"), "fixture AppContainer profile is removed after exit");
        }
    }

    if (Environment.GetEnvironmentVariable("PROCESSVAULT_BROWSER_SMOKE") == "1")
    {
        using var browser = new AppContainerRunner();
        await browser.LaunchWebsiteAsync("https://example.org");
        await Task.Delay(TimeSpan.FromSeconds(3));
        Check(browser.IsRunning, "Edge starts inside the internetClient AppContainer");
        browser.Stop();
        await Task.Delay(500);
        Check(!browser.IsRunning, "website process tree stops with its AppContainer session");
    }
}

if (failures.Count != 0) { Console.Error.WriteLine($"{failures.Count} test(s) failed."); return 1; }
Console.WriteLine("All ProcessVault tests passed.");
return 0;
