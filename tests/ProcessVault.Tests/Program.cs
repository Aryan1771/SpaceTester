using ProcessVault.Core;
using System.Diagnostics;

if (args.Contains("--pv-probe", StringComparer.Ordinal))
{
    Console.WriteLine("ProcessVault benign launch probe.");
    return 3;
}

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

using (var runner = new HostTestRunner())
{
    var finished = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
    runner.StateChanged += () => { if (runner.ToReport().State.StartsWith("Exited", StringComparison.Ordinal)) finished.TrySetResult(true); };
    await runner.LaunchProgramAsync(Environment.ProcessPath!, "--pv-probe");
    await finished.Task.WaitAsync(TimeSpan.FromSeconds(10));
    await Task.Delay(150);
    Check(runner.ToReport().State == "Exited (code 3)", "launched process exit status is observed");
    Check(runner.ToReport().Events.Any(e => e.Type == "stdout" && e.Message.Contains("benign launch probe", StringComparison.Ordinal)), "launched process output is captured");
}

if (failures.Count != 0) { Console.Error.WriteLine($"{failures.Count} test(s) failed."); return 1; }
Console.WriteLine("All ProcessVault tests passed.");
return 0;
