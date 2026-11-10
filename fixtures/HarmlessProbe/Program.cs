using System.Diagnostics;

if (args.Contains("--child", StringComparer.Ordinal))
{
    Console.WriteLine($"Child fixture process running as PID {Environment.ProcessId}.");
    await Task.Delay(1500);
    return 7;
}

var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ProcessVaultFixture", Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
var marker = Path.Combine(root, "fixture-event.txt");
await File.WriteAllTextAsync(marker, $"Harmless ProcessVault demonstration. Created {DateTimeOffset.UtcNow:O}. PID {Environment.ProcessId}.\n");
Console.WriteLine($"Created a harmless marker under the current LocalAppData: {marker}");

var self = Environment.ProcessPath ?? throw new InvalidOperationException("Could not resolve fixture executable.");
var childInfo = new ProcessStartInfo(self) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
childInfo.ArgumentList.Add("--child");
using var child = Process.Start(childInfo) ?? throw new InvalidOperationException("Could not start child fixture.");
var childOutput = await child.StandardOutput.ReadToEndAsync();
await child.WaitForExitAsync();
Console.Write(childOutput);
Console.WriteLine($"Child exited with code {child.ExitCode}. The process and file use the current execution context.");
Console.WriteLine("When launched by ProcessVault, AppContainer policy applies and its temporary profile is removed after the process tree exits.");
return 0;
