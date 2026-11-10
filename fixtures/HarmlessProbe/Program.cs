using System.Diagnostics;
using System.Net.Http;

if (args.Contains("--child", StringComparer.Ordinal))
{
    Console.WriteLine($"Child fixture process running as PID {Environment.ProcessId}.");
    await Task.Delay(1500);
    return 7;
}

if (args.Contains("--probe-network", StringComparer.Ordinal))
{
    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
    using var response = await client.GetAsync("https://example.org");
    Console.WriteLine($"AppContainer network probe received HTTP {(int)response.StatusCode}.");
    return response.IsSuccessStatusCode ? 0 : 1;
}

var hostAccessIndex = Array.FindIndex(args, arg => arg.Equals("--probe-host-access", StringComparison.Ordinal));
if (hostAccessIndex >= 0 && hostAccessIndex + 1 < args.Length)
{
    var hostFile = args[hostAccessIndex + 1];
    var canRead = true;
    var canWrite = true;
    try { _ = await File.ReadAllTextAsync(hostFile); }
    catch (UnauthorizedAccessException) { canRead = false; }
    try { await File.WriteAllTextAsync(hostFile, "modified by AppContainer probe"); }
    catch (UnauthorizedAccessException) { canWrite = false; }
    Console.WriteLine($"Host file access: read={canRead}, write={canWrite}.");
    return !canRead && !canWrite ? 0 : 1;
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
