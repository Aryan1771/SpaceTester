using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ProcessVault.Core;

public sealed record LaunchRecord(
    string Id,
    DateTimeOffset StartedAt,
    DateTimeOffset? EndedAt,
    string Kind,
    string TargetName,
    int? ProcessId,
    string? Sha256,
    string State,
    IReadOnlyList<TestEvent> Events);

public sealed record TestEvent(DateTimeOffset At, string Type, string Message, string Evidence = "Host observed");

public sealed record ProcessSnapshot(int ProcessId, int? ParentProcessId, string Name, string? Path, long MemoryBytes, TimeSpan CpuTime, bool IsResponding);

public static class LaunchValidation
{
    public static Uri ValidateWebAddress(string input)
    {
        if (!Uri.TryCreate(input.Trim(), UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrEmpty(uri.UserInfo))
            throw new ArgumentException("Enter a complete HTTP or HTTPS address without embedded credentials.");
        return uri;
    }

    public static string NormalizeExecutable(string path)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new FileNotFoundException("Selected program does not exist.", full);
        if (!string.Equals(Path.GetExtension(full), ".exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Choose a Windows .exe program.");
        return full;
    }

    public static IReadOnlyList<string> ParseWindowsArguments(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return [];
        var ptr = CommandLineToArgvW(commandLine, out var count);
        if (ptr == IntPtr.Zero) throw new ArgumentException("Arguments could not be parsed.");
        try
        {
            var args = new string[count];
            for (var i = 0; i < count; i++)
                args[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(ptr, i * IntPtr.Size)) ?? "";
            return args;
        }
        finally { LocalFree(ptr); }
    }

    public static string RedactAddress(Uri uri) => uri.GetLeftPart(UriPartial.Authority);

    [DllImport("shell32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int argumentCount);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
}

public static class ProcessInventory
{
    private const uint SnapshotProcess = 0x00000002;

    public static IReadOnlyList<ProcessSnapshot> Read()
    {
        var parents = ReadParentMap();
        var output = new List<ProcessSnapshot>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    output.Add(new ProcessSnapshot(process.Id, parents.GetValueOrDefault(process.Id), process.ProcessName,
                        TryGetPath(process), process.WorkingSet64, process.TotalProcessorTime, TryResponding(process)));
                }
                catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException or UnauthorizedAccessException)
                {
                    try { output.Add(new ProcessSnapshot(process.Id, parents.GetValueOrDefault(process.Id), process.ProcessName, null, 0, TimeSpan.Zero, false)); }
                    catch { }
                }
            }
        }
        return output.OrderByDescending(p => p.MemoryBytes).ToArray();
    }

    private static string? TryGetPath(Process process)
    {
        try { return process.MainModule?.FileName; }
        catch { return null; }
    }

    private static bool TryResponding(Process process)
    {
        try { return process.Responding; }
        catch { return false; }
    }

    private static Dictionary<int, int?> ReadParentMap()
    {
        var result = new Dictionary<int, int?>();
        using var snapshot = CreateToolhelp32Snapshot(SnapshotProcess, 0);
        if (snapshot.IsInvalid) return result;
        var entry = new PROCESSENTRY32 { Size = (uint)Marshal.SizeOf<PROCESSENTRY32>() };
        if (!Process32First(snapshot, ref entry)) return result;
        do
        {
            result[unchecked((int)entry.ProcessId)] = unchecked((int)entry.ParentProcessId);
            entry.Size = (uint)Marshal.SizeOf<PROCESSENTRY32>();
        } while (Process32Next(snapshot, ref entry));
        return result;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public uint Size, Usage, ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId, Threads, ParentProcessId;
        public int BasePriority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string ExeFile;
    }
    [DllImport("kernel32.dll", SetLastError = true)] private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool Process32First(Microsoft.Win32.SafeHandles.SafeFileHandle snapshot, ref PROCESSENTRY32 entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool Process32Next(Microsoft.Win32.SafeHandles.SafeFileHandle snapshot, ref PROCESSENTRY32 entry);
}
