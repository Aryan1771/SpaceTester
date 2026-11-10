using System.Security;
using System.Text;

namespace ProcessVault.Core;

public static class SandboxConfigBuilder
{
    public static string Build(string hostFolder, bool networking)
    {
        var escaped = SecurityElement.Escape(Path.GetFullPath(hostFolder)) ?? throw new InvalidOperationException("Could not encode the staging path.");
        return "<Configuration>\r\n" +
               "  <VGpu>Disable</VGpu>\r\n  <Networking>" + (networking ? "Enable" : "Disable") + "</Networking>\r\n" +
               "  <AudioInput>Disable</AudioInput>\r\n  <VideoInput>Disable</VideoInput>\r\n" +
               "  <PrinterRedirection>Disable</PrinterRedirection>\r\n  <ClipboardRedirection>Disable</ClipboardRedirection>\r\n" +
               "  <ProtectedClient>Enable</ProtectedClient>\r\n  <MemoryInMB>4096</MemoryInMB>\r\n" +
               "  <MappedFolders><MappedFolder><HostFolder>" + escaped + "</HostFolder><SandboxFolder>C:\\ProcessVault</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder></MappedFolders>\r\n" +
               "  <LogonCommand><Command>powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\ProcessVault\\launch.ps1</Command></LogonCommand>\r\n" +
               "</Configuration>\r\n";
    }

    public static string BuildBrowserScript(Uri uri)
    {
        var address = "'" + uri.AbsoluteUri.Replace("'", "''", StringComparison.Ordinal) + "'";
        return "$ErrorActionPreference = 'Stop'\r\n" +
               "$edge = @('C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe') | Where-Object { Test-Path $_ } | Select-Object -First 1\r\n" +
               "if (-not $edge) { throw 'Microsoft Edge was not found in the Windows Sandbox guest.' }\r\n" +
               "$psi = New-Object System.Diagnostics.ProcessStartInfo\r\n$psi.FileName = $edge\r\n$psi.Arguments = '--inprivate --no-first-run --disable-sync ' + " + address + "\r\n" +
               "$p = [System.Diagnostics.Process]::Start($psi)\r\n$p.WaitForExit()\r\n";
    }
}
