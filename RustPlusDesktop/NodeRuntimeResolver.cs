// Services/NodeRuntimeResolver.cs
// Centralized resolver for finding the Node.js runtime (bundled or system-wide).
using System;
using System.Diagnostics;
using System.IO;

namespace RustPlusDesk.Services;

public static class NodeRuntimeResolver
{
    /// <summary>
    /// Finds the Node.js executable. Tries bundled runtime first, then system PATH.
    /// </summary>
    public static string? FindNode()
    {
        // 1) Release/Publish: next to the EXE
        var p1 = Path.Combine(AppContext.BaseDirectory, "runtime", "node-win-x64", "node.exe");
        if (File.Exists(p1)) return p1;

        // 2) Debug: directly from the project
        var p2 = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..",
                                               "runtime", "node-win-x64", "node.exe"));
        if (File.Exists(p2)) return p2;

        // 3) Fallback: system-wide Node.js on PATH
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "where",
                Arguments = "node",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p != null)
            {
                p.WaitForExit(3000);
                var output = p.StandardOutput.ReadToEnd().Trim();
                if (!string.IsNullOrEmpty(output))
                {
                    // 'where' can return multiple lines; take the first existing file
                    foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        var trimmed = line.Trim();
                        if (File.Exists(trimmed)) return trimmed;
                    }
                }
            }
        }
        catch { /* ignore */ }

        return null;
    }
}
