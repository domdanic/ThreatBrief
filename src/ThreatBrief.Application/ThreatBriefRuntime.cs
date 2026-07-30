using ThreatBrief.Core;

namespace ThreatBrief.Application;

public static class ThreatBriefRuntime
{
    public static string FindAppRoot(string? startPath = null)
    {
        var current = new DirectoryInfo(Path.GetFullPath(startPath ?? AppContext.BaseDirectory));
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Invoke-ThreatBrief.ps1")))
            {
                var binSegment = $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}";
                if (!current.FullName.Contains(binSegment, StringComparison.OrdinalIgnoreCase))
                {
                    return current.FullName;
                }
            }

            current = current.Parent;
        }

        return AppContext.BaseDirectory;
    }

    public static PortableDataPaths GetDataPaths(string appRoot)
    {
        var overridePath = Environment.GetEnvironmentVariable("THREATBRIEF_DATA_PATH");
        return PortableDataPaths.At(
            string.IsNullOrWhiteSpace(overridePath)
                ? Path.Combine(appRoot, "data")
                : overridePath);
    }
}
