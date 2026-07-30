namespace ThreatBrief.Core;

public sealed record PortableDataPaths
{
    public required string Root { get; init; }
    public string DatabasePath => Path.Combine(Root, "threatbrief.db");
    public string ReportsPath => Path.Combine(Root, "reports");
    public string StatePath => Path.Combine(Root, "state");
    public string NormalizedPath => Path.Combine(Root, "normalized");

    public static PortableDataPaths BesideExecutable() =>
        At(Path.Combine(AppContext.BaseDirectory, "data"));

    public static PortableDataPaths At(string root)
    {
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new ArgumentException("A data directory is required.", nameof(root));
        }

        return new PortableDataPaths { Root = Path.GetFullPath(root) };
    }

    public void EnsureCreated()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(ReportsPath);
        Directory.CreateDirectory(StatePath);
        Directory.CreateDirectory(NormalizedPath);
    }
}

