using System.Diagnostics;

namespace ThreatBrief.Application.AI;

public sealed class LocalOllamaLifecycleService : IDisposable
{
    private Process? _ownedProcess;

    public bool OwnsProcess => _ownedProcess is { HasExited: false };

    public static bool IsLocalEndpoint(string endpoint) =>
        Uri.TryCreate(endpoint, UriKind.Absolute, out var uri)
        && (uri.IsLoopback
            || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase));

    public static string ResolveBundlePath(string appRoot, string? configuredPath)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            candidates.Add(Path.IsPathRooted(configuredPath)
                ? configuredPath
                : Path.Combine(appRoot, configuredPath));
        }

        candidates.Add(Path.Combine(appRoot, "PortableOllama"));
        candidates.Add(Path.Combine(appRoot, "..", "PortableOllama"));
        candidates.Add(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Programs",
            "Ollama"));

        foreach (var candidate in candidates)
        {
            var fullPath = Path.GetFullPath(candidate);
            if (File.Exists(ResolveExecutablePath(fullPath)))
            {
                return fullPath;
            }
        }

        return Path.GetFullPath(candidates[0]);
    }

    public async Task<string> EnsureStartedAsync(
        string appRoot,
        string configuredPath,
        string endpoint,
        CancellationToken cancellationToken = default)
    {
        if (!IsLocalEndpoint(endpoint)
            || !Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException(
                "Automatic Ollama startup is restricted to localhost endpoints.");
        }

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        try
        {
            using var response = await client.GetAsync(
                new Uri(uri, "/api/version"),
                cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                return "Ollama is already running.";
            }
        }
        catch (HttpRequestException)
        {
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }

        var bundlePath = ResolveBundlePath(appRoot, configuredPath);
        var executable = ResolveExecutablePath(bundlePath);
        if (!File.Exists(executable))
        {
            throw new FileNotFoundException(
                $"Portable Ollama was not found at '{bundlePath}'.",
                executable);
        }

        var logs = Path.Combine(bundlePath, "logs");
        Directory.CreateDirectory(logs);
        var startInfo = new ProcessStartInfo(executable, "serve")
        {
            WorkingDirectory = Path.GetDirectoryName(executable)!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        var portableModels = Path.Combine(bundlePath, "models");
        if (Directory.Exists(portableModels))
        {
            startInfo.Environment["OLLAMA_MODELS"] = portableModels;
        }
        startInfo.Environment["OLLAMA_HOST"] = uri.Authority;
        startInfo.Environment["OLLAMA_KEEP_ALIVE"] = "5m";
        startInfo.Environment["OLLAMA_MAX_TRANSFER_STREAMS"] = "1";

        _ownedProcess = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Ollama could not be started.");
        _ = CopyOutputAsync(
            _ownedProcess.StandardOutput,
            Path.Combine(logs, "threatbrief.out.log"));
        _ = CopyOutputAsync(
            _ownedProcess.StandardError,
            Path.Combine(logs, "threatbrief.err.log"));

        var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_ownedProcess.HasExited)
            {
                throw new InvalidOperationException(
                    "Ollama exited during startup. Review logs\\threatbrief.err.log.");
            }

            try
            {
                using var response = await client.GetAsync(
                    new Uri(uri, "/api/version"),
                    cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    return "Portable Ollama started by ThreatBrief.";
                }
            }
            catch (HttpRequestException)
            {
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }

            await Task.Delay(500, cancellationToken);
        }

        StopOwnedProcess();
        throw new TimeoutException(
            "Ollama did not become ready within 30 seconds. Review its portable logs folder.");
    }

    public void StopOwnedProcess()
    {
        if (_ownedProcess is null)
        {
            return;
        }

        try
        {
            if (!_ownedProcess.HasExited)
            {
                _ownedProcess.Kill(entireProcessTree: true);
                _ownedProcess.WaitForExit(10_000);
            }
        }
        finally
        {
            _ownedProcess.Dispose();
            _ownedProcess = null;
        }
    }

    public void Dispose() => StopOwnedProcess();

    private static string ResolveExecutablePath(string root)
    {
        var rootExecutable = Path.Combine(root, "ollama.exe");
        return File.Exists(rootExecutable)
            ? rootExecutable
            : Path.Combine(root, "bin", "ollama.exe");
    }

    private static async Task CopyOutputAsync(StreamReader reader, string path)
    {
        await using var writer = new StreamWriter(path, append: true);
        while (await reader.ReadLineAsync() is { } line)
        {
            await writer.WriteLineAsync(line);
            await writer.FlushAsync();
        }
    }
}
