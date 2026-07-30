using System.Text.Json;

namespace ThreatBrief.Core.Configuration;

public sealed record SecretSettings
{
    public string? OtxApiKey { get; init; }
    public string? AbuseChAuthKey { get; init; }

    public static async Task<SecretSettings> LoadAsync(
        string dataRoot,
        CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(dataRoot, "config", "secrets.local.json");
        var fromFile = File.Exists(path)
            ? JsonSerializer.Deserialize<SecretSettings>(
                  await File.ReadAllTextAsync(path, cancellationToken),
                  new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
              ?? new SecretSettings()
            : new SecretSettings();

        return fromFile with
        {
            OtxApiKey = Environment.GetEnvironmentVariable("OTX_API_KEY") ?? fromFile.OtxApiKey,
            AbuseChAuthKey =
                Environment.GetEnvironmentVariable("ABUSECH_AUTH_KEY") ?? fromFile.AbuseChAuthKey
        };
    }
}

