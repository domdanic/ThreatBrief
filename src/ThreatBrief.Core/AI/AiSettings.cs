namespace ThreatBrief.Core.AI;

public static class AiProviders
{
    public const string None = "None";
    public const string OpenAiCompatible = "OpenAI Compatible";
    public const string Ollama = "Ollama";
}

public sealed record AiSettings
{
    public bool Enabled { get; init; }
    public bool DataSharingConsent { get; init; }
    public string Provider { get; init; } = AiProviders.None;
    public string Endpoint { get; init; } = "https://api.openai.com/v1";
    public string Model { get; init; } = "gpt-5.6-sol";
    public int RequestTimeoutSeconds { get; init; } = 90;
    public bool AutoStartLocalOllama { get; init; }
    public bool StopLocalOllamaOnExit { get; init; } = true;
    public string LocalOllamaPath { get; init; } = "..\\PortableOllama";
}
