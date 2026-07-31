using System.Text;
using System.Text.Json;
using ThreatBrief.Core.AI;
using ThreatBrief.Core.Models;

namespace ThreatBrief.Application.AI;

public sealed class OllamaProvider : IAiProvider
{
    private readonly string _endpoint;
    private readonly string _model;
    private readonly HttpClient _httpClient;

    public OllamaProvider(
        string endpoint,
        string model,
        HttpClient? httpClient = null,
        int timeoutSeconds = 90)
    {
        _endpoint = endpoint.TrimEnd('/');
        _model = model;
        _httpClient = httpClient ?? new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 30, 3600))
        };
    }

    public string Name => AiProviders.Ollama;

    public async Task<string> TestConnectionAsync(
        CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.GetAsync(
            $"{_endpoint}/api/tags",
            cancellationToken);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            cancellationToken: cancellationToken);
        var found = document.RootElement.TryGetProperty("models", out var models)
            && models.EnumerateArray().Any(item =>
                item.TryGetProperty("name", out var name)
                && string.Equals(
                    name.GetString(),
                    _model,
                    StringComparison.OrdinalIgnoreCase));
        return found
            ? $"Connected to Ollama; {_model} is installed."
            : $"Connected to Ollama, but {_model} was not found. Pull it before analysis.";
    }

    public async Task<ThreatAnalysis> AnalyzeThreatAsync(
        ThreatRecord threat,
        IReadOnlyList<string> watchlistMatches,
        CancellationToken cancellationToken = default)
    {
        var body = new
        {
            model = _model,
            stream = false,
            format = AiPrompt.JsonSchema,
            options = new { temperature = 0 },
            messages = new[]
            {
                new { role = "system", content = AiPrompt.Instructions },
                new { role = "user", content = AiPrompt.CreateInput(threat, watchlistMatches) }
            }
        };
        using var response = await _httpClient.PostAsync(
            $"{_endpoint}/api/chat",
            new StringContent(
                JsonSerializer.Serialize(body),
                Encoding.UTF8,
                "application/json"),
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var detail = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new HttpRequestException(
                $"Ollama returned {(int)response.StatusCode}: "
                + (detail.Length > 500 ? detail[..500] : detail));
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            cancellationToken: cancellationToken);
        var content = document.RootElement.GetProperty("message").GetProperty("content").GetString();
        return OpenAiCompatibleProvider.DeserializeAnalysis(content);
    }
}
