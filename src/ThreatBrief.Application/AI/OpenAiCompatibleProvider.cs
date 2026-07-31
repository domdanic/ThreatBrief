using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using ThreatBrief.Core.AI;
using ThreatBrief.Core.Models;

namespace ThreatBrief.Application.AI;

public sealed class OpenAiCompatibleProvider : IAiProvider
{
    private readonly string _endpoint;
    private readonly string _model;
    private readonly string? _apiKey;
    private readonly HttpClient _httpClient;

    public OpenAiCompatibleProvider(
        string endpoint,
        string model,
        string? apiKey,
        HttpClient? httpClient = null,
        int timeoutSeconds = 90)
    {
        _endpoint = endpoint.TrimEnd('/');
        _model = model;
        _apiKey = apiKey;
        if (httpClient is null)
        {
            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 10, 600))
            };
        }
        else
        {
            _httpClient = httpClient;
        }
    }

    public string Name => AiProviders.OpenAiCompatible;

    public async Task<string> TestConnectionAsync(
        CancellationToken cancellationToken = default)
    {
        using var request = CreateRequest(HttpMethod.Get, $"{_endpoint}/models");
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
        return $"Connected to {_endpoint}; model configured as {_model}.";
    }

    public async Task<ThreatAnalysis> AnalyzeThreatAsync(
        ThreatRecord threat,
        IReadOnlyList<string> watchlistMatches,
        CancellationToken cancellationToken = default)
    {
        var body = new
        {
            model = _model,
            store = false,
            instructions = AiPrompt.Instructions,
            input = AiPrompt.CreateInput(threat, watchlistMatches),
            text = new
            {
                format = new
                {
                    type = "json_schema",
                    name = "threat_analysis",
                    strict = true,
                    schema = AiPrompt.JsonSchema
                }
            }
        };
        using var request = CreateRequest(HttpMethod.Post, $"{_endpoint}/responses");
        request.Content = new StringContent(
                JsonSerializer.Serialize(body),
                Encoding.UTF8,
                "application/json");
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var document = await JsonDocument.ParseAsync(
            stream,
            cancellationToken: cancellationToken);
        var outputText = document.RootElement
            .GetProperty("output")
            .EnumerateArray()
            .SelectMany(item => item.TryGetProperty("content", out var content)
                ? content.EnumerateArray().ToArray()
                : [])
            .FirstOrDefault(item =>
                item.TryGetProperty("type", out var type)
                && type.GetString() == "output_text");
        if (outputText.ValueKind == JsonValueKind.Undefined
            || !outputText.TryGetProperty("text", out var text))
        {
            throw new InvalidDataException("The AI provider returned no structured analysis.");
        }

        return DeserializeAnalysis(text.GetString());
    }

    internal static ThreatAnalysis DeserializeAnalysis(string? json) =>
        JsonSerializer.Deserialize<ThreatAnalysis>(
            json ?? string.Empty,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
        ?? throw new InvalidDataException("The AI provider returned invalid analysis JSON.");

    private HttpRequestMessage CreateRequest(HttpMethod method, string uri)
    {
        var request = new HttpRequestMessage(method, uri);
        if (!string.IsNullOrWhiteSpace(_apiKey))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
        }

        return request;
    }

    private static async Task EnsureSuccessAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var detail = await response.Content.ReadAsStringAsync(cancellationToken);
        throw new HttpRequestException(
            $"AI provider returned {(int)response.StatusCode}: "
            + (detail.Length > 500 ? detail[..500] : detail));
    }
}
