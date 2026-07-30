using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace ThreatBrief.Core.Intelligence;

public static class IndicatorNormalizer
{
    public static string Normalize(string type, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(type);
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        var trimmed = value.Trim();
        var normalizedType = type.Trim().ToLowerInvariant();

        if (normalizedType is "domain" or "hostname")
        {
            return trimmed.TrimEnd('.').ToLowerInvariant();
        }

        if (normalizedType is "ipv4" or "ipv6" or "ip")
        {
            return IPAddress.TryParse(trimmed, out var address)
                ? address.ToString().ToLowerInvariant()
                : trimmed.ToLowerInvariant();
        }

        if (normalizedType is "url" or "uri")
        {
            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
            {
                return trimmed;
            }

            var builder = new UriBuilder(uri)
            {
                Scheme = uri.Scheme.ToLowerInvariant(),
                Host = uri.Host.ToLowerInvariant(),
                Fragment = string.Empty
            };
            if ((builder.Scheme == "http" && builder.Port == 80)
                || (builder.Scheme == "https" && builder.Port == 443))
            {
                builder.Port = -1;
            }

            return builder.Uri.AbsoluteUri.TrimEnd('/');
        }

        if (normalizedType.Contains("hash", StringComparison.Ordinal)
            || normalizedType is "md5" or "sha1" or "sha256" or "sha512")
        {
            return trimmed.ToLowerInvariant();
        }

        return trimmed.ToLowerInvariant();
    }

    public static string CanonicalKey(string type, string value)
    {
        var normalizedType = type.Trim().ToLowerInvariant();
        var normalizedValue = Normalize(normalizedType, value);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{normalizedType}:{normalizedValue}"));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

