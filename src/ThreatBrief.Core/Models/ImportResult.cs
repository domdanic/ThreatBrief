namespace ThreatBrief.Core.Models;

public sealed record ImportResult(
    int Total,
    int Added,
    int Updated,
    int Unchanged,
    bool EstablishedBaseline);

