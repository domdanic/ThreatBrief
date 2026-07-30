namespace ThreatBrief.Core.Triage;

public static class TriageStates
{
    public const string New = "New";
    public const string Reviewing = "Reviewing";
    public const string ActionRequired = "Action Required";
    public const string Handled = "Handled";
    public const string NotApplicable = "Not Applicable";
    public const string Ignored = "Ignored";
    public const string Backlog = "Backlog";
    public const string Resolved = "Resolved";
    public const string Dismissed = "Dismissed";

    public static IReadOnlyList<string> All { get; } =
    [
        New,
        Reviewing,
        ActionRequired,
        Handled,
        NotApplicable,
        Ignored,
        Backlog,
        Resolved,
        Dismissed
    ];

    public static bool IsActive(string? status) =>
        status is New or Reviewing or ActionRequired;

    public static bool IsTerminal(string? status) =>
        status is Handled or NotApplicable or Ignored or Resolved or Dismissed;
}

