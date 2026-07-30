using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using ThreatBrief.Application;
using ThreatBrief.Application.Refresh;
using ThreatBrief.Application.Nvd;
using ThreatBrief.Application.Connectors;
using ThreatBrief.Application.Maintenance;
using ThreatBrief.Application.Reports;
using ThreatBrief.Application.Updates;
using ThreatBrief.Core.Configuration;
using ThreatBrief.Core.Intelligence;
using ThreatBrief.Core.Models;
using ThreatBrief.Core.Watchlist;
using ThreatBrief.Core.Priority;
using ThreatBrief.Core.Triage;
using ThreatBrief.Data;

namespace ThreatBrief.Desktop;

public sealed partial class MainWindow : Window
{
    private readonly SqliteThreatRepository _repository;
    private readonly ThreatRefreshService _refreshService;
    private readonly SqliteIntelligenceRepository _intelligenceRepository;
    private readonly string _dataRoot;
    private ThreatRecord? _selected;
    private IntelligenceReport? _selectedReport;
    private WatchlistSettings _watchlist = new();
    private bool _loaded;
    private bool _settingTriage;

    public MainWindow()
    {
        InitializeComponent();
        var appRoot = ThreatBriefRuntime.FindAppRoot();
        var paths = ThreatBriefRuntime.GetDataPaths(appRoot);
        paths.EnsureCreated();
        _dataRoot = paths.Root;
        _repository = new SqliteThreatRepository(paths.DatabasePath);
        _intelligenceRepository = new SqliteIntelligenceRepository(paths.DatabasePath);
        _refreshService = new ThreatRefreshService(_repository, appRoot, paths.Root);
        Opened += MainWindow_OnOpened;
    }

    private async void MainWindow_OnOpened(object? sender, EventArgs e)
    {
        _loaded = true;
        _watchlist = await WatchlistSettings.LoadOrCreateAsync(
            _dataRoot);
        await LoadSettingsControlsAsync();
        await LoadThreatsAsync();
        await LoadIntelligenceAsync();
        if (_watchlist.Updates.CheckOnStartup
            && !string.IsNullOrWhiteSpace(_watchlist.Updates.GitHubRepository))
        {
            await CheckForUpdatesAsync();
        }
    }

    private async Task LoadThreatsAsync()
    {
        try
        {
            var view = GetSelectedView();
            var days = int.TryParse(view, out var parsedDays) ? parsedDays : 0;
            var records = await _repository.QueryAsync(new ThreatQuery
            {
                SearchText = SearchBox.Text,
                UnreadOnly = UnreadOnlyBox.IsChecked == true,
                AddedWithinDays = days == 0 ? null : days,
                Limit = 2000
            });

            records = ApplyTriageView(records, view);
            var items = records.Select(record => new ThreatListItem(record, _watchlist));
            if (WatchlistOnlyBox.IsChecked == true)
            {
                items = items.Where(item => item.WatchlistMatches.Count > 0);
            }

            var materialized = items
                .OrderByDescending(item => item.Priority.Score)
                .ThenByDescending(item => item.RelevanceScore)
                .ThenByDescending(item => item.DateAdded)
                .ToList();
            ThreatList.ItemsSource = materialized;
            ResultsHeader.Text =
                $"{materialized.Count} threat{(materialized.Count == 1 ? string.Empty : "s")}";
            UnreadCountText.Text = $"{await _repository.CountUnreadAsync()} unread";
            await LoadDashboardAsync();
        }
        catch (Exception exception)
        {
            await ShowErrorAsync("Unable to load threat history", exception.Message);
        }
    }

    private async Task LoadDashboardAsync()
    {
        var all = await _repository.QueryAsync(new ThreatQuery { Limit = 5000 });
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var alerting = all.Where(record =>
            AlertPolicy.IsAlerting(record, _watchlist.AlertWindowDays)).ToArray();
        CriticalCountText.Text = alerting.Count(record =>
            ThreatPriorityScorer.Score(record, _watchlist).Tier == "CRITICAL").ToString();
        WatchlistCountText.Text = alerting.Count(record =>
            _watchlist.Match(record).Count > 0).ToString();
        AlertWindowText.Text = $"Alert window: {_watchlist.AlertWindowDays} days";
        DueSoonCountText.Text = all.Count(record =>
            TriageStates.IsActive(record.TriageStatus)
            &&
            DateOnly.TryParse(record.DueDate, out var due)
            && due >= today
            && due <= today.AddDays(7)).ToString();
        OverdueCountText.Text = all.Count(record =>
            TriageStates.IsActive(record.TriageStatus)
            && DateOnly.TryParse(record.DueDate, out var due)
            && due < today).ToString();

        var latestBySource = (await _repository.GetRefreshHistoryAsync(100))
            .GroupBy(refresh => refresh.Collector, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(refresh => refresh.Collector)
            .ToArray();
        SourceHealthText.Text = latestBySource.Length == 0
            ? "No successful refresh recorded"
            : string.Join("  |  ", latestBySource.Select(FormatSourceHealth));
    }

    private static string FormatSourceHealth(RefreshRecord refresh)
    {
        if (!DateTimeOffset.TryParse(refresh.RefreshedAt, out var refreshedAt))
        {
            return $"{refresh.Collector}: unknown";
        }

        var age = DateTimeOffset.UtcNow - refreshedAt;
        var ageText = age.TotalMinutes < 2
            ? "just now"
            : age.TotalHours < 1
                ? $"{Math.Floor(age.TotalMinutes)}m ago"
                : age.TotalHours < 24
                    ? $"{Math.Floor(age.TotalHours)}h ago"
                    : $"{Math.Floor(age.TotalDays)}d ago";
        return $"{refresh.Collector}: {(age.TotalHours > 24 ? "STALE" : "healthy")} ({ageText})";
    }

    private async void RefreshButton_OnClick(object? sender, RoutedEventArgs e)
    {
        SetBusy(true, "Refreshing CISA intelligence...");
        try
        {
            var outcome = await _refreshService.RefreshAsync();
            var community = await new CommunityConnectorService(
                    _intelligenceRepository,
                    _dataRoot)
                .RefreshAsync();
            StatusText.Text =
                $"Imported {outcome.Import.Added} new and {outcome.Import.Updated} changed records";
            CommunityStatusText.Text = string.Join(
                Environment.NewLine,
                community.Select(FormatConnectorResult));
            await LoadThreatsAsync();
            await LoadIntelligenceAsync();
        }
        catch (Exception exception)
        {
            await ShowErrorAsync("Refresh failed", exception.Message);
        }
        finally
        {
            SetBusy(false, string.Empty);
        }
    }

    private async Task LoadIntelligenceAsync()
    {
        var reports = await _intelligenceRepository.QueryReportsAsync(limit: 500);
        var reportItems = reports.Select(report => new ReportListItem(report)).ToList();
        ReportList.ItemsSource = reportItems;
        ReportsHeader.Text = $"{reportItems.Count} intelligence report(s)";

        var indicators = await _intelligenceRepository.QueryIndicatorsAsync(
            activeOnly: ActiveIndicatorsOnlyBox.IsChecked == true,
            limit: 5000);
        var indicatorItems = indicators.Select(indicator => new IndicatorListItem(indicator)).ToList();
        IndicatorList.ItemsSource = indicatorItems;
        IndicatorsHeader.Text =
            $"{indicatorItems.Count} {(ActiveIndicatorsOnlyBox.IsChecked == true ? "active " : string.Empty)}indicator(s)";
    }

    private void ReportList_OnSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        _selectedReport = (ReportList.SelectedItem as ReportListItem)?.Report;
        if (_selectedReport is null)
        {
            return;
        }

        ReportDetailTitle.Text = _selectedReport.Title;
        ReportDetailSource.Text =
            $"{_selectedReport.Source}  |  {_selectedReport.Author}  |  {_selectedReport.ModifiedAt ?? _selectedReport.PublishedAt}";
        ReportDetailDescription.Text = _selectedReport.Description;
        ReportDetailRelations.Text =
            $"Related CVEs: {(_selectedReport.CveIds.Count == 0 ? "None" : string.Join(", ", _selectedReport.CveIds))}" +
            Environment.NewLine +
            $"Indicators: {_selectedReport.IndicatorCount}";
    }

    private void OpenReportButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(_selectedReport?.SourceUrl))
        {
            OpenUrl(_selectedReport.SourceUrl);
        }
    }

    private async void IndicatorFilter_OnChanged(object? sender, RoutedEventArgs e)
    {
        if (_loaded)
        {
            await LoadIntelligenceAsync();
        }
    }

    private async Task LoadSettingsControlsAsync()
    {
        var secrets = await SecretSettings.LoadAsync(_dataRoot);
        OtxEnabledBox.IsChecked = _watchlist.Connectors.OtxEnabled;
        ThreatFoxEnabledBox.IsChecked = _watchlist.Connectors.ThreatFoxEnabled;
        OtxKeyBox.Text = secrets.OtxApiKey;
        AbuseKeyBox.Text = secrets.AbuseChAuthKey;
        AlertWindowBox.Value = _watchlist.AlertWindowDays;
        WatchlistTermsBox.Text = string.Join(Environment.NewLine, _watchlist.Terms);
        GitHubRepositoryBox.Text = _watchlist.Updates.GitHubRepository;
        CheckUpdatesBox.IsChecked = _watchlist.Updates.CheckOnStartup;
        VersionText.Text =
            $"ThreatBrief {Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "development"}";
    }

    private async void SaveSettingsButton_OnClick(object? sender, RoutedEventArgs e)
    {
        var settings = new WatchlistSettings
        {
            AlertWindowDays = (int)(AlertWindowBox.Value ?? 30),
            Terms = (WatchlistTermsBox.Text ?? string.Empty)
                .Split(
                    new[] { "\r\n", "\n" },
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            Connectors = new ConnectorSettings
            {
                OtxEnabled = OtxEnabledBox.IsChecked == true,
                ThreatFoxEnabled = ThreatFoxEnabledBox.IsChecked == true,
                OtxLookbackDays = _watchlist.Connectors.OtxLookbackDays,
                ThreatFoxLookbackDays = _watchlist.Connectors.ThreatFoxLookbackDays
            },
            Updates = new UpdateSettings
            {
                CheckOnStartup = CheckUpdatesBox.IsChecked == true,
                GitHubRepository = string.IsNullOrWhiteSpace(GitHubRepositoryBox.Text)
                    ? null
                    : GitHubRepositoryBox.Text.Trim(),
                Channel = "stable"
            }
        };
        var configDirectory = Path.Combine(_dataRoot, "config");
        Directory.CreateDirectory(configDirectory);
        await File.WriteAllTextAsync(
            Path.Combine(configDirectory, "watchlist.json"),
            JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
        await File.WriteAllTextAsync(
            Path.Combine(configDirectory, "secrets.local.json"),
            JsonSerializer.Serialize(
                new SecretSettings
                {
                    OtxApiKey = string.IsNullOrWhiteSpace(OtxKeyBox.Text) ? null : OtxKeyBox.Text,
                    AbuseChAuthKey =
                        string.IsNullOrWhiteSpace(AbuseKeyBox.Text) ? null : AbuseKeyBox.Text
                },
                new JsonSerializerOptions { WriteIndented = true }));
        _watchlist = settings;
        CommunityStatusText.Text = "Settings saved.";
        await LoadThreatsAsync();
    }

    private async void RefreshCommunityButton_OnClick(object? sender, RoutedEventArgs e)
    {
        SetBusy(true, "Refreshing OTX and ThreatFox...");
        try
        {
            var results = await new CommunityConnectorService(
                    _intelligenceRepository,
                    _dataRoot)
                .RefreshAsync();
            CommunityStatusText.Text = string.Join(
                Environment.NewLine,
                results.Select(FormatConnectorResult));
            await LoadIntelligenceAsync();
        }
        finally
        {
            SetBusy(false, string.Empty);
        }
    }

    private static string FormatConnectorResult(ConnectorRefreshResult result) =>
        result.Enabled
            ? result.Succeeded
                ? $"{result.Source}: healthy ({result.Reports} reports, {result.Indicators} indicators)"
                : $"{result.Source}: failed - {result.Message}"
            : $"{result.Source}: disabled";

    private async void CheckUpdatesButton_OnClick(object? sender, RoutedEventArgs e) =>
        await CheckForUpdatesAsync();

    private async Task CheckForUpdatesAsync()
    {
        try
        {
            var result = await new GitHubUpdateService().CheckAsync(
                GitHubRepositoryBox.Text,
                "stable");
            UpdateStatusText.Text = result.Message;
            if (result.UpdateAvailable && result.ReleaseUrl is not null)
            {
                UpdateStatusText.Text += " Use the release page to download it.";
            }
        }
        catch (Exception exception)
        {
            UpdateStatusText.Text = $"Update check failed: {exception.Message}";
        }
    }

    private async void GenerateBriefingButton_OnClick(object? sender, RoutedEventArgs e)
    {
        var result = await new DailyBriefingService(
                _repository,
                _intelligenceRepository,
                _dataRoot)
            .GenerateAsync();
        MaintenanceStatusText.Text =
            $"Briefing written to {Path.GetDirectoryName(result.MarkdownPath)}";
    }

    private async void CreateBackupButton_OnClick(object? sender, RoutedEventArgs e)
    {
        var path = await new PortableBackupService(_dataRoot).CreateBackupAsync();
        MaintenanceStatusText.Text = $"Backup created: {path}";
    }

    private async void RestoreBackupButton_OnClick(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(
            new FilePickerOpenOptions
            {
                Title = "Restore ThreatBrief backup",
                AllowMultiple = false,
                FileTypeFilter =
                [
                    new FilePickerFileType("ThreatBrief backup")
                    {
                        Patterns = ["*.zip"]
                    }
                ]
            });
        if (files.Count == 0)
        {
            return;
        }

        var backupPath = files[0].TryGetLocalPath();
        if (string.IsNullOrWhiteSpace(backupPath)
            || !await ConfirmAsync(
                "Restore this backup?",
                "Current data and settings will be replaced. A safety backup will be created first. API keys are never restored."))
        {
            return;
        }

        try
        {
            SetBusy(true, "Restoring backup...");
            var result = await new PortableBackupService(_dataRoot)
                .RestoreBackupAsync(backupPath);
            _watchlist = await WatchlistSettings.LoadOrCreateAsync(_dataRoot);
            await LoadSettingsControlsAsync();
            await LoadThreatsAsync();
            await LoadIntelligenceAsync();
            MaintenanceStatusText.Text =
                $"Restore complete. Pre-restore safety backup: {result.SafetyBackupPath}";
        }
        catch (Exception exception)
        {
            MaintenanceStatusText.Text = $"Restore failed: {exception.Message}";
        }
        finally
        {
            SetBusy(false, string.Empty);
        }
    }

    private async void SearchBox_OnKeyUp(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            await LoadThreatsAsync();
        }
    }

    private async void Filter_OnChanged(object? sender, RoutedEventArgs e)
    {
        if (_loaded)
        {
            await LoadThreatsAsync();
        }
    }

    private void ThreatList_OnSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        _selected = (ThreatList.SelectedItem as ThreatListItem)?.Record;
        ShowSelectedThreat();
    }

    private void ShowSelectedThreat()
    {
        EmptyDetailText.IsVisible = _selected is null;
        SelectedDetail.IsVisible = _selected is not null;
        if (_selected is null)
        {
            return;
        }

        DetailId.Text = _selected.Id;
        DetailTitle.Text = _selected.Title;
        DetailVendorProduct.Text = $"{_selected.Vendor} / {_selected.Product}";
        DetailDateAdded.Text = _selected.DateAdded;
        DetailDueDate.Text = _selected.DueDate;
        DetailDescription.Text = _selected.Description;
        DetailAction.Text = _selected.RecommendedAction;
        DetailRansomware.Text =
            $"Known ransomware association: {(_selected.RansomwareAssociated ? "Yes" : _selected.RansomwareStatus ?? "Unknown")}";
        DetailRansomware.Foreground = _selected.RansomwareAssociated
            ? Avalonia.Media.Brushes.OrangeRed
            : Avalonia.Media.Brushes.LightGray;
        DetailSource.Text = $"Source: {_selected.Source} - {_selected.SourceUrl}";
        var sourceNames = _selected.Sources.Count == 0
            ? _selected.Source ?? "Unknown"
            : string.Join(", ", _selected.Sources);
        DetailSource.Text = $"Correlated sources ({_selected.SourceCount}): {sourceNames}";
        DetailSeverity.Text = _selected.Cvss is null
            ? _selected.Severity ?? "Awaiting NVD"
            : $"{_selected.Severity ?? "CVSS"} {_selected.Cvss:0.0}";
        DetailAttack.Text = string.Join(
            " / ",
            new[]
            {
                _selected.AttackVector,
                _selected.AttackComplexity,
                _selected.UserInteraction is null ? null : $"UI {_selected.UserInteraction}"
            }.Where(value => !string.IsNullOrWhiteSpace(value)));
        var matches = _watchlist.Match(_selected);
        DetailRelevance.Text = matches.Count == 0
            ? "No watchlist match"
            : string.Join(", ", matches);
        EnrichButton.Content = _selected.NvdEnrichedAt is null
            ? "Enrich from NVD"
            : "Refresh NVD data";
        var priority = ThreatPriorityScorer.Score(_selected, _watchlist);
        DetailPriority.Text = $"{priority.Tier} PRIORITY - {priority.Score}/100";
        DetailPriorityReasons.Text = string.Join(
            Environment.NewLine,
            priority.Reasons.Select(reason => $"- {reason}"));
        _settingTriage = true;
        TriageStatusBox.SelectedItem = TriageStatusBox.Items
            .OfType<ComboBoxItem>()
            .FirstOrDefault(item => string.Equals(
                item.Content?.ToString(),
                _selected.TriageStatus,
                StringComparison.Ordinal));
        _settingTriage = false;
        ReadButton.Content = _selected.IsRead ? "Mark unread" : "Mark read";
        SaveButton.Content = _selected.IsSaved ? "Unsave" : "Save";
    }

    private async void TriageStatusBox_OnSelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_settingTriage
            || _selected is null
            || TriageStatusBox.SelectedItem is not ComboBoxItem item
            || item.Content is not string status)
        {
            return;
        }

        await _repository.SetTriageStatusAsync(_selected.Id, status);
        _selected = await _repository.GetAsync(_selected.Id);
        await LoadDashboardAsync();
    }

    private async void HandledButton_OnClick(object? sender, RoutedEventArgs e) =>
        await SetSelectedStatusAsync(TriageStates.Handled);

    private async void NotApplicableButton_OnClick(object? sender, RoutedEventArgs e) =>
        await SetSelectedStatusAsync(TriageStates.NotApplicable);

    private async void IgnoreButton_OnClick(object? sender, RoutedEventArgs e) =>
        await SetSelectedStatusAsync(TriageStates.Ignored);

    private async Task SetSelectedStatusAsync(string status)
    {
        if (_selected is null)
        {
            return;
        }

        await _repository.SetTriageStatusAsync(_selected.Id, status);
        var id = _selected.Id;
        await LoadThreatsAsync();
        await ReselectAsync(id);
    }

    private async void ApplyBulkStatusButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (BulkStatusBox.SelectedItem is not ComboBoxItem { Content: string status }
            || ThreatList.ItemsSource is not IEnumerable<ThreatListItem> visibleItems)
        {
            return;
        }

        var ids = visibleItems.Select(item => item.Id).Distinct().ToArray();
        if (ids.Length == 0
            || !await ConfirmAsync(
                "Apply bulk disposition?",
                $"Set {ids.Length} visible threat(s) to '{status}'? This can be changed later."))
        {
            return;
        }

        SetBusy(true, $"Updating {ids.Length} threats...");
        try
        {
            await _repository.SetTriageStatusesAsync(ids, status);
            await LoadThreatsAsync();
        }
        finally
        {
            SetBusy(false, string.Empty);
        }
    }

    private async void EnrichButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (_selected is null)
        {
            return;
        }

        SetBusy(true, $"Enriching {_selected.Id} from NVD...");
        try
        {
            await new NvdEnrichmentService(_repository).EnrichAsync([_selected.Id]);
            await ReselectAsync(_selected.Id);
        }
        catch (Exception exception)
        {
            await ShowErrorAsync("NVD enrichment failed", exception.Message);
        }
        finally
        {
            SetBusy(false, string.Empty);
        }
    }

    private async void ReadButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (_selected is null)
        {
            return;
        }

        await _repository.SetReadAsync(_selected.Id, !_selected.IsRead);
        var selectedId = _selected.Id;
        await LoadThreatsAsync();
        await ReselectAsync(selectedId);
    }

    private async void MarkAllReadButton_OnClick(object? sender, RoutedEventArgs e)
    {
        await _repository.SetAllReadAsync();
        await LoadThreatsAsync();
    }

    private void OpenCisaButton_OnClick(object? sender, RoutedEventArgs e) =>
        OpenUrl("https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

    private void OpenNvdButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (_selected is not null)
        {
            OpenUrl($"https://nvd.nist.gov/vuln/detail/{Uri.EscapeDataString(_selected.Id)}");
        }
    }

    private static void OpenUrl(string url) =>
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });

    private async void SaveButton_OnClick(object? sender, RoutedEventArgs e)
    {
        if (_selected is null)
        {
            return;
        }

        await _repository.SetSavedAsync(_selected.Id, !_selected.IsSaved);
        await ReselectAsync(_selected.Id);
    }

    private async Task ReselectAsync(string id)
    {
        _selected = await _repository.GetAsync(id);
        if (_selected is not null)
        {
            ShowSelectedThreat();
        }
    }

    private string GetSelectedView() =>
        RangeBox.SelectedItem is ComboBoxItem { Tag: string value } ? value : "7";

    private static IReadOnlyList<ThreatRecord> ApplyTriageView(
        IReadOnlyList<ThreatRecord> records,
        string view)
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        return view switch
        {
            "inbox" => records.Where(record =>
                !TriageStates.IsTerminal(record.TriageStatus)
                && (!record.IsRead || TriageStates.IsActive(record.TriageStatus))).ToArray(),
            "due" => records.Where(record =>
                TriageStates.IsActive(record.TriageStatus)
                &&
                DateOnly.TryParse(record.DueDate, out var due)
                && due >= today
                && due <= today.AddDays(7)).ToArray(),
            "overdue" => records.Where(record =>
                TriageStates.IsActive(record.TriageStatus)
                && DateOnly.TryParse(record.DueDate, out var due)
                && due < today).ToArray(),
            "ransomware" => records.Where(record => record.RansomwareAssociated).ToArray(),
            "saved" => records.Where(record => record.IsSaved).ToArray(),
            _ => records
        };
    }

    private void SetBusy(bool busy, string message)
    {
        StatusOverlay.IsVisible = busy;
        StatusText.Text = message;
        RefreshButton.IsEnabled = !busy;
    }

    private async Task ShowErrorAsync(string title, string message)
    {
        var dialog = new Window
        {
            Title = title,
            Width = 520,
            Height = 220,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = new StackPanel
            {
                Margin = new Avalonia.Thickness(22),
                Spacing = 18,
                Children =
                {
                    new TextBlock
                    {
                        Text = title,
                        FontSize = 20,
                        FontWeight = Avalonia.Media.FontWeight.Bold
                    },
                    new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap },
                    new Button
                    {
                        Content = "Close",
                        HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right
                    }
                }
            }
        };

        if (dialog.Content is StackPanel panel && panel.Children[^1] is Button close)
        {
            close.Click += (_, _) => dialog.Close();
        }

        await dialog.ShowDialog(this);
    }

    private async Task<bool> ConfirmAsync(string title, string message)
    {
        var result = false;
        var dialog = new Window
        {
            Title = title,
            Width = 500,
            Height = 210,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        };
        var cancel = new Button { Content = "Cancel" };
        var confirm = new Button { Content = "Apply", Classes = { "primary" } };
        cancel.Click += (_, _) => dialog.Close();
        confirm.Click += (_, _) =>
        {
            result = true;
            dialog.Close();
        };
        dialog.Content = new StackPanel
        {
            Margin = new Avalonia.Thickness(22),
            Spacing = 18,
            Children =
            {
                new TextBlock
                {
                    Text = title,
                    FontSize = 20,
                    FontWeight = Avalonia.Media.FontWeight.Bold
                },
                new TextBlock { Text = message, TextWrapping = Avalonia.Media.TextWrapping.Wrap },
                new StackPanel
                {
                    Orientation = Avalonia.Layout.Orientation.Horizontal,
                    HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
                    Spacing = 8,
                    Children = { cancel, confirm }
                }
            }
        };
        await dialog.ShowDialog(this);
        return result;
    }
}
