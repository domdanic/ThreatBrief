# ThreatBrief

[![CI](https://github.com/domdanic/ThreatBrief/actions/workflows/ci.yml/badge.svg)](https://github.com/domdanic/ThreatBrief/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

ThreatBrief is a portable defensive threat-intelligence collector, reader, and
triage desk. It combines CISA KEV and NVD vulnerability intelligence with
optional AlienVault OTX and abuse.ch ThreatFox community feeds, correlates
duplicate CVEs and indicators, and retains the history locally in SQLite.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- Internet access for live refreshes

The launcher prefers PowerShell 7 (`pwsh.exe`) and falls back to Windows
PowerShell (`powershell.exe`) when PowerShell 7 is unavailable.

## License

ThreatBrief is released under the [MIT License](LICENSE). It may be used,
modified, and distributed for personal or commercial purposes. The software is
provided without warranty; see the license text for the complete terms.

## Run

From Explorer or Command Prompt:

```text
ThreatBrief.cmd
```

From PowerShell:

```powershell
.\Invoke-ThreatBrief.ps1
```

Useful options:

```powershell
# Use a local catalog instead of the network (also useful for testing)
.\Invoke-ThreatBrief.ps1 -CatalogPath .\tests\fixtures\cisa-kev-v1.json

# Store generated data somewhere else
.\Invoke-ThreatBrief.ps1 -DataPath C:\ThreatBriefData

# Include entries CISA added during the last 14 days in the readable report
.\Invoke-ThreatBrief.ps1 -RecentDays 14
```

Generated files are placed under `data/` by default:

- `state/cisa-kev-state.json` — previous catalog state
- `normalized/cisa-kev-latest.json` — normalized current catalog
- `reports/ThreatBrief-Latest.json` — machine-readable refresh result
- `reports/ThreatBrief-Latest.md` — human-readable briefing

The first refresh establishes a baseline. Later refreshes identify newly added
and changed KEV records. Every report also includes full readable details for
entries CISA added during a rolling seven-day window. Use `-RecentDays` to
change that window.

## Test

The tests have no external dependencies and do not use the live network:

```powershell
.\tests\Run-Tests.ps1
dotnet run --project .\tests\ThreatBrief.Data.Tests\ThreatBrief.Data.Tests.csproj
```

## SQLite history

The C# service layer stores the full normalized catalog, refresh history,
read/unread state, and saved items in `data/threatbrief.db`.

During development, import the latest PowerShell output with:

```powershell
dotnet run --project .\src\ThreatBrief.Cli -- `
  import .\data\normalized\cisa-kev-latest.json `
  --data-path .\data
```

Example history queries:

```powershell
# Recent records
dotnet run --project .\src\ThreatBrief.Cli -- list --days 7 --data-path .\data

# Search the full catalog
dotnet run --project .\src\ThreatBrief.Cli -- list --search Microsoft --data-path .\data

# Read/unread and saved state
dotnet run --project .\src\ThreatBrief.Cli -- read CVE-2026-12345 --data-path .\data
dotnet run --project .\src\ThreatBrief.Cli -- save CVE-2026-12345 --data-path .\data
```

## Portable operation

The release build will be self-contained and keep its writable `data` directory
beside the application. The complete folder can be moved between Windows
computers on a writable thumb drive without installation, administrator access,
registry entries, or a separately installed .NET runtime.

SQLite uses rollback journaling and ThreatBrief disables connection pooling so
the database file is released promptly after operations. Always close
ThreatBrief before unplugging the drive.

## Desktop application

During development:

```powershell
dotnet run --project .\src\ThreatBrief.Desktop
```

The desktop dashboard provides:

- One-click CISA refresh and automatic SQLite import
- Daily counts for critical priority, watchlist matches, due-soon, and overdue items
- CISA and NVD source-health timestamps with stale-data warnings
- 24-hour, 7-day, 30-day, and full-history views
- Inbox, due-soon, overdue, ransomware, saved, and all-history triage views
- CVE, vendor, product, and description search
- Unread filtering and persistent read/unread state
- Mark-all-read workflow
- Saved items
- A readable threat detail and required-action panel
- Direct CISA catalog and NVD record links
- Canonical reports and indicators with cross-source deduplication
- Daily briefing export in Markdown, HTML, and JSON
- Portable backup and safety-checked restore
- Opt-in GitHub release checks with no silent installation
- Prominent notifications and verified portable download-and-restart updates
- Optional AI-assisted threat explanations through OpenAI-compatible or Ollama endpoints

Create a self-contained Windows build with:

```powershell
dotnet publish .\src\ThreatBrief.Desktop `
  --configuration Release `
  --runtime win-x64 `
  --self-contained true `
  --output .\dist\ThreatBrief-win-x64
```

Or run `.\build\Publish-Portable.ps1`. The resulting versioned folder under
`dist\` is the portable application.

### NVD enrichment and watchlist

ThreatBrief enriches recent KEVs with CVSS severity, attack vector and
complexity, privileges, user interaction, CWE, references, and affected-product
data from the NVD API. Enrichment is cached for 24 hours and requests up to 100
CVE IDs at once to respect the public API limits. An optional API key can be
provided through the `NVD_API_KEY` environment variable.

The portable watchlist and alert window are stored in
`data\config\watchlist.json`. Edit `AlertWindowDays` (30 by default) and the
`Terms` array to match your environment. Watchlist matches are ranked first and
can be filtered in the desktop app.

Critical-priority and watchlist dashboard counts only include non-terminal
records inside the alert window. Old historical records naturally fall off;
Handled, Not Applicable, Ignored, Resolved, and Dismissed records disappear
immediately. Explicitly active work remains visible in due-soon and overdue
views until dispositioned.

This product uses data from the NVD API but is not endorsed or certified by the
NVD.

### Correlation and triage

ThreatBrief stores one canonical threat per CVE ID. Each collector writes a
separate source observation, so CISA, NVD, Microsoft, and future feeds enrich
the same threat instead of creating duplicate list entries.

The desktop app calculates an explainable operational priority from active
exploitation, ransomware association, watchlist matches, CVSS, remediation
deadlines, attack vector, required privileges, and user interaction. Priority
does not replace CVSS; it answers how urgently the record deserves attention in
the configured environment.

Triage states are portable and persistent:

- New
- Reviewing
- Action Required
- Handled
- Not Applicable
- Ignored
- Resolved
- Backlog
- Dismissed

Historical baseline records use `Backlog` and do not count as operationally
overdue. Due-soon and overdue views only include active `New`, `Reviewing`, and
`Action Required` records. Items can be dispositioned individually with quick
buttons or in bulk for the currently visible filtered results. Bulk changes
require confirmation and remain reversible.

### Microsoft Defender Threat Intelligence

The Microsoft Graph Defender Threat Intelligence API is a planned correlated
source. Microsoft currently requires an active Defender Threat Intelligence
Portal license, the API add-on license, Microsoft Entra authentication, and the
`ThreatIntelligence.Read.All` permission. Tenant credentials are intentionally
not stored until that licensed connector is configured.

### Community intelligence connectors

OTX and ThreatFox are disabled until explicitly enabled under
**Sources & Settings**. OTX requires an OTX API key. ThreatFox requires a free
abuse.ch Auth-Key. Keys can be entered in the app, stored beside the portable
database in `data\config\secrets.local.json`, or supplied through
`OTX_API_KEY` and `ABUSECH_AUTH_KEY` environment variables. Environment
variables take precedence.

The local secrets file is intentionally excluded from backups and should never
be committed or shared. MISP and OpenCTI are suitable future integration
targets for organizations that already operate those platforms; they are not
required for the standalone v1 application.

### Updates

ThreatBrief checks
[domdanic/ThreatBrief releases](https://github.com/domdanic/ThreatBrief/releases)
at startup by default. Available updates appear in a persistent banner with
options to view the release, dismiss that version, or explicitly
**Download and restart**.

Automatic portable updates require both a versioned ZIP and its matching
`.sha256` release asset. ThreatBrief downloads both from HTTPS GitHub release
URLs, caps download size, verifies SHA-256, validates archive paths, creates a
safety backup, and stages the release before closing. A separate PowerShell 5.1
helper preserves the complete `data` directory, replaces application files,
restarts ThreatBrief, and restores the prior files if replacement or initial
startup fails. Updates are never downloaded or applied silently.

### Optional AI assistance

ThreatBrief 1.1 adds AI capability to the standard application, disabled by
default. ThreatBrief never contacts an AI endpoint until the user enables AI,
chooses a provider, and explicitly consents to sending the selected normalized
threat record to that endpoint.

Supported provider modes:

- **OpenAI Compatible** — defaults to `https://api.openai.com/v1`; the endpoint
  and model are configurable for compatible services.
- **Ollama** — connects to a local Ollama service, normally at
  `http://localhost:11434`. ThreatBrief does not bundle Ollama or a model in its
  standard download. When a standalone portable Ollama bundle is available,
  ThreatBrief can start it automatically and stop only the process it started.
- **None** — the default; no AI network activity occurs.

The first AI workflow is **Explain this threat**. It produces a structured
summary, organizational impact, exploitation path, recommended actions,
caveats, and confidence. Feed descriptions are delimited and treated as
untrusted data. The model receives no command, browser, filesystem, triage,
merge, or deletion tools.

Every accepted result is cached and audited in the portable SQLite database
with its threat ID, input fingerprint, provider, model, and generation time.
Unchanged records reuse the cached result unless **Regenerate** is selected.

The API key can be entered under **AI Assistance** or supplied with
`THREATBRIEF_AI_API_KEY`. `OPENAI_API_KEY` is also recognized. Environment
variables take precedence. Portable keys are stored in
`data\config\secrets.local.json`, which is excluded from Git and backups.
OpenAI-compatible Responses API requests set `store` to `false`.

For portable Ollama, enable **Automatically start portable Ollama with
ThreatBrief**, leave **Stop it when ThreatBrief exits** selected, and enter the
bundle folder. Relative paths are resolved from the ThreatBrief folder; the
default `..\PortableOllama` finds sibling ThreatBrief and PortableOllama folders.
The folder picker stores a relative path when both folders are on the same
drive, preserving portability. Standard Ollama installation folders containing
`ollama.exe` are also supported. Use **Detect models** to populate the installed
model list from the configured Ollama endpoint. Manual model entry remains
available. Ollama requests default to a five-minute timeout, adjustable from
30 seconds to one hour under **AI Assistance** for slower hardware and cold
model loads. Automatic process control is restricted to localhost endpoints.

## Architecture

```text
CISA KEV / NVD / OTX / ThreatFox
        |
Source-specific collectors
        |
Canonical CVEs, reports, and indicators
        |
C# services + SQLite
        |
Avalonia desktop UI + portable exports/backups
```
