# Submission recording guide

This guide targets Windows PowerShell, Python 3.11+, Node 22 and the pinned release
`d855c4ece913775306295a8fec54254e7c2181d1`. Prepare before recording. All services
bind to `127.0.0.1`. Never run a second lab demo on the same fixed Node lab port.
No model call, external scan, deployment or publication is part of this guide.

The long-form launch recipe below is PowerShell. For the final CMD-only check,
use the actual command matrix and output tails in `tasks/FINAL_CHECK.md`; do not
paste PowerShell variable assignments into CMD. The release checks were executed
with CMD-compatible commands and structured subprocess arguments.

## 1. Prepare an isolated source copy

Run from PowerShell. A real local Git clone excludes ignored credential files.
Do not copy the working directory or any credential files into it.

```powershell
$Release = 'd855c4ece913775306295a8fec54254e7c2181d1'
$Repo = 'C:\Users\satvi\Desktop\AI Cybersecurity'
$DemoRoot = Join-Path $env:TEMP ('sentinelx-recording-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $DemoRoot | Out-Null
git clone --local --no-hardlinks $Repo (Join-Path $DemoRoot 'source')
if ($LASTEXITCODE -ne 0) { throw 'Clone failed' }
$Source = Join-Path $DemoRoot 'source'
git -C $Source checkout --detach $Release
if ($LASTEXITCODE -ne 0) { throw 'Release checkout failed' }
py -3.11 -m venv (Join-Path $DemoRoot 'venv')
if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed' }
$Py = Join-Path $DemoRoot 'venv\Scripts\python.exe'
& $Py -m pip install -e "$Source[dev]"
if ($LASTEXITCODE -ne 0) { throw 'Install failed' }
& $Py -m pip install -e (Join-Path $Source 'sdk\python')
if ($LASTEXITCODE -ne 0) { throw 'SDK install failed' }
Set-Location $Source
$env:MODEL_PROVIDER = 'recorded'
$env:MODEL_API_KEY = ''
$env:BASETEN_API_KEY = ''
```

Dependency installation may use the package registry; it does not contact a model
provider. The clone has a template file but no real `.env`. Do not create one.
Keep this PowerShell session open: the variables below are used for cleanup.
Do not select a license or publish the clone.

## 2. Rehearse the previously verified workflows

```powershell
& $Py examples/agent_guard_basic.py enforce
if ($LASTEXITCODE -ne 0) { throw 'Agent Guard demo failed' }
& $Py scripts/demo_evidence_chain.py
if ($LASTEXITCODE -ne 0) { throw 'Evidence demo failed' }
$RehearsalTemp = Join-Path $DemoRoot 'pytest-public-processes'
& $Py -m pytest tests/integration/test_shield_public_processes.py -q -p no:cacheprovider "--basetemp=$RehearsalTemp"
if ($LASTEXITCODE -ne 0) { throw 'Separate-process rehearsal failed' }
```

The first command executes the real Python SDK with stubbed tools and synthetic
hostile input; label it **SIMULATED scripted agent / no network / no LLM**.
The second intentionally tampers only with its own temporary database. The third
uses actual separate API and proxy processes and a real upstream HTTP server.
No private approval-store injection or mock upstream is used by that test.

For a fresh Site Guard report, first check that port 18081 is free and no other
lab run is active. The lab is intentionally vulnerable, resettable synthetic data.
This command starts/resets that isolated clone's lab and stops it when finished:

```powershell
& $Py scripts/run_scan.py --target vibe_notes_node --out (Join-Path $DemoRoot 'scan-report')
if ($LASTEXITCODE -ne 0) { throw 'Lab scan failed' }
Get-Content -LiteralPath (Join-Path $DemoRoot 'scan-report\report.md')
```

Do not add `--model`. Inspect the actual output for confirmed/candidate counts,
budget and skipped checks. Never show historical numbers as a fresh measurement.
If port 18081 belongs to another process, stop this step; do not terminate it.

## 3. Start the recording's real API, proxy and synthetic upstream

The small upstream below is a disposable fixture, not a replacement for proxy
matching or activation. It counts every application request. Counter queries do
not count as application traffic. The API and proxy are the production ASGI apps.

```powershell
function Get-DemoPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    return $port
}
$ApiPort = Get-DemoPort
$ProxyPort = Get-DemoPort
$UpstreamPort = Get-DemoPort
$ChosenPorts = @($ApiPort,$ProxyPort,$UpstreamPort)
if (($ChosenPorts | Select-Object -Unique).Count -ne 3) { throw 'Retry port selection' }
$ApiUrl = "http://127.0.0.1:$ApiPort"
$ProxyUrl = "http://127.0.0.1:$ProxyPort"
$UpstreamUrl = "http://127.0.0.1:$UpstreamPort"
$env:SENTINELX_DEMO_TOKEN = 'synthetic-recording-local-only'
$env:SHIELD_RUNTIME_DB = Join-Path $DemoRoot 'shield-runtime.db'
$env:SHIELD_EVIDENCE_DB = Join-Path $DemoRoot 'shield-evidence.db'
$env:SENTINELX_API_EVIDENCE_DB = Join-Path $DemoRoot 'api-evidence.db'
$env:SENTINELX_SCAN_EVIDENCE_DB = Join-Path $DemoRoot 'scan-evidence.db'
$env:SHIELD_KILL_SWITCH_FILE = Join-Path $DemoRoot 'kill-switch'
$env:SHIELD_UPSTREAM = $UpstreamUrl
$env:SHIELD_MODE = 'enforce'
$env:SHIELD_AUTO_SHIELD = '0'
$env:SHIELD_LAB_MODE = '1'
$UpstreamScript = Join-Path $DemoRoot 'upstream.py'
@'
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
hits = 0
lock = threading.Lock()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global hits
        with lock:
            if self.path != '/__demo/count':
                hits += 1
            body = json.dumps({'upstream_requests': hits, 'synthetic': True}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()
'@ | Set-Content -LiteralPath $UpstreamScript -Encoding UTF8
$Started = @()
$Started += Start-Process -FilePath $Py -ArgumentList @($UpstreamScript,$UpstreamPort) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $DemoRoot 'upstream.out') -RedirectStandardError (Join-Path $DemoRoot 'upstream.err')
$Started += Start-Process -FilePath $Py -ArgumentList @('-m','uvicorn','apps.api.main:app','--host','127.0.0.1','--port',$ApiPort,'--no-access-log') -WorkingDirectory $Source -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $DemoRoot 'api.out') -RedirectStandardError (Join-Path $DemoRoot 'api.err')
$Started += Start-Process -FilePath $Py -ArgumentList @('-m','uvicorn','sentinelx.shield.server:create_shield_app','--factory','--host','127.0.0.1','--port',$ProxyPort,'--no-access-log') -WorkingDirectory $Source -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $DemoRoot 'proxy.out') -RedirectStandardError (Join-Path $DemoRoot 'proxy.err')
foreach ($url in @("$ApiUrl/health","$ProxyUrl/__shield/health","$UpstreamUrl/health")) {
    $ready = $false
    for ($i=0; $i -lt 100; $i++) {
        try { $null = Invoke-RestMethod -Uri $url -TimeoutSec 1; $ready=$true; break }
        catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $ready) { throw "Service did not start: $url. Run cleanup below." }
}
$Headers = @{Authorization='Bearer synthetic-recording-local-only'}
function Invoke-DemoApi($Method,$Path,$Body) {
    $params = @{Method=$Method; Uri="$ApiUrl/api/v1$Path"; Headers=$Headers; TimeoutSec=15}
    if ($null -ne $Body) { $params.ContentType='application/json'; $params.Body=($Body | ConvertTo-Json -Depth 10) }
    Invoke-RestMethod @params
}
function Get-ProxyStatus($Path) {
    try { [int](Invoke-WebRequest -UseBasicParsing -Uri "$ProxyUrl$Path" -TimeoutSec 5).StatusCode }
    catch {
        if ($null -eq $_.Exception.Response) { throw }
        [int]$_.Exception.Response.StatusCode
    }
}
```

Use only one API writer. The two production processes must use the same runtime
database and upstream. `enforce` is an explicit demo opt-in; default remains
monitor. The shared token above is a synthetic local-demo token, not production
authentication. Port selection can race another local program: if startup fails,
clean up only this run's processes and retry; never kill the occupying process.

## 4. Public proposal → approval → activation → traffic → removal

Run in the same PowerShell session. Keep the returned IDs; do not substitute
hardcoded success output. These requests use only public authenticated routes.

```powershell
Get-ProxyStatus '/health'  # must observe 200
$Session = Invoke-DemoApi 'POST' '/sessions' @{scenario_id='S1';lab='synthetic';arm='A'}
$Rule = Invoke-DemoApi 'POST' '/shield/rules' @{route_pattern='/submission-probe';intent='RECON';mode='enforce';reason='Authorized synthetic recording';ttl_minutes=10}
$Rule | Select-Object rule_id,state,mode,expires_at
Get-ProxyStatus '/submission-probe'  # before activation: 200
$Approval = Invoke-DemoApi 'POST' '/approvals' @{session_id=$Session.id;action_id=$Rule.rule_id;tool='shield_rule';arguments=@{};reviewer='local demo operator';rationale='Reviewed exact synthetic rule';decision='approve'}
$Approval
$Active = Invoke-DemoApi 'POST' "/shield/rules/$($Rule.rule_id)/approve" @{session_id=$Session.id;action_id=$Rule.rule_id;tool='shield_rule'}
$Active | Select-Object rule_id,state,mode
$Before = (Invoke-RestMethod "$UpstreamUrl/__demo/count").upstream_requests
$BlockedStatus = Get-ProxyStatus '/submission-probe'
$After = (Invoke-RestMethod "$UpstreamUrl/__demo/count").upstream_requests
[pscustomobject]@{HTTP=$BlockedStatus;UpstreamBefore=$Before;UpstreamAfter=$After}
if ($Active.state -ne 'ACTIVE' -or $BlockedStatus -ne 403 -or $Before -ne $After) { throw 'Enforcement not verified' }
$BenignStatus = Get-ProxyStatus '/health'
$AfterBenign = (Invoke-RestMethod "$UpstreamUrl/__demo/count").upstream_requests
[pscustomobject]@{HTTP=$BenignStatus;UpstreamRequests=$AfterBenign}
if ($BenignStatus -ne 200 -or $AfterBenign -ne ($After+1)) { throw 'Benign forwarding not verified' }
Invoke-DemoApi 'DELETE' "/shield/rules/$($Rule.rule_id)" $null
$RemovedStatus = Get-ProxyStatus '/submission-probe'
$AfterRemoval = (Invoke-RestMethod "$UpstreamUrl/__demo/count").upstream_requests
[pscustomobject]@{HTTP=$RemovedStatus;UpstreamRequests=$AfterRemoval}
if ($RemovedStatus -ne 200 -or $AfterRemoval -ne ($AfterBenign+1)) { throw 'Removal not verified' }
$Evidence = Invoke-DemoApi 'GET' '/shield/evidence' $null
$Evidence | ConvertTo-Json -Depth 8
```

The approval route derives the canonical rule subject from trusted stored content.
The `reviewer` label is not independent identity proof; the actual security model
is one authenticated local demo principal. A synthetic upstream result does not
prove the scanner or a real business application has been fixed.

## 5. Optional dashboard shot

The reproducible terminal flow above is sufficient; do not improvise a dashboard
configuration during recording. If showing the dashboard, build it before the
take (`npm ci`, `npm run build`) and serve only on loopback. Its default API/token
expect `127.0.0.1:8080` and the built-in local-demo token. For this guide's dynamic
API port and synthetic token, a preview copy must set
`window.SENTINELX_API_BASE_URL` and `window.SENTINELX_DEMO_TOKEN` **before** the
bundle loads. These globals configure only the local API, never model credentials.
Keep the original build untouched. Otherwise omit this shot; do not show stale
dashboard data as evidence for the current run.

## 6. Cleanup and recording checklist

Run even after a failed step. Stop only processes returned by this session's
`Start-Process`. Do not enumerate and terminate all Python/Node processes.

```powershell
foreach ($process in $Started) {
    if (-not $process.HasExited) { $process | Stop-Process }
}
Set-Location $Repo
git status --short --branch
```

Keep `$DemoRoot` for review; it contains only this run's synthetic state and logs.
Do not run recursive cleanup against an unverified computed path. The clone's
lab scanner stops its own lab; if interrupted, use that clone's
`python scripts/lab_down.py vibe_notes_node`, never an unrelated process kill.

- [ ] Pin and display the release SHA; show no actual credentials or personal data.
- [ ] Rehearsal passes with actual status codes and upstream counter comparisons.
- [ ] Record at readable resolution; hide unrelated windows/notifications.
- [ ] Keep narration within the owner's confirmed video limit; label cuts/replays.
- [ ] Label scripted agent SIMULATED and historical artifacts RECORDED evidence.
- [ ] Show BLOCK versus executed action, candidate versus confirmed finding.
- [ ] Show temporary Shield limitation and single-operator trust boundary.
- [ ] Inspect the exported video for secrets, stale IDs, audio and misleading claims.
- [ ] Owner uploads video, tests judge access, replaces the video URL placeholder.
- [ ] Owner completes the portal and saves the submission receipt separately.
