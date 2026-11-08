# Thin installer selector; vardrsec.py owns installation behavior.
$PSNativeCommandUseErrorActionPreference = $false
function Usage { Write-Output 'Usage: .\install.ps1 [--full | --mapless] [Python installer arguments]'; Write-Output 'Full: Map interface + Runner/Gate + database/proxy. Mapless: Runner/Gate CLI only.' }
$mode = $null; $help = $false; $forward = @()
foreach ($item in $args) {
    switch -CaseSensitive ($item) {
        '--full' { if ($mode -and $mode -ne 'full') { Usage; exit 2 }; $mode = 'full' }
        '--mapless' { if ($mode -and $mode -ne 'mapless') { Usage; exit 2 }; $mode = 'mapless' }
        '--help' { $help = $true }
        '-h' { $help = $true }
        default { $forward += $item }
    }
}
if ($help) { Usage; exit 0 }
if (-not $mode) {
    if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { Usage; exit 2 }
    Usage
    $choice = Read-Host 'Choose full or mapless'
    if ($choice -notin @('full', 'mapless')) { [Console]::Error.WriteLine('Choose full or mapless explicitly.'); exit 2 }
    $mode = $choice.ToLowerInvariant()
}
$python = $null; $prefix = @()
foreach ($name in @('py', 'python', 'python3')) {
    $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { continue }
    $probe = @(); if ($name -eq 'py') { $probe = @('-3') }
    & $command.Source @probe -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' *> $null
    if ($LASTEXITCODE -eq 0) { $python = $command.Source; $prefix = $probe; break }
}
if (-not $python) { [Console]::Error.WriteLine('Python 3.10+ is required; use an existing Python installation.'); exit 2 }
$script = Join-Path $PSScriptRoot 'vardrsec.py'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { [Console]::Error.WriteLine('Run this launcher from the VardrSec checkout.'); exit 2 }
& $python @prefix $script install "--$mode" @forward
exit $LASTEXITCODE
