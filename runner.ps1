# Without a separator all arguments belong to Runner; wrapper options need --.
$PSNativeCommandUseErrorActionPreference = $false
if ($args.Count -eq 1 -and $args[0] -in @('-h', '--help')) {
    Write-Output 'Usage: .\runner.ps1 [Runner arguments]'; Write-Output '.\runner.ps1 [--authority-volume NAME] [--input-directory DIR] [--output-directory DIR] -- <Runner arguments>'; exit 0
}
$forward = @($args)
if ($forward -notcontains '--') { $forward = @('--') + $forward }
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
& $python @prefix $script runner @forward
exit $LASTEXITCODE
