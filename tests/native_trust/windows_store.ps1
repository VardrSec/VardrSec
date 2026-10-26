param(
    [Parameter(Mandatory)][ValidateSet('enroll','remove')][string]$Action,
    [Parameter(Mandatory)][string]$Certificate,
    [Parameter(Mandatory)][ValidatePattern('^[A-F0-9]{40}$')][string]$Thumbprint
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Certificate-store acceptance is restricted to disposable GitHub-hosted runners'
}
$target = "Cert:\CurrentUser\Root\$Thumbprint"
if ($Action -eq 'enroll') {
    if (Test-Path -LiteralPath $target) { throw 'Fixture CA was already trusted' }
    $cert = Import-Certificate -FilePath $Certificate -CertStoreLocation Cert:\CurrentUser\Root
    if ($cert.Thumbprint -ne $Thumbprint) { throw 'Imported certificate fingerprint differs' }
} elseif (Test-Path -LiteralPath $target) {
    Remove-Item -LiteralPath $target
}
