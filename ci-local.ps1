# Local CI simulation. Mirrors .github/workflows/ci.yml.
# Usage: .\ci-local.ps1 [-Fix]
[CmdletBinding()]
param(
    [switch]$Fix
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Pass = 0
$Fail = 0
$Results = New-Object System.Collections.Generic.List[string]

function Add-Pass([string]$Name) {
    $script:Pass += 1
    $script:Results.Add("PASS $Name")
}

function Add-Fail([string]$Name, [string]$Reason) {
    $script:Fail += 1
    $script:Results.Add("FAIL ${Name}: $Reason")
}

function Add-Warn([string]$Message) {
    $script:Results.Add("WARN $Message")
}

function Write-Step([string]$Message) {
    Write-Host "> $Message" -ForegroundColor Yellow
}

function Test-Command([string]$Name) {
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-Tool {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    if (Test-Command "uv") {
        & uv run @Args
    } else {
        & $Args[0] @($Args | Select-Object -Skip 1)
    }
}

function Invoke-With {
    param(
        [string[]]$Packages,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Args
    )
    if (Test-Command "uv") {
        $uvArgs = @("run")
        foreach ($Package in $Packages) {
            $uvArgs += @("--with", $Package)
        }
        $uvArgs += $Args
        & uv @uvArgs
    } else {
        & $Args[0] @($Args | Select-Object -Skip 1)
    }
}

Write-Step "Checking CI tools"
if (-not (Test-Command "uv")) {
    Add-Warn "uv not found; using current Python environment for tools"
}

Write-Step "[1/5] Ruff format"
if ($Fix) {
    Invoke-With -Packages @("ruff==0.15.13") python -m ruff format src tests
} else {
    Invoke-With -Packages @("ruff==0.15.13") python -m ruff format --check src tests
}
if ($LASTEXITCODE -eq 0) {
    Add-Pass "ruff format"
} else {
    Add-Fail "ruff format" "run .\ci-local.ps1 -Fix"
}

Write-Step "[2/5] Ruff lint"
if ($Fix) {
    Invoke-With -Packages @("ruff==0.15.13") python -m ruff check src tests --fix
} else {
    Invoke-With -Packages @("ruff==0.15.13") python -m ruff check src tests
}
if ($LASTEXITCODE -eq 0) {
    Add-Pass "ruff lint"
} else {
    Add-Fail "ruff lint" "see output above"
}

Write-Step "[3/5] Mypy"
Invoke-With -Packages @("mypy==2.1.0", "tomli==2.4.1", "types-tqdm", "pytest>=8,<9") python -m mypy src tests --pretty
if ($LASTEXITCODE -eq 0) {
    Add-Pass "mypy"
} else {
    Add-Fail "mypy" "see output above"
}

Write-Step "[4/5] Pytest"
Invoke-Tool --extra dev pytest -q
if ($LASTEXITCODE -eq 0) {
    Add-Pass "pytest"
} else {
    Add-Fail "pytest" "see output above"
}

Write-Step "[5/5] Compile Python"
Invoke-Tool python -m compileall src tests
if ($LASTEXITCODE -eq 0) {
    Add-Pass "compileall"
} else {
    Add-Fail "compileall" "see output above"
}

Write-Host ""
Write-Host "CI Results" -ForegroundColor White
foreach ($Result in $Results) {
    Write-Host "  $Result"
}

if ($Fail -gt 0) {
    Write-Host "FAILED - $Fail check(s) failed, $Pass passed" -ForegroundColor Red
    exit 1
}

Write-Host "ALL REQUIRED CHECKS PASSED - $Pass checks" -ForegroundColor Green
