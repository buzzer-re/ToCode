[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $HOME "ToCode"),
    [string]$Repo = "https://github.com/buzzer-re/ToCode.git",
    [string]$Branch = "main",
    [switch]$Dev
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message"
}

function Fail {
    param([string]$Message)
    Write-Error "install.ps1: $Message"
    exit 1
}

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-PythonCommand {
    $candidates = @(
        @("py", "-3"),
        @("python3"),
        @("python")
    )

    foreach ($candidate in $candidates) {
        $name = $candidate[0]
        if (-not (Test-Command $name)) {
            continue
        }

        $args = @()
        if ($candidate.Count -gt 1) {
            $args = $candidate[1..($candidate.Count - 1)]
        }

        & $name @args -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return @{
                Name = $name
                Args = $args
            }
        }
    }

    return $null
}

if (-not (Test-Command "git")) {
    Fail "git is required but was not found on PATH"
}

$gitDir = Join-Path $InstallDir ".git"
if (Test-Path $gitDir) {
    Write-Step "Updating ToCode at $InstallDir"
    git -C $InstallDir fetch origin $Branch
    git -C $InstallDir checkout $Branch
    git -C $InstallDir pull --ff-only origin $Branch
}
elseif (Test-Path $InstallDir) {
    Fail "$InstallDir already exists and is not a Git checkout"
}
else {
    Write-Step "Cloning ToCode into $InstallDir"
    git clone --branch $Branch $Repo $InstallDir
}

if (Test-Command "uv") {
    Write-Step "Syncing local project environment with uv"
    if ($Dev) {
        uv --directory $InstallDir sync --extra dev
    }
    else {
        uv --directory $InstallDir sync
    }

    Write-Step "Installing the tocode command with uv"
    uv tool install --force --editable $InstallDir

    if (-not (Test-Command "tocode")) {
        $toolBin = (& uv tool dir --bin 2>$null)
        if ($LASTEXITCODE -eq 0 -and $toolBin) {
            $env:PATH = "$toolBin;$env:PATH"
        }
    }
}
else {
    $python = Get-PythonCommand
    if ($null -eq $python) {
        Fail "Python 3.10 or newer is required when uv is not installed"
    }

    Write-Step "Installing the tocode command with pip"
    $package = $InstallDir
    if ($Dev) {
        $package = "$InstallDir[dev]"
    }
    & $python.Name @($python.Args) -m pip install --user --editable $package

    $userBase = (& $python.Name @($python.Args) -c "import site; print(site.USER_BASE)")
    if ($LASTEXITCODE -eq 0 -and $userBase) {
        $env:PATH = "$(Join-Path $userBase 'Scripts');$env:PATH"
    }
}

if (-not (Test-Command "tocode")) {
    Fail "tocode was installed, but its bin directory is not on PATH"
}

tocode --help | Out-Null

Write-Step "ToCode is installed"
Write-Host "Run: tocode <binary> -o <output_dir>"
