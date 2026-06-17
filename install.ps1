[CmdletBinding()]
param(
    [string]$InstallDir,
    [string]$Repo = "https://github.com/buzzer-re/ToCode.git",
    [string]$Branch = "main",
    [switch]$Dev,
    [switch]$Full
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:PathWasUpdated = $false

# When run from an existing ToCode checkout, install from it instead of
# cloning a second copy. $PSScriptRoot is empty when piped through iex.
$scriptDir = $PSScriptRoot
if (-not $InstallDir) {
    if ($scriptDir -and (Test-Path (Join-Path $scriptDir ".git")) -and (Test-Path (Join-Path $scriptDir "pyproject.toml"))) {
        $InstallDir = $scriptDir
    }
    else {
        $InstallDir = Join-Path $HOME "ToCode"
    }
}

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message"
}

function Fail {
    param(
        [string]$Message,
        [string[]]$Hints = @()
    )
    Write-Host ""
    Write-Host "ToCode was not installed: $Message" -ForegroundColor Red
    foreach ($hint in $Hints) {
        Write-Host "    $hint" -ForegroundColor Yellow
    }
    exit 1
}

function Assert-NativeSuccess {
    param(
        [string]$Message,
        [string[]]$Hints = @()
    )
    if ($LASTEXITCODE -ne 0) {
        Fail "$Message (exit code $LASTEXITCODE)." $Hints
    }
}

# Runs a native command with stderr suppressed. Under
# $ErrorActionPreference = "Stop", Windows PowerShell turns redirected native
# stderr into a terminating NativeCommandError, so relax the preference first.
function Invoke-Quiet {
    param([scriptblock]$Command)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $Command 2>$null
    }
    finally {
        $ErrorActionPreference = $previous
    }
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

        $extraArgs = @()
        if ($candidate.Count -gt 1) {
            $extraArgs = $candidate[1..($candidate.Count - 1)]
        }

        Invoke-Quiet { & $name @extraArgs -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" } | Out-Null
        if ($LASTEXITCODE -eq 0) {
            return @{
                Name = $name
                Args = $extraArgs
            }
        }
    }

    return $null
}

function Test-PathEntry {
    param(
        [string]$PathValue,
        [string]$Entry
    )

    $parts = $PathValue -split ';' | Where-Object { $_ }
    foreach ($part in $parts) {
        if ($part.TrimEnd('\') -ieq $Entry.TrimEnd('\')) {
            return $true
        }
    }
    return $false
}

function Add-UserPath {
    param([string]$BinDir)

    if (-not $BinDir) {
        return
    }

    if (-not (Test-Path $BinDir)) {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    }

    if (-not (Test-PathEntry -PathValue $env:PATH -Entry $BinDir)) {
        $env:PATH = "$BinDir;$env:PATH"
    }

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) {
        $userPath = ""
    }
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if (-not $machinePath) {
        $machinePath = ""
    }

    $missingFromPersistentPath = -not (Test-PathEntry -PathValue $userPath -Entry $BinDir) -and -not (Test-PathEntry -PathValue $machinePath -Entry $BinDir)
    if ($missingFromPersistentPath) {
        $newUserPath = if ($userPath) { "$userPath;$BinDir" } else { $BinDir }
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        $script:PathWasUpdated = $true
        Write-Step "Added $BinDir to your user Path"
    }
}

if (-not (Test-Command "git")) {
    Fail "Git was not found on PATH." @(
        "Install Git for Windows from https://git-scm.com/download/win, then run this installer again."
    )
}

$gitDir = Join-Path $InstallDir ".git"
if (Test-Path $gitDir) {
    if ($scriptDir -and ((Resolve-Path $InstallDir).Path.TrimEnd('\') -ieq (Resolve-Path $scriptDir).Path.TrimEnd('\'))) {
        Write-Step "Installing ToCode from this checkout at $InstallDir"
    }
    else {
        Write-Step "Updating ToCode at $InstallDir"
        git -C $InstallDir fetch origin $Branch
        Assert-NativeSuccess "could not fetch branch '$Branch' from origin"
        git -C $InstallDir checkout $Branch
        Assert-NativeSuccess "could not check out branch '$Branch' in $InstallDir"
        git -C $InstallDir pull --ff-only origin $Branch
        Assert-NativeSuccess "could not update the checkout at $InstallDir" @(
            "The checkout may have local changes. Resolve them, or remove the directory and run this installer again."
        )
    }
}
elseif (Test-Path $InstallDir) {
    Fail "$InstallDir already exists and is not a ToCode Git checkout." @(
        "Move or delete it, or pick another location with: .\install.ps1 -InstallDir <path>"
    )
}
else {
    Write-Step "Cloning ToCode into $InstallDir"
    git clone --branch $Branch $Repo $InstallDir
    Assert-NativeSuccess "could not clone $Repo"
}

$binDir = $null

# Build the list of optional dependency groups to install. "dev" pulls in the
# test tooling; -Full installs the angr pure-Python fallback backend.
#
# uv sync populates the project's .venv (used by `uv run` / development), while
# uv tool install builds a separate isolated environment for the `tocode`
# command. Runtime extras (angr) must be passed to BOTH or the installed
# command will not see them. dev is build/test tooling, so it only belongs in
# the project venv, not the tool environment.
$uvExtras = @()
$pipExtras = @()
$toolExtras = @()
if ($Dev) {
    $uvExtras += @("--extra", "dev")
    $pipExtras += "dev"
}
if ($Full) {
    $uvExtras += @("--extra", "angr")
    $pipExtras += "angr"
    $toolExtras += "angr"
}

if (Test-Command "uv") {
    Write-Step "Syncing local project environment with uv"
    uv --directory $InstallDir sync --locked @uvExtras
    Assert-NativeSuccess "uv could not sync the project environment"

    Write-Step "Installing the tocode command with uv"
    $toolTarget = $InstallDir
    if ($toolExtras.Count -gt 0) {
        $toolTarget = "$InstallDir[$($toolExtras -join ',')]"
    }
    uv tool install --force --editable $toolTarget
    Assert-NativeSuccess "uv could not install the tocode command"

    $toolBin = Invoke-Quiet { uv tool dir --bin }
    if ($LASTEXITCODE -eq 0 -and $toolBin) {
        $binDir = "$toolBin".Trim()
    }
}
else {
    $python = Get-PythonCommand
    if ($null -eq $python) {
        Fail "neither uv nor Python 3.10+ was found on PATH." @(
            "Install uv from https://docs.astral.sh/uv/getting-started/installation/ (recommended),",
            "or install Python 3.10 or newer from https://www.python.org/downloads/, then run this installer again."
        )
    }

    Invoke-Quiet { & $python.Name @($python.Args) -m pip --version } | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Invoke-Quiet { & $python.Name @($python.Args) -m ensurepip --upgrade } | Out-Null
        Invoke-Quiet { & $python.Name @($python.Args) -m pip --version } | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Fail "the selected Python has no pip module available." @(
                "Install uv from https://docs.astral.sh/uv/getting-started/installation/ (recommended; it does not need pip),",
                "or install pip for this interpreter, then run this installer again."
            )
        }
    }

    Write-Step "Installing the tocode command with pip"
    $package = $InstallDir
    if ($pipExtras.Count -gt 0) {
        $package = "$InstallDir[$($pipExtras -join ',')]"
    }
    & $python.Name @($python.Args) -m pip install --user --editable $package
    Assert-NativeSuccess "pip could not install ToCode"

    # The per-user scripts directory is versioned on Windows (for example
    # %APPDATA%\Python\Python312\Scripts), so ask Python for the real path
    # instead of assuming USER_BASE\Scripts.
    $scriptsDir = Invoke-Quiet { & $python.Name @($python.Args) -c "import sysconfig; print(sysconfig.get_path('scripts', sysconfig.get_preferred_scheme('user')))" }
    if ($LASTEXITCODE -eq 0 -and $scriptsDir) {
        $binDir = "$scriptsDir".Trim()
    }
}

if ($binDir) {
    Add-UserPath -BinDir $binDir
}

if (Test-Command "tocode") {
    tocode --help | Out-Null
    Assert-NativeSuccess "tocode is installed but 'tocode --help' failed" @(
        "Check the output above, or re-run this installer."
    )

    Write-Host ""
    Write-Host "ToCode is installed." -ForegroundColor Green
    if ($script:PathWasUpdated) {
        Write-Host "Your PATH was updated for future sessions. If 'tocode' is not recognized in an already-open terminal, open a new one."
    }
    Write-Host "Run: tocode <binary> -o <output_dir>"
    exit 0
}

$tocodeExe = $null
if ($binDir) {
    $tocodeExe = Join-Path $binDir "tocode.exe"
}

if ($tocodeExe -and (Test-Path $tocodeExe)) {
    Write-Host ""
    Write-Host "ToCode is installed." -ForegroundColor Green
    Write-Host "The tocode command lives in $binDir, which was added to your PATH, but this terminal does not pick up the change automatically."
    Write-Host "Open a new PowerShell window, then run: tocode <binary> -o <output_dir>"
    exit 0
}

$hints = @()
if ($binDir) {
    $hints += "Expected it in $binDir - check that directory and add it to your PATH if it is there."
}
else {
    $hints += "Could not determine the tool bin directory. Add the directory containing tocode.exe to your PATH manually."
}
$hints += "You can also run ToCode without PATH changes: uv --directory $InstallDir run tocode --help"
Fail "the install finished, but the tocode command could not be located." $hints
