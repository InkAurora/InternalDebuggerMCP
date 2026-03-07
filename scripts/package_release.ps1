param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [string]$PythonPath = "",
    [string]$MSBuildPath = "",
    [switch]$IncludeSymbols
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-MSBuild {
    param([string]$PreferredPath)

    if ($PreferredPath) {
        if (-not (Test-Path -LiteralPath $PreferredPath)) {
            throw "MSBuild was not found at '$PreferredPath'."
        }
        return (Resolve-Path -LiteralPath $PreferredPath).Path
    }

    $knownPath = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    if (Test-Path -LiteralPath $knownPath) {
        return $knownPath
    }

    $vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswherePath) {
        $installationPath = & $vswherePath -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($LASTEXITCODE -eq 0 -and $installationPath) {
            $candidate = Join-Path $installationPath "MSBuild\Current\Bin\MSBuild.exe"
            if (Test-Path -LiteralPath $candidate) {
                return $candidate
            }
        }
    }

    throw "Unable to locate MSBuild.exe. Pass -MSBuildPath explicitly."
}

function Resolve-Python {
    param([string]$PreferredPath, [string]$RepositoryRoot)

    if ($PreferredPath) {
        if (-not (Test-Path -LiteralPath $PreferredPath)) {
            throw "Python was not found at '$PreferredPath'."
        }
        return (Resolve-Path -LiteralPath $PreferredPath).Path
    }

    $venvPython = Join-Path $RepositoryRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPython) {
        return $venvPython
    }

    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw "Unable to locate python.exe. Pass -PythonPath explicitly."
}

function Read-ProjectMetadata {
    param([string]$PyprojectPath)

    $content = Get-Content -LiteralPath $PyprojectPath -Raw
    $versionMatch = [regex]::Match($content, '(?m)^version\s*=\s*"([^"]+)"')
    if (-not $versionMatch.Success) {
        throw "Failed to read version from $PyprojectPath"
    }

    $dependenciesMatch = [regex]::Match($content, '(?s)dependencies\s*=\s*\[(.*?)\]')
    $dependencies = @()
    if ($dependenciesMatch.Success) {
        foreach ($match in [regex]::Matches($dependenciesMatch.Groups[1].Value, '"([^"]+)"')) {
            $dependencies += $match.Groups[1].Value
        }
    }

    return @{
        Version = $versionMatch.Groups[1].Value
        Dependencies = $dependencies
    }
}

function Assert-PathExists {
    param([string]$PathValue, [string]$Description)

    if (-not (Test-Path -LiteralPath $PathValue)) {
        throw "$Description was not found at '$PathValue'."
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$solutionPath = Join-Path $repoRoot "InternalDebuggerMCP.sln"
$pyprojectPath = Join-Path $repoRoot "src\McpServer\pyproject.toml"
$mcpSourceRoot = Join-Path $repoRoot "src\McpServer"

$msbuild = Resolve-MSBuild -PreferredPath $MSBuildPath
$python = Resolve-Python -PreferredPath $PythonPath -RepositoryRoot $repoRoot
$metadata = Read-ProjectMetadata -PyprojectPath $pyprojectPath

$outputRoot = Join-Path $repoRoot "artifacts\$Configuration\$Platform"
$injectorSource = Join-Path $outputRoot "Injector\Injector.exe"
$injectorPdbSource = Join-Path $outputRoot "Injector\Injector.pdb"
$dllSource = Join-Path $outputRoot "InternalDebuggerDLL\InternalDebuggerDLL.dll"
$dllPdbSource = Join-Path $outputRoot "InternalDebuggerDLL\InternalDebuggerDLL.pdb"

$distRoot = Join-Path $repoRoot "dist"
$stageRoot = Join-Path $distRoot "staging"
$packageRoot = Join-Path $stageRoot "InternalDebuggerMCP"
$serverStageRoot = Join-Path $packageRoot "mcp-server"
$vendorStageRoot = Join-Path $serverStageRoot "vendor"
$zipPath = Join-Path $distRoot ("InternalDebuggerMCP-{0}-win-{1}.zip" -f $metadata.Version, $Platform.ToLowerInvariant())

Write-Host "Building native solution with $msbuild"
& $msbuild $solutionPath /m "/p:Configuration=$Configuration;Platform=$Platform"
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE."
}

Assert-PathExists -PathValue $injectorSource -Description "Injector executable"
Assert-PathExists -PathValue $dllSource -Description "Debugger DLL"

if (Test-Path -LiteralPath $stageRoot) {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}

New-Item -ItemType Directory -Path $vendorStageRoot -Force | Out-Null

Copy-Item -LiteralPath $injectorSource -Destination (Join-Path $packageRoot "Injector.exe")
Copy-Item -LiteralPath $dllSource -Destination (Join-Path $packageRoot "InternalDebuggerDLL.dll")

if ($IncludeSymbols) {
    if (Test-Path -LiteralPath $injectorPdbSource) {
        Copy-Item -LiteralPath $injectorPdbSource -Destination (Join-Path $packageRoot "Injector.pdb")
    }
    if (Test-Path -LiteralPath $dllPdbSource) {
        Copy-Item -LiteralPath $dllPdbSource -Destination (Join-Path $packageRoot "InternalDebuggerDLL.pdb")
    }
}

Copy-Item -LiteralPath (Join-Path $repoRoot "README.md") -Destination (Join-Path $packageRoot "README.md")
Copy-Item -LiteralPath (Join-Path $mcpSourceRoot "launch.py") -Destination (Join-Path $serverStageRoot "launch.py")
Copy-Item -LiteralPath (Join-Path $mcpSourceRoot "README.md") -Destination (Join-Path $serverStageRoot "README.md")
Copy-Item -LiteralPath (Join-Path $mcpSourceRoot "mcp.json.example") -Destination (Join-Path $serverStageRoot "mcp.json.example")
Copy-Item -LiteralPath (Join-Path $mcpSourceRoot "mcp_server") -Destination (Join-Path $serverStageRoot "mcp_server") -Recurse

Get-ChildItem -LiteralPath $serverStageRoot -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Get-ChildItem -LiteralPath $serverStageRoot -Recurse -File -Include "*.pyc","*.pyo" | Remove-Item -Force

if ($metadata.Dependencies.Count -gt 0) {
    Write-Host "Vendoring Python dependencies into $vendorStageRoot"
    & $python -m pip install --disable-pip-version-check --no-compile --upgrade --target $vendorStageRoot @($metadata.Dependencies)
    if ($LASTEXITCODE -ne 0) {
        throw "pip install failed with exit code $LASTEXITCODE."
    }
}

$manifest = @{
    packageName = "InternalDebuggerMCP"
    version = $metadata.Version
    configuration = $Configuration
    platform = $Platform
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    files = @(
        "Injector.exe",
        "InternalDebuggerDLL.dll",
        "mcp-server/launch.py",
        "mcp-server/mcp_server",
        "mcp-server/vendor",
        "mcp-server/mcp.json.example"
    )
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $packageRoot "package-manifest.json") -Encoding ASCII

$quickStart = @(
    "InternalDebuggerMCP release package",
    "",
    "1. Configure your MCP client to launch mcp-server\launch.py with a local Python 3.10+ interpreter.",
    "2. Use the get_injection_setup MCP tool to discover the exact injector and DLL paths in this extraction.",
    "3. Use find_process_pid to resolve the target process PID.",
    "4. Run Injector.exe <PID> <full-dll-path> from an elevated shell when needed.",
    "5. Call ping(pid) to confirm the injected pipe is reachable."
)
$quickStart | Set-Content -LiteralPath (Join-Path $packageRoot "QUICKSTART.txt") -Encoding ASCII

Assert-PathExists -PathValue (Join-Path $serverStageRoot "launch.py") -Description "Packaged MCP launcher"
Assert-PathExists -PathValue (Join-Path $serverStageRoot "mcp_server") -Description "Packaged MCP source"

$vendorEntries = Get-ChildItem -LiteralPath $vendorStageRoot -Force
if ($metadata.Dependencies.Count -gt 0 -and $vendorEntries.Count -eq 0) {
    throw "Vendored dependency directory is empty: $vendorStageRoot"
}

Compress-Archive -LiteralPath $packageRoot -DestinationPath $zipPath -CompressionLevel Optimal

Write-Host "Created release package: $zipPath"