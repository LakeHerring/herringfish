$OutDir = "tests\vectors"

$RepoOwner = "usnistgov"
$RepoName = "ACVP-Server"
$Branch = "master"

$ApiBase = "https://api.github.com/repos/$RepoOwner/$RepoName"
$RefUrl = "$ApiBase/git/ref/heads/$Branch"
$RawBaseUrl = "https://raw.githubusercontent.com/$RepoOwner/$RepoName/$Branch"

$VersionFile = Join-Path $OutDir ".acvp-commit"

Write-Host ""
Write-Host "Updating NIST ACVP vectors..." -ForegroundColor Cyan
Write-Host ""

# ===========================================================================

# Create output directory

# ===========================================================================

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# ===========================================================================

# GitHub API headers

# ===========================================================================

$Headers = @{
"Accept" = "application/vnd.github+json"
"User-Agent" = "herringfish-acvp-updater"
}

# ===========================================================================

# Get current NIST commit SHA

# ===========================================================================

Write-Host "Checking NIST ACVP repository..." -ForegroundColor Cyan

try {
$Ref = Invoke-RestMethod -Uri $RefUrl -Headers $Headers -UseBasicParsing
}
catch {
Write-Error "Failed to fetch GitHub repository metadata."
Write-Error $_.Exception.Message
exit 1
}

$RemoteCommit = $Ref.object.sha

if ([string]::IsNullOrWhiteSpace($RemoteCommit)) {
Write-Error "GitHub did not return a commit SHA."
exit 1
}

Write-Host "Remote commit: $RemoteCommit" -ForegroundColor DarkGray

# ===========================================================================

# Check local commit

# ===========================================================================

$LocalCommit = $null

if (Test-Path $VersionFile) {
$LocalCommit = (Get-Content -Path $VersionFile -Raw).Trim()
}

if ($LocalCommit) {
Write-Host "Local commit:  $LocalCommit" -ForegroundColor DarkGray
}

# ===========================================================================

# If commits match, nothing needs to be done

# ===========================================================================

if ($LocalCommit -eq $RemoteCommit) {

Write-Host ""
Write-Host "NIST ACVP repository has not changed." -ForegroundColor Green
Write-Host "Local vectors are already current." -ForegroundColor Green
Write-Host ""
Write-Host "Nothing to download." -ForegroundColor DarkGray
Write-Host ""

exit 0

}

# ===========================================================================

# Repository changed

# ===========================================================================

Write-Host ""
Write-Host "NIST ACVP repository has changed." -ForegroundColor Yellow
Write-Host "Comparing individual vector files..." -ForegroundColor Cyan
Write-Host ""

# ===========================================================================

# Get recursive Git tree

# ===========================================================================

$TreeUrl = $ApiBase + "/git/trees/" + $RemoteCommit + "?recursive=1"

try {
$Tree = Invoke-RestMethod -Uri $TreeUrl -Headers $Headers -UseBasicParsing
}
catch {
Write-Error "Failed to fetch Git tree metadata."
Write-Error $_.Exception.Message
exit 1
}

if ($Tree.truncated -eq $true) {
Write-Error "GitHub returned a truncated repository tree."
Write-Error "The repository tree is too large for the recursive Git Trees API."
exit 1
}

# ===========================================================================

# Select ACVP vector files

# ===========================================================================

$AllowedFolders = @('SHA3-384-2.0','SHA2-512-256-1.0','SHA2-512-1.0','SHAKE-256-FIPS202','SHAKE-256-1.0','SHA3-512-2.0')

$RemoteFiles = @(
    $Tree.tree | Where-Object {
        $_.type -eq "blob" -and
        $_.path.StartsWith("gen-val/json-files/")
    }
)

$RemoteFiles = $RemoteFiles | Where-Object {
    $folder = $_.path.Substring("gen-val/json-files/".Length).Split('/')[0]
    $AllowedFolders -contains $folder
}

Write-Host "Remote ACVP files: $($RemoteFiles.Count)" -ForegroundColor DarkGray
Write-Host ""

# ===========================================================================

# Function to calculate Git blob SHA-1

# ===========================================================================

function Get-GitBlobHash {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $Bytes = [System.IO.File]::ReadAllBytes($Path)

    # Git calculates the SHA-1 over:
    #
    # blob <file-size><NUL><file-data>

    $HeaderText = "blob " + $Bytes.Length + [char]0
    $Header = [System.Text.Encoding]::ASCII.GetBytes($HeaderText)

    $Data = New-Object byte[] ($Header.Length + $Bytes.Length)

    [System.Buffer]::BlockCopy(
        $Header,
        0,
        $Data,
        0,
        $Header.Length
    )

    [System.Buffer]::BlockCopy(
        $Bytes,
        0,
        $Data,
        $Header.Length,
        $Bytes.Length
    )

    $SHA1 = [System.Security.Cryptography.SHA1]::Create()

    try {
        $HashBytes = $SHA1.ComputeHash($Data)
    }
    finally {
        $SHA1.Dispose()
    }

    return (
        [System.BitConverter]::ToString($HashBytes)
    ).Replace("-", "").ToLowerInvariant()
}

# ===========================================================================

# Statistics

# ===========================================================================

$Skipped = 0
$Downloaded = 0
$NewFiles = 0
$ChangedFiles = 0
$Failed = 0
$Removed = 0

$RemotePaths = @{}

# ===========================================================================

# Compare remote files against local files

# ===========================================================================

foreach ($RemoteFile in $RemoteFiles) {

$RelativePath = $RemoteFile.path.Substring(
    "gen-val/json-files/".Length
)

$RemotePaths[$RelativePath] = $true

$WindowsRelativePath = $RelativePath.Replace("/", "\")

$LocalPath = Join-Path $OutDir $WindowsRelativePath

# -----------------------------------------------------------------------
# Existing file
# -----------------------------------------------------------------------

if (Test-Path $LocalPath -PathType Leaf) {

    try {
        $LocalHash = Get-GitBlobHash -Path $LocalPath
    }
    catch {
        Write-Warning "Could not hash local file: $RelativePath"
        $LocalHash = $null
    }

    if ($LocalHash -eq $RemoteFile.sha) {

        $Skipped++

        continue
    }

    Write-Host "UPDATE  $RelativePath" -ForegroundColor Yellow

    $ChangedFiles++
}
else {

    Write-Host "NEW     $RelativePath" -ForegroundColor Green

    $NewFiles++
}

# -----------------------------------------------------------------------
# Create destination directory
# -----------------------------------------------------------------------

$LocalDirectory = Split-Path $LocalPath -Parent

if (-not (Test-Path $LocalDirectory)) {
    New-Item -ItemType Directory -Path $LocalDirectory -Force | Out-Null
}

# -----------------------------------------------------------------------
# Download changed/new file
# -----------------------------------------------------------------------

$EncodedPath = (
    $RelativePath -split "/" |
    ForEach-Object {
        [System.Uri]::EscapeDataString($_)
    }
) -join "/"

$DownloadUrl = "$RawBaseUrl/gen-val/json-files/$EncodedPath"

try {

    Invoke-WebRequest -Uri $DownloadUrl -OutFile $LocalPath -UseBasicParsing

    $Downloaded++
}
catch {

    Write-Warning "Failed to download: $RelativePath"
    Write-Warning $_.Exception.Message

    $Failed++
}

}

# ===========================================================================

# Remove files no longer present in NIST

# ===========================================================================

Write-Host ""
Write-Host "Checking for removed vectors..." -ForegroundColor Cyan
Write-Host ""

$LocalFiles = @(
Get-ChildItem -Path $OutDir -Recurse -File |
Where-Object {
$_.FullName -ne $VersionFile
}
)

foreach ($LocalFile in $LocalFiles) {

$RelativePath = $LocalFile.FullName.Substring(
    $OutDir.Length + 1
)

$RelativePath = $RelativePath.Replace("\", "/")

if (-not $RemotePaths.ContainsKey($RelativePath)) {

    Write-Host "REMOVE  $RelativePath" -ForegroundColor Red

    Remove-Item -Path $LocalFile.FullName -Force

    $Removed++
}

}

# ===========================================================================

# Remove empty directories

# ===========================================================================

Get-ChildItem -Path $OutDir -Directory -Recurse |
Sort-Object FullName -Descending |
ForEach-Object {

    $Contents = Get-ChildItem -Path $_.FullName -Force

    if ($Contents.Count -eq 0) {
        Remove-Item -Path $_.FullName -Force
    }
}

# ===========================================================================

# Save current NIST commit

# ===========================================================================

Set-Content -Path $VersionFile -Value $RemoteCommit -Encoding ASCII

# ===========================================================================

# Final statistics

# ===========================================================================

$VectorFiles = @(
Get-ChildItem -Path $OutDir -Recurse -File -Filter "*.json"
)

$VectorDirectories = @(
Get-ChildItem -Path $OutDir -Directory -Recurse
)

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host " NIST ACVP vectors successfully updated" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host ""

Write-Host "Repository:         $RepoOwner/$RepoName"
Write-Host "Branch:             $Branch"
Write-Host "Commit:             $RemoteCommit"
Write-Host "Destination:        $OutDir"
Write-Host ""

Write-Host "Remote files:       $($RemoteFiles.Count)"
Write-Host "Already current:    $Skipped"
Write-Host "New files:          $NewFiles"
Write-Host "Changed files:      $ChangedFiles"
Write-Host "Downloaded:         $Downloaded"
Write-Host "Removed:            $Removed"
Write-Host "Failed:             $Failed"
Write-Host ""

Write-Host "Local directories:  $($VectorDirectories.Count)"
Write-Host "Local JSON files:   $($VectorFiles.Count)"
Write-Host ""

if ($Failed -eq 0) {
Write-Host "Done." -ForegroundColor Green
}
else {
Write-Warning "Update completed with $Failed failed download(s)."
}
