# Build local x64 release assets, create the next tag, and optionally publish it.
$ErrorActionPreference = "Stop"

$level = if ($env:usage_level) { $env:usage_level } else { "patch" }
if ($level -notin @("patch", "minor", "major")) {
    throw "level must be patch, minor, or major"
}
if (git status --porcelain) {
    throw "refusing to release a dirty worktree"
}

$current = git tag --list "v[0-9]*.[0-9]*.[0-9]*" --sort=-v:refname |
    Select-Object -First 1
if (-not $current) { $current = "v0.0.0" }
$parts = $current.TrimStart("v").Split(".")
$major = [int]$parts[0]
$minor = [int]$parts[1]
$patch = [int]$parts[2]
switch ($level) {
    "major" { $major++; $minor = 0; $patch = 0 }
    "minor" { $minor++; $patch = 0 }
    "patch" { $patch++ }
}
$next = "v$major.$minor.$patch"
$nextVersion = $next.TrimStart("v")
git rev-parse --verify --quiet "refs/tags/$next" *> $null
if ($LASTEXITCODE -eq 0) { throw "tag already exists: $next" }

$repoRoot = [IO.Path]::GetFullPath((git rev-parse --show-toplevel).Trim())
$manifestPath = Join-Path $repoRoot "Cargo.toml"
$manifest = [IO.File]::ReadAllText($manifestPath)
$versionPattern = [regex]'(?m)^version = "[^"]+"$'
if ($versionPattern.Matches($manifest).Count -ne 1) {
    throw "expected exactly one workspace package version in $manifestPath"
}
$updatedManifest = $versionPattern.Replace($manifest, "version = `"$nextVersion`"", 1)
[IO.File]::WriteAllText($manifestPath, $updatedManifest, [Text.UTF8Encoding]::new($false))

cargo metadata --format-version 1 --no-deps | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$releaseParent = [IO.Path]::GetFullPath((Join-Path $repoRoot "dist\local-release"))
$releaseRoot = [IO.Path]::GetFullPath((Join-Path $releaseParent $next))
if (-not $releaseRoot.StartsWith($releaseParent + [IO.Path]::DirectorySeparatorChar)) {
    throw "release output escaped its expected parent: $releaseRoot"
}
if (Test-Path -LiteralPath $releaseRoot) {
    Remove-Item -Recurse -Force -LiteralPath $releaseRoot
}
New-Item -ItemType Directory -Force -Path $releaseRoot | Out-Null

$windowsTarget = "x86_64-pc-windows-msvc"
cargo test --workspace --release --locked --target $windowsTarget
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cargo build --workspace --release --locked --target $windowsTarget
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$windowsReleaseBin = Join-Path $repoRoot "target\$windowsTarget\release"
foreach ($binary in @("lfp-pipe-ingress.exe", "lfp-pipe-client.exe")) {
    $reportedVersion = & (Join-Path $windowsReleaseBin $binary) --version
    if ($LASTEXITCODE -ne 0 -or $reportedVersion -notmatch " $([regex]::Escape($nextVersion))$") {
        throw "$binary reported '$reportedVersion'; expected $nextVersion"
    }
}

$windowsArchive = "lfp-pipe-$next-$windowsTarget"
$windowsDirectory = Join-Path $releaseRoot $windowsArchive
$windowsBin = Join-Path $windowsDirectory "bin"
New-Item -ItemType Directory -Force -Path $windowsBin | Out-Null
Copy-Item -LiteralPath (Join-Path $repoRoot "target\$windowsTarget\release\lfp-pipe-ingress.exe") -Destination $windowsBin
Copy-Item -LiteralPath (Join-Path $repoRoot "target\$windowsTarget\release\lfp-pipe-client.exe") -Destination $windowsBin
$windowsAsset = Join-Path $releaseRoot "$windowsArchive.zip"
Compress-Archive -Path $windowsDirectory -DestinationPath $windowsAsset
Remove-Item -Recurse -Force -LiteralPath $windowsDirectory

docker build --file Dockerfile.release --build-arg "RELEASE_TAG=$next" --output "type=local,dest=$releaseRoot" .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$linuxAsset = Join-Path $releaseRoot "lfp-pipe-$next-x86_64-unknown-linux-gnu.tar.gz"
if (-not (Test-Path -LiteralPath $linuxAsset)) {
    throw "Linux x64 release asset was not produced: $linuxAsset"
}

git add -- Cargo.toml Cargo.lock
git commit -m "Release $next"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

git tag -a $next -m "Release $next"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "created the $next release commit and tag from $current with local Windows and Linux x64 assets"

if ($env:usage_push -eq "true") {
    $head = (git rev-parse HEAD).Trim()
    $base = (git rev-parse HEAD^).Trim()
    $remoteMain = ((git ls-remote origin refs/heads/main) -split "\s+")[0]
    if ($base -ne $remoteMain) {
        throw "origin/main must point to the release commit's parent $base before publishing $next"
    }
    git push origin "${head}:refs/heads/main"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    git push origin $next
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    gh release create $next $windowsAsset $linuxAsset --draft --verify-tag --generate-notes --title $next
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    gh release edit $next --draft=false
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Output "published $next; GitHub Actions will build only missing release targets"
} else {
    Write-Output "local assets: $releaseRoot"
    Write-Output "publish with: mise run version:bump $level --push"
}
