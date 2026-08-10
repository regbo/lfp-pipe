# Windows implementation for the mise version:bump task. Mise supplies parsed
# task arguments through usage_* environment variables.
$ErrorActionPreference = "Stop"

$level = if ($env:usage_level) { $env:usage_level } else { "patch" }
if ($level -notin @("patch", "minor", "major")) {
    throw "level must be patch, minor, or major"
}

if (git status --porcelain) {
    throw "refusing to tag a dirty worktree"
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
git rev-parse --verify --quiet "refs/tags/$next" *> $null
if ($LASTEXITCODE -eq 0) { throw "tag already exists: $next" }

git tag -a $next -m "Release $next"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "created $next from $current"
if ($env:usage_push -eq "true") {
    git push origin $next
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    Write-Output "push with: git push origin $next"
}
