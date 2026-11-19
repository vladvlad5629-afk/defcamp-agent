# Build the harness image and save it as <name>.tar, the file you upload.
#
#   powershell -ExecutionPolicy Bypass -File build.ps1              -> my-harness.tar
#   powershell -ExecutionPolicy Bypass -File build.ps1 -Name team-x -> team-x.tar
param([string]$Name = "my-harness")

$archive = Join-Path $PSScriptRoot "$Name.tar"

# The event runs linux/amd64, whatever machine you build on.
docker build --platform linux/amd64 -t $Name (Join-Path $PSScriptRoot "harness")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker save -o $archive $Name
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$size = (Get-Item $archive).Length
Write-Host ("wrote {0}.tar ({1} MB). Upload it on the Harnesses page." -f $Name, [math]::Floor($size / 1MB))
if ($size -gt 1GB) { Write-Warning "over the 1 GiB upload limit; try a smaller base image" }
