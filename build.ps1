# Build the harness image and save it as <name>.tar, the file you upload.
#
#   powershell -ExecutionPolicy Bypass -File build.ps1              -> my-harness.tar
#   powershell -ExecutionPolicy Bypass -File build.ps1 -Name team-x -> team-x.tar
param([string]$Name = "my-harness")

$archive = Join-Path $PSScriptRoot "$Name.tar"

# Export a Docker image archive explicitly. Recent Docker/containerd stores
# can make docker save emit OCI layouts, which the event loader rejects.
docker buildx build --platform linux/amd64 --tag "${Name}:latest" --output "type=docker,dest=$archive" (Join-Path $PSScriptRoot "harness")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$entries = tar -tf $archive
if ($entries -contains "oci-layout") { throw "OCI archive produced; expected Docker image archive" }

$size = (Get-Item $archive).Length
Write-Host ("wrote {0}.tar ({1} MB). Upload it on the Harnesses page." -f $Name, [math]::Floor($size / 1MB))
if ($size -gt 1GB) { Write-Warning "over the 1 GiB upload limit; try a smaller base image" }
