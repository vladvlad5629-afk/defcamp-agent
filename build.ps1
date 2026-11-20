# Build the harness image and save it as <name>.tar, the file you upload.
#
#   powershell -ExecutionPolicy Bypass -File build.ps1              -> my-harness.tar
#   powershell -ExecutionPolicy Bypass -File build.ps1 -Name team-x -> team-x.tar
param([string]$Name = "my-harness")

$archive = Join-Path $PSScriptRoot "$Name.tar"

# Buildx produces an OCI layout on current Docker. Convert it to the legacy
# Docker archive expected by the competition loader (with `repositories`).
$ociArchive = Join-Path $PSScriptRoot "$Name.oci.tar"
docker buildx build --platform linux/amd64 --tag "${Name}:latest" --output "type=docker,dest=$ociArchive" (Join-Path $PSScriptRoot "harness")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if (Get-Command skopeo -ErrorAction SilentlyContinue) {
  skopeo copy "oci-archive:$ociArchive" "docker-archive:${archive}:${Name}:latest"
} else {
  docker run --rm -v "${PSScriptRoot}:/work" quay.io/skopeo/stable copy "oci-archive:/work/$Name.oci.tar" "docker-archive:/work/$Name.tar:${Name}:latest"
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Remove-Item -LiteralPath $ociArchive -Force
$entries = tar -tf $archive
if ($entries -notcontains "repositories") { throw "Legacy Docker archive was not produced" }
docker load --input $archive
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$size = (Get-Item $archive).Length
Write-Host ("wrote {0}.tar ({1} MB). Upload it on the Harnesses page." -f $Name, [math]::Floor($size / 1MB))
if ($size -gt 1GB) { Write-Warning "over the 1 GiB upload limit; try a smaller base image" }
