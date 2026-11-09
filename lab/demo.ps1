# Boot the VulnShop lab in Docker, scan it with the two lab accounts, and write report.html.
# Run from the repository root with the virtual environment active:  powershell -File lab/demo.ps1
$ErrorActionPreference = "Stop"
docker compose up -d --build --wait
if ($LASTEXITCODE -ne 0) { throw "docker compose failed; is Docker Desktop running?" }

# Lab-only accounts, set just for this scan.
$env:APIFUZZ_USER_A = "alice"; $env:APIFUZZ_PASSWORD_A = "alice"
$env:APIFUZZ_USER_B = "bob";   $env:APIFUZZ_PASSWORD_B = "bob"
try {
    apifuzz scan http://localhost:8000/openapi.json --i-have-authorization --require-docker --html report.html --fail-on never
} finally {
    Remove-Item Env:APIFUZZ_USER_A, Env:APIFUZZ_PASSWORD_A, Env:APIFUZZ_USER_B, Env:APIFUZZ_PASSWORD_B
}
Write-Host "Open report.html to see the findings. Stop the lab with: docker compose down"
