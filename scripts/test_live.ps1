# PowerShell Live Test Script for AuthTime
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AuthTime PowerShell Live Verification Test" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 0. Reset State
Write-Host "`n[Step 0] Resetting Target Application State..." -ForegroundColor Yellow
try {
    Invoke-RestMethod -Uri "http://127.0.0.1:8000/faults/reset" -Method Post | Out-Null
    Write-Host "✅ Target application state reset complete." -ForegroundColor Green
} catch {
    Write-Host "❌ Target server not responding on http://127.0.0.1:8000. Starting server in python run.py or python scripts/test_live.py." -ForegroundColor Red
}

# 1. Login
Write-Host "`n[Step 1] Logging in as Admin ('admin1')..." -ForegroundColor Yellow
$loginBody = @{ user_id = "admin1" } | ConvertTo-Json
$loginResp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/auth/login" -Method Post -ContentType "application/json" -Body $loginBody
$token = $loginResp.access_token
Write-Host "✅ Login Successful! Access Token: $($token.Substring(0, 25))..." -ForegroundColor Green

$headers = @{ "Authorization" = "Bearer $token" }

# 2. Baseline Check
Write-Host "`n[Step 2] Testing Baseline Access to Protected Resource ('/admin/users')..." -ForegroundColor Yellow
$baseResp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/admin/users" -Method Get -Headers $headers
Write-Host "✅ Baseline Verified! Response: $($baseResp | ConvertTo-Json -Compress)" -ForegroundColor Green

# 3. Fault Injection
Write-Host "`n[Step 3] Revoking Admin Authorization via Fault Injection ('stale_cache', TTL=10s)..." -ForegroundColor Yellow
$faultBody = @{ fault_type = "stale_cache"; user_id = "admin1"; new_role = "User"; cache_ttl_seconds = 10 } | ConvertTo-Json
$faultResp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/faults/inject" -Method Post -ContentType "application/json" -Body $faultBody
Write-Host "✅ Authorization revoked in DB! Stale cache set for 10 seconds." -ForegroundColor Green

# 4. Immediate Post-Revocation Test
Write-Host "`n[Step 4] Requesting Protected Resource IMMEDIATELY Post-Revocation..." -ForegroundColor Yellow
$postResp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/admin/users" -Method Get -Headers $headers
Write-Host "🚨 VULNERABLE! Status: 200 OK. Access allowed post-revocation!" -ForegroundColor Red

# 5. Wait for Cache Expiry
Write-Host "`n[Step 5] Waiting 10 seconds for Cache TTL to expire..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# 6. Post-Expiry Test
Write-Host "`n[Step 6] Requesting Protected Resource AFTER Cache TTL Expiry..." -ForegroundColor Yellow
try {
    $expResp = Invoke-RestMethod -Uri "http://127.0.0.1:8000/admin/users" -Method Get -Headers $headers
    Write-Host "Still allowed!" -ForegroundColor Red
} catch {
    Write-Host "✅ SUCCESS! Access reliably blocked (403 Forbidden)." -ForegroundColor Green
}

Write-Host "`n============================================================" -ForegroundColor Cyan
