# Script de test API RansomGuard
$baseUrl = "http://localhost:8000"

Write-Host "=== Test API RansomGuard ===" -ForegroundColor Cyan

# 1. Vérifier le statut du système
Write-Host "`n[1] Statut du système:" -ForegroundColor Yellow
$status = Invoke-RestMethod "$baseUrl/api/status"
Write-Host "Statut: $($status.status)"
Write-Host "Menaces détectées: $($status.threats_detected)"
Write-Host "Fichiers protégés: $($status.files_protected)"

# 2. Voir les menaces actuelles
Write-Host "`n[2] Menaces détectées:" -ForegroundColor Yellow
$threats = Invoke-RestMethod "$baseUrl/api/threats"
Write-Host "Nombre total de menaces: $($threats.count)"
if ($threats.threats.Count -gt 0) {
    Write-Host "`nDétails des menaces:"
    $threats.threats | ForEach-Object {
        Write-Host "  - Type: $($_.type), Sévérité: $($_.severity), Fichier: $($_.file_path)"
    }
}

# 3. Lancer un scan de test
Write-Host "`n[3] Lancement d'un scan rapide:" -ForegroundColor Yellow
$scanBody = @{
    scan_type = "quick"
    use_advanced_detection = $true
} | ConvertTo-Json

$scanResult = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/scan" -ContentType "application/json" -Body $scanBody
Write-Host "Scan démarré - ID: $($scanResult.scan_id)"

# 4. Suivre le progrès du scan
Write-Host "`n[4] Progression du scan:" -ForegroundColor Yellow
$maxAttempts = 10
$attempt = 0
do {
    Start-Sleep -Seconds 2
    $scanStatus = Invoke-RestMethod "$baseUrl/api/scan/status/$($scanResult.scan_id)"
    Write-Host "Progrès: $($scanStatus.progress)% - Fichiers scannés: $($scanStatus.files_scanned) - Menaces: $($scanStatus.threats_found)"
    $attempt++
} while ($scanStatus.status -eq "running" -and $attempt -lt $maxAttempts)

# 5. Test d'analyse de fichier
Write-Host "`n[5] Test d'analyse de fichier suspect:" -ForegroundColor Yellow
$testFile = "test_malware.txt"
"This is a test file with suspicious content: ransomware encrypt bitcoin payment" | Out-File $testFile

# Créer un fichier multipart pour l'upload
$boundary = [System.Guid]::NewGuid().ToString()
$fileContent = Get-Content $testFile -Raw
$body = @"
--$boundary
Content-Disposition: form-data; name="file"; filename="$testFile"
Content-Type: text/plain

$fileContent
--$boundary--
"@

try {
    $headers = @{
        "Content-Type" = "multipart/form-data; boundary=$boundary"
    }
    $analysisResult = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/analyze/file" -Headers $headers -Body $body
    Write-Host "Résultat de l'analyse:"
    Write-Host "  - Est une menace: $($analysisResult.is_ransomware)"
    Write-Host "  - Confiance: $([math]::Round($analysisResult.confidence * 100, 2))%"
    Write-Host "  - Type: $($analysisResult.threat_type)"
    Write-Host "  - Sévérité: $($analysisResult.severity)"
} catch {
    Write-Host "Erreur lors de l'analyse du fichier: $_" -ForegroundColor Red
}

# 6. Test d'éradication (dry-run)
Write-Host "`n[6] Test d'éradication (mode simulation):" -ForegroundColor Yellow
$eradicationBody = @{
    scope = @{
        hosts = @("localhost")
        paths = @($PWD.Path)
    }
    actions = @("kill_processes", "quarantine_files")
    dry_run = $true
    min_confidence = 0.6
} | ConvertTo-Json -Depth 3

try {
    $eradicationResult = Invoke-RestMethod -Method Post -Uri "$baseUrl/api/eradications" -ContentType "application/json" -Body $eradicationBody
    Write-Host "Résultats de la simulation d'éradication:"
    Write-Host "  - Fichiers évalués: $($eradicationResult.stats.files_evaluated)"
    Write-Host "  - Fichiers à mettre en quarantaine: $($eradicationResult.stats.files_to_quarantine)"
    Write-Host "  - Processus à terminer: $($eradicationResult.stats.processes_to_kill)"
} catch {
    Write-Host "Erreur lors de l'éradication: $_" -ForegroundColor Red
}

# Nettoyage
Remove-Item $testFile -ErrorAction SilentlyContinue

Write-Host "`n=== Test terminé ===" -ForegroundColor Green
Write-Host "Visitez http://localhost:8000/docs pour plus de tests interactifs" -ForegroundColor Cyan
