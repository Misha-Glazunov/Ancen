# Ежедневный бэкап БД: mysqldump внутри контейнера -> gzip -> AES-256 шифрование ->
# заливка в MinIO (бакет ancen-backups). Пароль MySQL не покидает контейнер mysql
# (уже есть в его окружении из deploy/mysql/.env), пароль MinIO берётся из
# deploy/minio/.env через --env-file. BACKUP_ENCRYPTION_PASSWORD — отдельная
# машинная переменная окружения (setx /M), не хранится в репозитории.
#
# ponytail: без ретеншна/автоочистки старых бэкапов в MinIO — увеличить, если
# место в MinIO станет проблемой (см. 16_Текущий_статус.md).
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$workDir = Join-Path $root "deploy\backup\tmp"
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$dumpFile = "ancen-$timestamp.sql.gz"
$encFile = "$dumpFile.enc"
$containerTmp = "/tmp/$dumpFile"

Write-Host "Dumping database..."
docker exec ancen-mysql-1 sh -c "mysqldump -uroot -p`"`$MYSQL_ROOT_PASSWORD`" ancen | gzip -c > $containerTmp"
docker cp "ancen-mysql-1:$containerTmp" (Join-Path $workDir $dumpFile)
docker exec ancen-mysql-1 rm $containerTmp

Write-Host "Encrypting..."
docker run --rm -e BACKUP_ENCRYPTION_PASSWORD -v "${workDir}:/data" alpine:3.20 sh -c `
    "apk add --no-cache openssl >/dev/null 2>&1 && openssl enc -aes-256-cbc -pbkdf2 -salt -in /data/$dumpFile -out /data/$encFile -pass env:BACKUP_ENCRYPTION_PASSWORD"
Remove-Item (Join-Path $workDir $dumpFile)

Write-Host "Uploading to MinIO..."
docker run --rm --entrypoint sh --network ancen_default --env-file "$root\deploy\minio\.env" -v "${workDir}:/data" minio/mc -c `
    "mc alias set local http://minio:9000 `$MINIO_ROOT_USER `$MINIO_ROOT_PASSWORD >/dev/null && mc mb --ignore-existing local/ancen-backups >/dev/null && mc cp /data/$encFile local/ancen-backups/$encFile"
Remove-Item (Join-Path $workDir $encFile)

Write-Host "Backup done: $encFile"
