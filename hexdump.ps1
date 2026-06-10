$authBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\auth.bin")
Write-Host "=== auth.bin ==="
Write-Host "Tamanho: $($authBytes.Length) bytes"
Write-Host "Primeiros 160 bytes:"
$hex = ""
for($i=0; $i -lt [Math]::Min(160,$authBytes.Length); $i++) {
    $hex += $authBytes[$i].ToString("x2") + " "
    if(($i+1) % 16 -eq 0){ Write-Host $hex; $hex="" }
}
if($hex){ Write-Host $hex }

Write-Host ""
Write-Host "Últimos 64 bytes:"
$hex = ""
$start = [Math]::Max(0, $authBytes.Length - 64)
for($i=$start; $i -lt $authBytes.Length; $i++) {
    $hex += $authBytes[$i].ToString("x2") + " "
    if(($i - $start + 1) % 16 -eq 0){ Write-Host $hex; $hex="" }
}
if($hex){ Write-Host $hex }

# Verifica por strings legíveis (UUIDs, URLs, etc)
Write-Host ""
Write-Host "=== Strings legíveis em auth.bin ==="
$text = [System.Text.Encoding]::ASCII.GetString($authBytes)
$matches = [regex]::Matches($text, '[\x20-\x7E]{4,}')
foreach($m in $matches) {
    Write-Host "  offset=$($m.Index): '$($m.Value)'"
}

Write-Host ""
Write-Host "=== request_content.x-protobuf ==="
$protoBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\request_content.x-protobuf")
Write-Host "Tamanho: $($protoBytes.Length) bytes"
Write-Host "Primeiros 160 bytes:"
$hex = ""
for($i=0; $i -lt [Math]::Min(160,$protoBytes.Length); $i++) {
    $hex += $protoBytes[$i].ToString("x2") + " "
    if(($i+1) % 16 -eq 0){ Write-Host $hex; $hex="" }
}
if($hex){ Write-Host $hex }

Write-Host ""
Write-Host "=== Strings legíveis em request_content.x-protobuf ==="
$text2 = [System.Text.Encoding]::ASCII.GetString($protoBytes)
$matches2 = [regex]::Matches($text2, '[\x20-\x7E]{4,}')
foreach($m in $matches2) {
    Write-Host "  offset=$($m.Index): '$($m.Value)'"
}

Write-Host ""
Write-Host "=== response_content.x-protobuf ==="
$respBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\response_content.x-protobuf")
Write-Host "Tamanho: $($respBytes.Length) bytes"
Write-Host "Primeiros 160 bytes:"
$hex = ""
for($i=0; $i -lt [Math]::Min(160,$respBytes.Length); $i++) {
    $hex += $respBytes[$i].ToString("x2") + " "
    if(($i+1) % 16 -eq 0){ Write-Host $hex; $hex="" }
}
if($hex){ Write-Host $hex }

Write-Host ""
Write-Host "=== Strings legíveis em response_content.x-protobuf ==="
$text3 = [System.Text.Encoding]::ASCII.GetString($respBytes)
$matches3 = [regex]::Matches($text3, '[\x20-\x7E]{4,}')
foreach($m in $matches3) {
    Write-Host "  offset=$($m.Index): '$($m.Value)'"
}
