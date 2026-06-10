$basePath = $PSScriptRoot

$arquivos = [ordered]@{
    "auth.bin"                    = [System.IO.File]::ReadAllBytes("$basePath\auth.bin")
    "request_content.x-protobuf"  = [System.IO.File]::ReadAllBytes("$basePath\request_content.x-protobuf")
    "response_content.x-protobuf" = [System.IO.File]::ReadAllBytes("$basePath\response_content.x-protobuf")
}

# Exibe os primeiros bytes de um array em formato hexadecimal (16 por linha)
function Show-Hex {
    param([byte[]]$bytes, [int]$max = 64)

    $hex = ""
    for ($i = 0; $i -lt [Math]::Min($max, $bytes.Length); $i++) {
        $hex += $bytes[$i].ToString("x2") + " "
        if (($i + 1) % 16 -eq 0) { Write-Host "  $hex"; $hex = "" }
    }
    if ($hex) { Write-Host "  $hex" }
}

# Analisa se o array possui a estrutura VanguardHeader (32 bytes)
function Test-Cabecalho {
    param([byte[]]$bytes)

    if ($bytes.Length -ge 32) {
        $magic       = [BitConverter]::ToUInt32($bytes, 0)
        $totalSize   = [BitConverter]::ToUInt32($bytes, 4)
        $msgType     = [BitConverter]::ToUInt32($bytes, 8)
        $payloadSize = [BitConverter]::ToUInt32($bytes, 24)
        Write-Host "  magic=0x$($magic.ToString('X8')), tamanho_total=$totalSize, tipo_mensagem=$msgType, tamanho_payload=$payloadSize"
        $temHeader = if ($totalSize -gt 0 -and $totalSize -le $bytes.Length) { 'POSSIVEL' } else { 'IMPROVAVEL - payload bruto' }
        Write-Host "  Possui VanguardHeader: $temHeader"
    } else {
        Write-Host "  Pequeno demais para VanguardHeader"
    }
}

# Decodifica o primeiro byte no formato wire do protobuf
function Show-WireFormat {
    param([string]$nome, [byte[]]$bytes)

    $firstByte   = $bytes[0]
    $fieldNumber = $firstByte -shr 3
    $wireType    = $firstByte -band 0x07
    Write-Host "  primeiro byte de $nome : 0x$($firstByte.ToString('x2')) -> campo=$fieldNumber, wireType=$wireType"
    if ($wireType -le 5) {
        Write-Host "    Tipo wire valido"
    } else {
        Write-Host "    Tipo wire INVALIDO - o arquivo pode nao ser protobuf bruto"
    }
}

Write-Host "=== TAMANHOS DOS ARQUIVOS ==="
foreach ($nome in $arquivos.Keys) {
    Write-Host "$nome : $($arquivos[$nome].Length) bytes"
}

foreach ($nome in $arquivos.Keys) {
    Write-Host ""
    Write-Host "=== $nome - Primeiros 64 bytes em hex ==="
    Show-Hex $arquivos[$nome]
}

Write-Host ""
Write-Host "=== Analise do cabecalho de auth.bin ==="
Test-Cabecalho $arquivos["auth.bin"]

Write-Host ""
Write-Host "=== Analise do cabecalho de request_content.x-protobuf ==="
Test-Cabecalho $arquivos["request_content.x-protobuf"]

# Verifica se o protobuf comeca com formato wire valido
# Campo 1, wire tipo 0 (varint) = 0x08
# Campo 1, wire tipo 2 (delimitado por tamanho) = 0x0a
# Campo 2, wire tipo 0 = 0x10
# Campo 2, wire tipo 2 = 0x12
Write-Host ""
Write-Host "=== Verificacao do formato wire do Protobuf ==="
foreach ($nome in $arquivos.Keys) {
    Show-WireFormat $nome $arquivos[$nome]
}

# Procura a string "realsoninho" nos arquivos
Write-Host ""
Write-Host "=== Busca pela string 'realsoninho' ==="
foreach ($nome in $arquivos.Keys) {
    $texto = [System.Text.Encoding]::ASCII.GetString($arquivos[$nome])
    if ($texto.Contains("realsoninho")) {
        Write-Host "  ENCONTRADA em $nome !"
    } else {
        Write-Host "  NAO encontrada em $nome"
    }
}
