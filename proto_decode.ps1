# Decodificador de varint Protobuf
function Read-Varint {
    param([byte[]]$data, [int]$offset)
    $result = [uint64]0
    $shift = 0
    $bytesRead = 0
    do {
        if($offset + $bytesRead -ge $data.Length) { return @{Value=$result; BytesRead=$bytesRead} }
        $b = $data[$offset + $bytesRead]
        $result = $result -bor (([uint64]($b -band 0x7F)) -shl $shift)
        $shift += 7
        $bytesRead++
    } while(($b -band 0x80) -ne 0)
    return @{Value=$result; BytesRead=$bytesRead}
}

function Decode-Protobuf {
    param([byte[]]$data, [int]$offset=0, [int]$length=-1, [int]$depth=0)
    if($length -eq -1) { $length = $data.Length - $offset }
    $end = $offset + $length
    $indent = "  " * $depth
    $fieldCount = 0
    
    while($offset -lt $end -and $fieldCount -lt 30) {
        $tagResult = Read-Varint $data $offset
        $offset += $tagResult.BytesRead
        $tag = $tagResult.Value
        $fieldNumber = $tag -shr 3
        $wireType = $tag -band 7
        
        switch($wireType) {
            0 { # Varint
                $valResult = Read-Varint $data $offset
                $offset += $valResult.BytesRead
                Write-Host "${indent}Campo $fieldNumber (varint): $($valResult.Value)"
            }
            1 { # 64-bit fixed
                if($offset + 8 -le $end) {
                    $val = [BitConverter]::ToUInt64($data, $offset)
                    $offset += 8
                    Write-Host "${indent}Campo $fieldNumber (fixed64): $val (0x$($val.ToString('X16')))"
                } else { $offset = $end }
            }
            2 { # Length-delimited
                $lenResult = Read-Varint $data $offset
                $offset += $lenResult.BytesRead
                $len = [int]$lenResult.Value
                if($offset + $len -le $end) {
                    # Verifica se é texto legível
                    $isPrintable = $true
                    $sampleLen = [Math]::Min($len, 100)
                    for($j=0; $j -lt $sampleLen; $j++) {
                        $b = $data[$offset + $j]
                        if($b -lt 0x20 -and $b -ne 0x0a -and $b -ne 0x0d -and $b -ne 0x09) {
                            $isPrintable = $false; break
                        }
                    }
                    
                    if($isPrintable -and $len -gt 0 -and $len -lt 500) {
                        $str = [System.Text.Encoding]::UTF8.GetString($data, $offset, $len)
                        Write-Host "${indent}Campo $fieldNumber (string, $len bytes): '$str'"
                    } elseif($len -gt 0 -and $len -lt 200) {
                        # Tenta decodificar como protobuf aninhado
                        $firstByte = $data[$offset]
                        $subField = $firstByte -shr 3
                        $subWire = $firstByte -band 7
                        if($subField -ge 1 -and $subField -le 100 -and $subWire -le 5) {
                            Write-Host "${indent}Campo $fieldNumber (mensagem embutida, $len bytes):"
                            Decode-Protobuf $data $offset $len ($depth + 1)
                        } else {
                            $hex = ""
                            $showLen = [Math]::Min(32, $len)
                            for($j=0; $j -lt $showLen; $j++) { $hex += $data[$offset+$j].ToString("x2") + " " }
                            if($len -gt 32) { $hex += "..." }
                            Write-Host "${indent}Campo $fieldNumber (bytes, $len bytes): $hex"
                        }
                    } else {
                        $hex = ""
                        $showLen = [Math]::Min(32, $len)
                        for($j=0; $j -lt $showLen; $j++) { $hex += $data[$offset+$j].ToString("x2") + " " }
                        if($len -gt 32) { $hex += "..." }
                        Write-Host "${indent}Campo $fieldNumber (bytes, $len bytes): $hex"
                    }
                    $offset += $len
                } else { $offset = $end }
            }
            5 { # 32-bit fixed
                if($offset + 4 -le $end) {
                    $val = [BitConverter]::ToUInt32($data, $offset)
                    $offset += 4
                    Write-Host "${indent}Campo $fieldNumber (fixed32): $val (0x$($val.ToString('X8')))"
                } else { $offset = $end }
            }
            default {
                Write-Host "${indent}Campo $fieldNumber (wireType=$wireType desconhecido) - parando"
                $offset = $end
            }
        }
        $fieldCount++
    }
}

Write-Host "=== decodificando protobuf auth.bin ==="
$authBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\auth.bin")
Decode-Protobuf $authBytes

Write-Host ""
Write-Host "=== decodificando protobuf request_content.x-protobuf ==="
$protoBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\request_content.x-protobuf")
Decode-Protobuf $protoBytes

Write-Host ""
Write-Host "=== decodificando protobuf response_content.x-protobuf ==="
$respBytes = [System.IO.File]::ReadAllBytes("$PSScriptRoot\response_content.x-protobuf")
Decode-Protobuf $respBytes
