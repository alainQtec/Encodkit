#!/usr/bin/env pwsh
#region    Classes

enum EncodingName {
    Base85
    Base58
    Base16
}

# Binary-Coded Decimal (BCD) Encoding:
# This algorithm represents decimal digits with four bits, with each decimal digit encoded in its own four-bit code.
class BCD {
    BCD() {}
}

# Also known as reflected binary code, this encoding scheme assigns a unique binary code to each decimal number,
# such that only one bit changes between consecutive numbers.
class GrayCode {
}

# This algorithm assigns shorter binary codes to more frequently occurring characters in a message,
# and longer codes to less frequently occurring characters.
class Huffman {
}


# This is a coding scheme in which the transition of a signal from high to low represents a binary 1,
# and the transition from low to high represents a binary 0.
class Manchester {
}
class EncodingBase : System.Text.ASCIIEncoding {
    EncodingBase() {}
    static [byte[]] GetBytes([string] $text) {
        return [EncodingBase]::new().GetBytes($text)
    }
    static [string] GetString([byte[]]$bytes) {
        return [EncodingBase]::new().GetString($bytes)
    }
    static [char[]] GetChars([byte[]]$bytes) {
        return [EncodingBase]::new().GetChars($bytes)
    }
}
#region    Base85
# .SYNOPSIS
#     Base85 encoding
# .DESCRIPTION
#     A binary-to-text encoding scheme that uses 85 printable ASCII characters to represent binary data
# .EXAMPLE
#     $b = [System.Text.Encoding]::UTF8.GetBytes("Hello world")
#     [base85]::Encode($b)
#     [System.Text.Encoding]::UTF8.GetString([base85]::Decode("87cURD]j7BEbo7"))
class Base85 : EncodingBase {
    static [String] $NON_A85_Pattern = "[^\x21-\x75]"

    Base85() {}
    static [string] Encode([string]$text) {
        return [Base85]::Encode([Base85]::new().GetBytes($text), $false)
    }
    static [string] Encode([byte[]]$Bytes) {
        return [Base85]::Encode($Bytes, $false)
    }
    static [string] Encode([byte[]]$Bytes, [bool]$Format) {
        # Using Format means we'll add "<~" Prefix and "~>" Suffix marks to output text
        [System.IO.Stream]$InputStream = New-Object -TypeName System.IO.MemoryStream(,$Bytes)
        [System.Object]$Timer = [System.Diagnostics.Stopwatch]::StartNew()
        [System.Object]$BinaryReader = New-Object -TypeName System.IO.BinaryReader($InputStream)
        [System.Object]$Ascii85Output = New-Object -TypeName System.Text.StringBuilder
        if ($Format) {
            [void]$Ascii85Output.Append("<~")
            [System.UInt16]$LineLen = 2
        }
        $EncodedString = [string]::Empty
        Try {
            Write-Verbose "[base85] Encoding started at $([Datetime]::Now.Add($timer.Elapsed).ToString()) ..."
            While ([System.Byte[]]$BytesRead = $BinaryReader.ReadBytes(4)) {
                [System.UInt16]$ByteLength = $BytesRead.Length
                if ($ByteLength -lt 4) {
                    [System.Byte[]]$WorkingBytes = ,0x00 * 4
                    [System.Buffer]::BlockCopy($BytesRead,0,$WorkingBytes,0,$ByteLength)
                    [System.Array]::Resize([ref]$BytesRead,4)
                    [System.Buffer]::BlockCopy($WorkingBytes,0,$BytesRead,0,4)
                }
                if ([BitConverter]::IsLittleEndian) {
                    [Array]::Reverse($BytesRead)
                }
                [System.Char[]]$A85Chars = ,0x00 * 5
                [System.UInt32]$Sum = [BitConverter]::ToUInt32($BytesRead,0)
                [System.UInt16]$ByteLen = [Math]::Ceiling(($ByteLength / 4) * 5)
                if ($ByteLength -eq 4 -And $Sum -eq 0) {
                    [System.Char[]]$A85Chunk = "z"
                } else {
                    [System.Char[]]$A85Chunk = ,0x00 * $ByteLen
                    $A85Chars[0] = [Base85]::GetChars([Math]::Floor(($Sum / [Math]::Pow(85,4)) % 85) + 33)[0]
                    $A85Chars[1] = [Base85]::GetChars([Math]::Floor(($Sum / [Math]::Pow(85,3)) % 85) + 33)[0]
                    $A85Chars[2] = [Base85]::GetChars([Math]::Floor(($Sum / [Math]::Pow(85,2)) % 85) + 33)[0]
                    $A85Chars[3] = [Base85]::GetChars([Math]::Floor(($Sum / 85) % 85) + 33)[0]
                    $A85Chars[4] = [Base85]::GetChars([Math]::Floor($Sum % 85) + 33)[0]
                    [System.Array]::Copy($A85Chars,$A85Chunk,$ByteLen)
                }
                forEach ($A85Char in $A85Chunk) {
                    [void]$Ascii85Output.Append($A85Char)
                    if (!$Format) {
                        if ($LineLen -eq 64) {
                            [void]$Ascii85Output.Append("`r`n")
                            $LineLen = 0
                        } else {
                            $LineLen++
                        }
                    }
                }
            }
            if ($Format) {
                if ($LineLen -le 62) {
                    [void]$Ascii85Output.Append("~>")
                } else {
                    [void]$Ascii85Output.Append("~`r`n>")
                }
            }
            $EncodedString = $Ascii85Output.ToString()
        } catch {
            Write-Error "Exception: $($_.Exception.Message)"
            break;
        } finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $InputStream.Close()
            $InputStream.Dispose()
            $Timer.Stop()
            [String]$TimeLapse = "[base85] Encoding completed in $($Timer.Elapsed.Hours) hours, $($Timer.Elapsed.Minutes) minutes, $($Timer.Elapsed.Seconds) seconds, $($Timer.Elapsed.Milliseconds) milliseconds"
            Write-Verbose $TimeLapse
        }
        return $EncodedString
    }
    static [byte[]] Decode([string]$text) {
        $text = $text.Replace(" ","").Replace("`r`n","").Replace("`n","")
        $decoded = $null; if ($text.StartsWith("<~") -or $text.EndsWith("~>")) {
            $text = $text.Replace("<~","").Replace("~>","")
        }
        if ($text -match $([Base85]::NON_A85_Pattern)) {
            Throw "Invalid Ascii85 data detected in input stream."
        }
        [System.Object]$InputStream = New-Object -TypeName System.IO.MemoryStream([System.Text.Encoding]::ASCII.GetBytes($text),0,$text.Length)
        [System.Object]$BinaryReader = New-Object -TypeName System.IO.BinaryReader($InputStream)
        [System.Object]$OutputStream = New-Object -TypeName System.IO.MemoryStream
        [System.Object]$BinaryWriter = New-Object -TypeName System.IO.BinaryWriter($OutputStream)
        [System.Object]$Timer = [System.Diagnostics.Stopwatch]::StartNew()
        Try {
            Write-Verbose "[base85] Decoding started at $([Datetime]::Now.Add($timer.Elapsed).ToString()) ..."
            While ([System.Byte[]]$BytesRead = $BinaryReader.ReadBytes(5)) {
                [System.UInt16]$ByteLength = $BytesRead.Length
                if ($ByteLength -lt 5) {
                    [System.Byte[]]$WorkingBytes = ,0x75 * 5
                    [System.Buffer]::BlockCopy($BytesRead,0,$WorkingBytes,0,$ByteLength)
                    [System.Array]::Resize([ref]$BytesRead,5)
                    [System.Buffer]::BlockCopy($WorkingBytes,0,$BytesRead,0,5)
                }
                [System.UInt16]$ByteLen = [Math]::Floor(($ByteLength * 4) / 5)
                [System.Byte[]]$BinChunk = ,0x00 * $ByteLen
                if ($BytesRead[0] -eq 0x7A) {
                    $BinaryWriter.Write($BinChunk)
                    [bool]$IsAtEnd = ($BinaryReader.BaseStream.Length -eq $BinaryReader.BaseStream.Position)
                    if (!$IsAtEnd) {
                        $BinaryReader.BaseStream.Position = $BinaryReader.BaseStream.Position - 4
                        Continue
                    }
                } else {
                    [System.UInt32]$Sum = 0
                    $Sum += ($BytesRead[0] - 33) * [Math]::Pow(85,4)
                    $Sum += ($BytesRead[1] - 33) * [Math]::Pow(85,3)
                    $Sum += ($BytesRead[2] - 33) * [Math]::Pow(85,2)
                    $Sum += ($BytesRead[3] - 33) * 85
                    $Sum += ($BytesRead[4] - 33)
                    [System.Byte[]]$A85Bytes = [System.BitConverter]::GetBytes($Sum)
                    if ([BitConverter]::IsLittleEndian) {
                        [Array]::Reverse($A85Bytes)
                    }
                    [System.Buffer]::BlockCopy($A85Bytes,0,$BinChunk,0,$ByteLen)
                    $BinaryWriter.Write($BinChunk)
                }
            }
            $decoded = $OutputStream.ToArray()
        } catch {
            Write-Error "Exception: $($_.Exception.Message)"
            break
        } finally {
            $BinaryReader.Close()
            $BinaryReader.Dispose()
            $BinaryWriter.Close()
            $BinaryWriter.Dispose()
            $InputStream.Close()
            $InputStream.Dispose()
            $OutputStream.Close()
            $OutputStream.Dispose()
            $Timer.Stop()
            [String]$TimeLapse = "[base85] Decoding completed after $($Timer.Elapsed.Hours) hours, $($Timer.Elapsed.Minutes) minutes, $($Timer.Elapsed.Seconds) seconds, $($Timer.Elapsed.Milliseconds) milliseconds"
            Write-Verbose $TimeLapse
        }
        return $decoded
    }
}

#endregion Base85
class Base16 : EncodingBase {
    Base16() {}
}

# .SYNOPSIS
#     Base 32
# .EXAMPLE
#     $e = [Base32]::Encode("Hello world again!")
#     $d = [Base32]::GetString([Base32]::Decode($e))
#     ($d -eq "Hello world again!") -should be $true
class Base32 : EncodingBase {
    [int]$InByteSize = 8;
    [int]$OutByteSize = 5;
    [string]$Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    Base32() {}

    [string] ToBase32String([byte[]]$bytes) {
        if ($null -eq $bytes) {
            return $null
        } elseif ($bytes.Length -eq 0) {
            return [string]::Empty;
        }
        # $builder = [System.Text.StringBuilder]::New($bytes.Length * $this.InByteSize / $this.OutByteSize);
        # [int]$bytesPosition = 0;
        # Offset inside a single byte that points to (from left to right)
        # 0 - highest bit, 7 - lowest bit
        # [int]$bytesSubPosition = 0;
        # Byte to look up in the dictionary
        # [byte]$outputBase32Byte = 0;
        # // The number of bits filled in the current output byte
        # [int]$outputBase32BytePosition = 0;
        # Iterate through input buffer until we reach past the end of it
        # while ($bytesPosition -lt $bytes.Length) {
        #     Calculate the number of bits we can extract out of current input byte to fill missing bits in the output byte
        #     $bitsAvailableInByte = [System.Math]::Min($this.InByteSize - $bytesPosition, $this.OutByteSize - $outputBase32BytePosition);
        #     Make space in the output byte
        #     $outputBase32Byte <<= $bitsAvailableInByte;
        # }
        return ' ....'
    }
}

class Base36 : EncodingBase {
    static [string] $alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

    static [string] Encode([int]$decNum) {
        $base36Num = ''
        do {
            $remainder = ($decNum % 36)
            $char = [Base36]::alphabet.substring($remainder, 1)
            $base36Num = '{0}{1}' -f $char, $base36Num
            $decNum = ($decNum - $remainder) / 36
        } while ($decNum -gt 0)
        return $base36Num
    }
    static [long] Decode([int]$base36Num) {
        [ValidateNotNullOrEmpty()]$base36Num = $base36Num # Alphadecimal string
        $inputarray = $base36Num.tolower().tochararray()
        [array]::reverse($inputarray)
        [long]$decNum = 0; $pos = 0
        foreach ($c in $inputarray) {
            $decNum += [Base36]::alphabet.IndexOf($c) * [long][Math]::Pow(36, $pos)
            $pos++
        }
        return $decNum
    }
}


# .SYNOPSIS
#     Base 58
# .EXAMPLE
#     $e = [Base58]::Encode("Hello world!!")
#     $d = [Base58]::GetString([Base58]::Decode($e))
#     ($d -eq "Hello world!!") -should be $true
class Base58 : EncodingBase {
    static [byte[]] $Bytes = [Base58]::GetBytes('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
    static [string] Encode([string]$text) {
        return [Base58]::Encode([System.Text.Encoding]::ASCII.GetBytes($text))
    }
    static [string] Encode([byte[]]$ba) {
        $b58_size = 2 * ($ba.length)
        $encoded = [byte[]]::New($b58_size)
        $leading_zeroes = [regex]::New("^(0*)").Match([string]::Join([string]::Empty, $ba)).Groups[1].Length
        for ($i = 0; $i -lt $ba.length; $i++) {
            [System.Numerics.BigInteger]$dec_char = $ba[$i]
            for ($z = $b58_size; $z -gt 0; $z--) {
                $dec_char = $dec_char + (256 * $encoded[($z - 1)])
                $encoded[($z - 1)] = $dec_char % 58
                $dec_char = $dec_char / 58
            }
        }
        $mapped = [byte[]]::New($encoded.length)
        for ($i = 0; $i -lt $encoded.length; $i++) {
            $mapped[$i] = [Base58]::Bytes[$encoded[$i]]
        }
        $encoded_binary_string = [System.Text.Encoding]::ASCII.GetString($mapped) # [Microsoft.PowerShell.Commands.ByteCollection]::new($mapped).Ascii
        if ([regex]::New("(1{$leading_zeroes}[^1].*)").Match($encoded_binary_string).Success) {
            return [regex]::New("(1{$leading_zeroes}[^1].*)").Match($encoded_binary_string).Groups[1].Value
        } else {
            throw "error: " + $encoded_binary_string
        }
    }
    static [byte[]] Decode([string]$text) {
        $leading_ones = [regex]::New("^(1*)").Match($text).Groups[1].Length
        $_bytes = [System.Text.Encoding]::ASCII.GetBytes($text)
        $mapped = [byte[]]::New($_bytes.length)
        for ($i = 0; $i -lt $_bytes.length; $i++) {
            $char = $_bytes[$i]
            $mapped[$i] = [Base58]::Bytes.IndexOf($char)
        }
        $decoded = [byte[]]::New($_bytes.length)
        for ($i = 0; $i -lt $mapped.length; $i++) {
            [System.Numerics.BigInteger]$b58_char = $mapped[$i]
            for ($z = $_bytes.length; $z -gt 0; $z--) {
                $b58_char = $b58_char + (58 * [Int32]::Parse($decoded[($z - 1)].ToString()))
                $decoded[($z - 1)] = $b58_char % 256
                $b58_char = $b58_char / 256
            }
        }
        $leading_zeroes = [regex]::New("^(0*)").Match([string]::Join([string]::Empty, $decoded)).Groups[1].Length
        $(1..($leading_zeroes - $leading_ones)).ForEach({
                $decoded = $decoded[1..($decoded.Length - 1)]
            }
        )
        return $decoded
        # hex_string can be: [string]::Join([string]::Empty, @($decoded.ForEach({ $_.ToString('x2') })))
    }
}

# .SYNOPSIS
#     Main Class. Encodes/decodes files. By default it uses base 85 encoding.
# .EXAMPLE
#     "some R4ndom text 123`n`t`n432`n!@#$%$ ..." | Out-File file1.txt
#     $file = Get-Item file1.txt
#     [EncodKit]::EncodeFile($file.FullName, $false, "file2.txt")
#     [EncodKit]::DecodeFile("file2.txt")
#     Now contents of file2.txt should be the same as those of file1.txt
class EncodKit {
    static [EncodingName] $DefaultEncoding = 'Base85'

    static [void] EncodeFile([string]$FilePath) {
        [EncodKit]::EncodeFile($FilePath, $false, $FilePath);
    }
    static [void] EncodeFile([string]$FilePath, [bool]$obfuscate, [string]$OutFile) {
        [EncodKit]::EncodeFile($FilePath, $obfuscate, $OutFile, [EncodKit]::DefaultEncoding)
    }
    static [void] EncodeFile([string]$FilePath, [bool]$obfuscate, [string]$OutFile, [EncodingName]$encoding) {
        [byte[]]$ba = $null;
        [ValidateNotNullOrEmpty()][string]$FilePath = [IO.Path]::GetFullPath($FilePath)
        $streamReader = [System.IO.FileStream]::new($FilePath, [System.IO.FileMode]::Open)
        $ba = [byte[]]::New($streamReader.Length)
        [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
        [void]$streamReader.Close();
        $encodedString = $(switch ($encoding.ToString()) {
                'Base85' { [Base85]::Encode($ba) }
                'Base58' { [Base58]::Encode($ba) }
                'Base32' {}
                'Base16' {}
                Default {
                    [Base85]::Encode($ba)
                }
            }
        )
        $encodedBytes = [EncodKit]::GetBytes($encodedString);
        if ($obfuscate) { [array]::Reverse($encodedBytes) }
        $streamWriter = [System.IO.FileStream]::new($OutFile, [System.IO.FileMode]::OpenOrCreate);
        [void]$streamWriter.Write($encodedBytes, 0, $encodedBytes.Length);
        [void]$streamWriter.Close()
    }
    static [void] DecodeFile([string]$FilePath) {
        [EncodKit]::DecodeFile($FilePath, $false, $FilePath);
    }
    static [void] DecodeFile([string]$FilePath, [bool]$obfuscate, [string]$OutFile) {
        [EncodKit]::DecodeFile($FilePath, $obfuscate, $OutFile, [EncodKit]::DefaultEncoding)
    }
    static [void] DecodeFile([string]$FilePath, [bool]$deObfuscate, [string]$OutFile, [EncodingName]$encoding) {
        [byte[]]$ba = $null;
        [ValidateNotNullOrEmpty()][string]$FilePath = [IO.Path]::GetFullPath($FilePath);
        $streamReader = [System.IO.FileStream]::new($FilePath, [System.IO.FileMode]::Open);
        [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
        [void]$streamReader.Close();
        if ($deObfuscate) { [array]::Reverse($ba) }
        $encodedString = [EncodKit]::GetString($ba)
        $decodedString = [EncodKit]::GetString($(switch ($encoding.ToString()) {
                    'Base85' { [Base85]::Decode($encodedString) }
                    'Base58' { [Base58]::Decode($encodedString) }
                    'Base32' {}
                    'Base16' {}
                    Default {
                        [Base85]::Decode($encodedString)
                    }
                }
            )
        )
        $streamWriter = [System.IO.FileStream]::new($OutFile, [System.IO.FileMode]::OpenOrCreate);
        $streamWriter.Write($decodedString, 0, $decodedString.Length);
        $streamWriter.Close();
    }
    static [byte[]] GetBytes([string]$text) {
        return [EncodingBase]::new().GetBytes($text)
    }
    static [string] GetString([byte[]]$bytes) {
        return [EncodingBase]::new().GetString($bytes)
    }
}
#endregion Classes


$Private = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -Filter "*.ps1" -ErrorAction SilentlyContinue
$Public = Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Public')) -Filter "*.ps1" -ErrorAction SilentlyContinue
# Load dependencies
$PrivateModules = [string[]](Get-ChildItem ([IO.Path]::Combine($PSScriptRoot, 'Private')) -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | Select-Object -ExpandProperty FullName)
if ($PrivateModules.Count -gt 0) {
    foreach ($Module in $PrivateModules) {
        Try {
            Import-Module $Module -ErrorAction Stop
        } Catch {
            Write-Error "Failed to import module $Module : $_"
        }
    }
}
# Dot source the files
foreach ($Import in ($Public + $Private)) {
    Try {
        . $Import.fullname
    } Catch {
        Write-Warning "Failed to import function $($Import.BaseName): $_"
        $host.UI.WriteErrorLine($_)
    }
}
# Export Public Functions
$Public | ForEach-Object { Export-ModuleMember -Function $_.BaseName }
Export-ModuleMember -Alias @('<Aliases>')