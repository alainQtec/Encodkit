#!/usr/bin/env pwsh
#region    Classes

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
<#
.SYNOPSIS
    Base85 encoding
.DESCRIPTION
    A binary-to-text encoding scheme that uses 85 printable ASCII characters to represent binary data
.NOTES
    Not Workin9!!!
#>
class Base85 {
    [ValidateNotNullOrEmpty()] [string] $PrefixMark = "<~"; # Prefix mark that identifies an encoded ASCII85 string, traditionally '<~'
    [ValidateNotNullOrEmpty()] [string] $SuffixMark = "~>"; # Suffix mark that identifies an encoded ASCII85 string, traditionally '~>'
    [ValidateNotNull()] [int] $LineLength = 75; # Maximum line length for encoded ASCII85 string;
    [ValidateNotNull()] [bool] $EnforceMarks = $true; # Add the Prefix and Suffix marks when encoding, and enforce their presence for decoding
    hidden [ValidateNotNull()] [int] $_asciiOffset = 33;
    hidden [ValidateNotNull()] [byte[]] $_encodedBlock = [byte[]]::New(5);
    hidden [ValidateNotNull()] [byte[]] $_decodedBlock = [byte[]]::New(4);
    hidden [ValidateNotNull()] [uint] $_tuple = 0;
    hidden [ValidateNotNull()] [int] $_linePos = 0;
    hidden [ValidateNotNullOrEmpty()] [uint[]] $pow85 = ((85 * 85 * 85 * 85), (85 * 85 * 85), (85 * 85), 85, 1);

    Base85() {}

    [string] Encode([byte[]]$ba) {
        $sb = [System.Text.StringBuilder]::new([int]($ba.Length * ($this._encodedBlock.Length / $this._decodedBlock.Length)))
        $this._linePos = 0;
        if ($this.EnforceMarks) {
            $sb = $this.AppendString($this.PrefixMark, $sb)
        }
        [int]$count = 0; $this._tuple = 0;
        foreach ($byte in $ba) {
            if ($count -ge ($this._decodedBlock.Length - 1)) {
                $this._tuple = $this._tuple -bor $byte
                if ($this._tuple -eq 0) {
                    $sb = $this.AppendChar([char]'z', $sb)
                } else {
                    $sb = $this.EncodeBlock($sb)
                } ; $this._tuple = 0; $count = 0;
            } else {
                $this._tuple = $this._tuple -bor [uint]($byte -shl (24 - ($count * 8)))
                $count++
            }
        }
        # Check for left over bytes at the end.
        if ($count -gt 0) {
            $sb = $this.EncodeBlock(($count + 1), $sb)
        }
        if ($this.EnforceMarks) {
            $sb = $this.AppendString($this.SuffixMark, $sb)
        }
        $encodedString = $sb.ToString(); [void]$sb.Clear()
        return $encodedString
    }
    [byte[]] Decode([string]$text) {
        if ($this.EnforceMarks) {
            if (!$text.StartsWith($this.PrefixMark) -or !$text.EndsWith($this.SuffixMark)) {
                throw [System.IO.InvalidDataException]::New("Encoded data should begin with '" + $this.PrefixMark + "' and end with '" + $this.SuffixMark + "'")
            }
        }
        # strip prefix and suffix if present
        if ($text.StartsWith($this.PrefixMark)) {
            $text = $text.Substring($this.PrefixMark.Length)
        }
        if ($text.EndsWith($this.SuffixMark)) {
            $text = $text.Substring(0, $text.Length - ($this.SuffixMark.Length))
        }
        $ms = [System.IO.MemoryStream]::New();
        [int] $count = 0;
        [bool] $processChar = $false;
        foreach ($c in $text.ToCharArray()) {
            switch ($true) {
                ($c -eq [char]'z') {
                    if ($count -ne 0) { throw [Exception]::new("The character 'z' is invalid inside an ASCII85 block.") }
                    $this._decodedBlock[0] = 0;
                    $this._decodedBlock[1] = 0;
                    $this._decodedBlock[2] = 0;
                    $this._decodedBlock[3] = 0;
                    $ms.Write($this._decodedBlock, 0, $this._decodedBlock.Length);
                    $processChar = $false;
                    break;
                }
                ($c -in [char[]](0, 8, 9, 10, 13, 32, 58, 49824)) {
                    $processChar = $false
                    break
                }
                Default {
                    if ($c -lt '!' -or $c -gt 'u') {
                        throw [System.InvalidOperationException]::new("Base85 only allows characters '!' to 'u'.")
                    }
                    $processChar = $true;
                    break
                }
            }
            if ($processChar) {
                $this._tuple += [uint]($c - $this._asciiOffset) * $this.pow85[$count]; $count++
                if ($count -eq $this._encodedBlock.Length) {
                    $this.DecodeBlock();
                    $ms.Write($this._decodedBlock, 0, $this._decodedBlock.Length);
                    $this._tuple = 0; $count = 0;
                }
            }
        }
        # Check for left over bytes at the end.
        if ($count -ne 0) {
            if ($count -eq 1) {
                throw [System.Exception]::New("The last block of ASCII85 data cannot be a single byte.")
            }
            $count--; $this._tuple += $this.pow85[$count];
            $this.DecodeBlock($count);
            for ($i = 0; $i -lt $Count; $i++) {
                $ms.WriteByte($this._decodedBlock[$i])
            }
        }
        $decoded = $ms.ToArray()
        $ms.SetLength(0); $ms.Close();
        return $decoded
    }
    hidden [System.Text.StringBuilder] AppendChar([char]$c, [System.Text.StringBuilder]$sb) {
        [void]$sb.Append($c); $this._linePos++
        if ($this.LineLength -gt 0 -and ($this._linePos -ge $this.LineLength)) {
            $this._linePos = 0; [void]$sb.Append("`n");
        }
        return $sb
    }
    hidden [System.Text.StringBuilder] AppendString([string]$s, [System.Text.StringBuilder]$sb) {
        if ($this.LineLength -gt 0 -and ($this._linePos + $s.Length) -gt $this.LineLength) {
            $this._linePos = 0; $sb.Append("`n");
        } else {
            $this._linePos += $s.Length
        }
        [void]$sb.Append($s)
        return $sb
    }
    hidden [System.Text.StringBuilder] EncodeBlock([System.Text.StringBuilder]$sb) {
        return $this.EncodeBlock($this._encodedBlock.Count, $sb)
    }
    hidden [System.Text.StringBuilder] EncodeBlock([int]$count, [System.Text.StringBuilder]$sb) {
        if ($null -eq $sb) { throw 'StringBuilder was Not FOUND!' }
        for ($i = $this._encodedBlock.Length - 1; $i -ge 0; $i--) {
            $this._encodedBlock[$i] = [byte](($this._tuple % 85) + $this._asciiOffset)
            $this._tuple /= 85;
        }
        for ($i = 0; $i -lt $Count; $i++) {
            $c = [char]$this._encodedBlock[$i]; $this.AppendChar($c)
        }
        return $sb
    }
    hidden [void] DecodeBlock() { $this.DecodeBlock($this._decodedBlock.Length) }
    hidden [void] DecodeBlock([int]$count) { for ($i = 0; $i -lt $count; $i++) { $this._decodedBlock[$i] = [byte]($this._tuple -shr 24 - ($i * 8)) } }
}
class Base16 {
    Base16() {}
}
class Base32 {
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
        $builder = [System.Text.StringBuilder]::New($bytes.Length * $this.InByteSize / $this.OutByteSize);
        [int]$bytesPosition = 0;
        # Offset inside a single byte that points to (from left to right)
        # 0 - highest bit, 7 - lowest bit
        [int]$bytesSubPosition = 0;
        # Byte to look up in the dictionary
        [byte]$outputBase32Byte = 0;
        # // The number of bits filled in the current output byte
        [int]$outputBase32BytePosition = 0;
        # Iterate through input buffer until we reach past the end of it
        while ($bytesPosition -lt $bytes.Length) {
            # Calculate the number of bits we can extract out of current input byte to fill missing bits in the output byte
            $bitsAvailableInByte = [System.Math]::Min($this.InByteSize - $bytesPosition, $this.OutByteSize - $outputBase32BytePosition);
            # Make space in the output byte
            # $outputBase32Byte <<= $bitsAvailableInByte;
        }
        return ' ....'
    }
}

class Base36 {
    Base36() {
        $this.PsObject.properties.add([psscriptproperty]::new('alphabet', [scriptblock]::Create({ return "0123456789abcdefghijklmnopqrstuvwxyz" })))
    }
    [string] Encode([int]$decNum) {
        $base36Num = ''
        do {
            $remainder = ($decNum % 36)
            $char = $this.alphabet.substring($remainder, 1)
            $base36Num = '{0}{1}' -f $char, $base36Num
            $decNum = ($decNum - $remainder) / 36
        } while ($decNum -gt 0)
        return $base36Num
    }
    [long] Decode([string]$base36Num) {
        [ValidateNotNullOrEmpty()]$base36Num = $base36Num # Alphadecimal string
        $inputarray = $base36Num.tolower().tochararray()
        [array]::reverse($inputarray)
        [long]$decNum = 0; $pos = 0
        foreach ($c in $inputarray) {
            $decNum += $this.alphabet.IndexOf($c) * [long][Math]::Pow(36, $pos)
            $pos++
        }
        return $decNum
    }
}

class Base58 {
    Base58() {
        $this.PsObject.properties.add([psscriptproperty]::new('B58bytes', [scriptblock]::Create({ return [System.Text.Encoding]::ASCII.GetBytes('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz') })))
    }
    [string] Encode([string]$text) { return $this.Encode($text, $false) }
    [string] Encode([string]$text, [bool]$Ashexidecimal) {
        if ($Ashexidecimal) {
            # only when string is hexidecimal
            $binary_to_encode = [byte[]]::New($text.length / 2)
            for ($i = 0; $i -lt $text.length; $i += 2) {
                # todo: Fix / find another way to convert instead of static byte ToByte(string value, int fromBase)
                $binary_to_encode[$i / 2] = [Convert]::ToByte([string]$text.SubString($i, 2), [int]16)
            }
        } else {
            $binary_to_encode = [System.Text.Encoding]::ASCII.GetBytes($text)
        }
        $b58_size = 2 * ($binary_to_encode.length)
        $encoded = [byte[]]::New($b58_size)
        $leading_zeroes = [regex]::New("^(0*)").Match([string]::Join([string]::Empty, $binary_to_encode)).Groups[1].Length
        for ($i = 0; $i -lt $binary_to_encode.length; $i++) {
            [System.Numerics.BigInteger]$dec_char = $binary_to_encode[$i]
            for ($z = $b58_size; $z -gt 0; $z--) {
                $dec_char = $dec_char + (256 * $encoded[($z - 1)])
                $encoded[($z - 1)] = $dec_char % 58
                $dec_char = $dec_char / 58
            }
        }
        $mapped = [byte[]]::New($encoded.length)
        for ($i = 0; $i -lt $encoded.length; $i++) {
            $mapped[$i] = $this.B58bytes[$encoded[$i]]
        }
        $encoded_binary_string = [System.Text.Encoding]::ASCII.GetString($mapped) # [Microsoft.PowerShell.Commands.ByteCollection]::new($mapped).Ascii
        if ([regex]::New("(1{$leading_zeroes}[^1].*)").Match($encoded_binary_string).Success) {
            return [regex]::New("(1{$leading_zeroes}[^1].*)").Match($encoded_binary_string).Groups[1].Value
        } else {
            throw "error: " + $encoded_binary_string
        }
    }
    [string] Decode([string]$text) { return $this.Decode($text, $false) }
    [string] Decode([string]$text, [bool]$Ashexidecimal) {
        $leading_ones = [regex]::New("^(1*)").Match($text).Groups[1].Length
        $_bytes = [System.Text.Encoding]::ASCII.GetBytes($text)
        $mapped = [byte[]]::New($_bytes.length)
        for ($i = 0; $i -lt $_bytes.length; $i++) {
            $char = $_bytes[$i]
            $mapped[$i] = $this.B58bytes.IndexOf($char)
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

        if ($Ashexidecimal) {
            $decoded_hex_string = [string]::Join([string]::Empty, @($decoded.ForEach({ $_.ToString('x2') })))
            return $decoded_hex_string
        } else {
            $plaintext = [System.Text.Encoding]::ASCII.GetString($decoded)
            return $plaintext
        }
    }
}

class EncodKit {
    static [void] EncodeFile([string]$inFileName, [string]$outFileName) {
        [EncodKit]::EncodeFile($inFileName, $outFileName, $false)
    }
    static [void] EncodeFile([string]$inFileName, [string]$outFileName, [bool]$doReverse) {
        $encoder = [Base85]::New();
        $encoder.EnforceMarks = $false;
        $encoder.LineLength = 0;
        [byte[]]$ba = $null;
        [ValidateNotNullOrEmpty()][string]$inFileName = [IO.Path]::GetFullPath($inFileName)
        $streamReader = [System.IO.FileStream]::new($inFileName, [System.IO.FileMode]::Open)
        $ba = [byte[]]::New($streamReader.Length)
        [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
        [void]$streamReader.Close();
        $encodedString = $encoder.Encode($ba);
        # Write-Debug "File encoded in string of length '$($encodedString.Length)'" -Debug
        $encodedBytes = [System.Text.Encoding]::ASCII.GetBytes($encodedString);
        if ($doReverse) { [array]::Reverse($encodedBytes) }
        $streamWriter = [System.IO.FileStream]::new($outFileName, [System.IO.FileMode]::OpenOrCreate);
        [void]$streamWriter.Write($encodedBytes, 0, $encodedBytes.Length);
        [void]$streamWriter.Close()
    }
    static [void] DecodeFile([string]$inFileName, [string]$outFileName) {
        [EncodKit]::DecodeFile($inFileName, $outFileName, $false)
    }
    static [void] DecodeFile([string]$inFileName, [string]$outFileName, [bool]$doReverse) {
        $decoder = [Base85]::New()
        $decoder.EnforceMarks = $false;
        $decoder.LineLength = 0;
        [byte[]]$ba = $null;
        [ValidateNotNullOrEmpty()][string]$inFileName = [IO.Path]::GetFullPath($inFileName);
        $streamReader = [System.IO.FileStream]::new($inFileName, [System.IO.FileMode]::Open);
        [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
        [void]$streamReader.Close();
        if ($doReverse) { [array]::Reverse($ba) }
        $encodedString = [System.Text.Encoding]::ASCII.GetString($ba)
        $decodedString = $decoder.Decode($encodedString);
        # Write-Debug "Decoded file length $($decodedString.Length)" -Debug;
        $streamWriter = [System.IO.FileStream]::new($outFileName, [System.IO.FileMode]::OpenOrCreate);
        $streamWriter.Write($decodedString, 0, $decodedString.Length);
        $streamWriter.Close();
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