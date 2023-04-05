#!/usr/bin/env pwsh
#region    Classes
class Encodkit {
    static [long]$n = 0
    static [byte[]] $b85 = [byte[]]::New(85);
    static [int[]] $p85 = (52200625, 614125, 7225, 85, 1);
    static [string] $a85 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$&()+,-./;=?@[]^_{|}~";

    Encodkit() {}
    static [byte[]] n4b() {
        $_n = [Encodkit]::n
        return [byte[]](($_n -shr 24), ($_n -shl 16), ($_n -shl 8), $_n)
    }
    static [byte[]] n5b() {
        $k = [byte[]]::New(5); for ($i = 0; $i -lt 5; $i++) {
            $k[4 - $i] = [byte][Encodkit]::b85[[int][byte]([Encodkit]::n % 85)]
            [Encodkit]::n /= 85
        }
        return $k
    }
    static [void] Encode() {}
    static [void] Decode([string]$EncodedString, [string]$OutFile) {}

    static [string] Compress([string]$text) { return [Encodkit]::Compress($text, $false, $false) }
    static [string] Compress([string]$text, [bool]$bLines, [bool]$bPrefix) {
        [int]$l = 0; [int]$p = 0; $ms = [System.IO.MemoryStream]::new(); [Encodkit]::n = 0;
        for ($i = 0; $i -lt ([Encodkit]::b85.Count); $i++) { [Encodkit]::b85[$i] = [byte][Encodkit]::a85[$i] }
        $SOL = [byte[]](0x3A, 0x3A); $EOL = [byte[]](0xA);
        $textBytes = [System.Text.Encoding]::UTF8.GetBytes($text)
        foreach ($byte in $textBytes) {
            if ($bLines) {
                if ($bPrefix -and $l -eq 1) { [void]$ms.Write($SOL, 0, 2) }
                if ($l -eq 101) { [void]$ms.Write($EOL, 0, 1); $l = 0 }
                $l++
            }
            if ($p -eq 3) {
                [Encodkit]::n = [Encodkit]::n -bor $byte
                $ms.Write([Encodkit]::n5b(), 0, 5)
                [Encodkit]::n = 0; $p = 0
            } else {
                [Encodkit]::n = [Encodkit]::n -bor [uint]($byte -shl (24 - ($p * 8)))
                $p++
            }
            if ($bLines -and ([Encodkit]::n -eq 0) -and $l -lt 99) {
                $ms.Write($EOL, 0, 1); $l = 0
            }
        }
        if ($p -gt 0) {
            for ($i = $p; $i -lt 3 - $p; $i++) {
                [Encodkit]::n = [Encodkit]::n -bor [uint](0 -shl (24 - ($p * 8)))
            }
            [Encodkit]::n = [Encodkit]::n -bor 0
            [void]$ms.Write([Encodkit]::n5b(), 0, $p + 1)
        }
        $c = [System.Text.Encoding]::UTF8.GetString($ms.ToArray()); $ms.SetLength(0);
        return $c
    }
    static [string[]] Compress([IO.FileInfo]$file, [string]$OutFile, [bool]$bLines, [bool]$bPrefix) {
        if (!$file.Exists) { throw [System.IO.FileNotFoundException]::New($file.FullName) }; $filename = $file.BaseName
        $c = [Encodkit]::Compress([IO.File]::ReadAllText($file.FullName), $bLines, $bPrefix)
        $b = [System.Text.Encoding]::UTF8.GetBytes($c); [Encodkit]::n = 0;
        $m = [System.Text.Encoding]::UTF8.GetBytes("`r`n" + $filename + ": " + $filename + "`r`n")
        $fs = [System.IO.FileStream]::new($OutFile, [System.IO.FileMode]::Append)
        $fs.Write($m, 0, $m.Length); $fs.Write($b, 0, [int]$b.Length);
        return [IO.File]::ReadAllLines($OutFile, [System.Text.Encoding]::UTF8)
    }
    static [string[]] Decompress([string]$Compresed) {
        [Encodkit]::b85 = [byte[]]::New(255); $ms = [System.IO.MemoryStream]::New(); [Encodkit]::n = 0;
        for ($i = 0; $i -lt 85; $i++) {
            [Encodkit]::b85[[int][Encodkit]::a85[$i]] = $i
        }
        $k = $false; $p = 0
        foreach ($c in $Compresed.ToCharArray()) {
            $k = $c -notin [char[]](0, 8, 9, 10, 13, 32, 58, 49824)
            if ($k) {
                [Encodkit]::n += [Encodkit]::b85[[int][byte]$c] * ([Encodkit]::p85[$p++])
                if ($p -eq 5) {
                    $ms.Write([Encodkit]::n4b(), 0, 4); [Encodkit]::n = 0; $p = 0
                }
            }
        }
        if ($p -gt 0) {
            for ($i = 0; $i -lt 5 - $p; $i++) { [Encodkit]::n += 84 * [Encodkit]::p85[$p + $i] }
            $ms.Write([Encodkit]::n4b(), 0, $p - 1)
        }
        $d = [System.Text.Encoding]::UTF8.GetString($ms.ToArray()); $ms.SetLength(0);
        return $d
    }
    static [string[]] Decompress([string]$Compresed, [string]$OutFile) {
        [IO.File]::WriteAllBytes($OutFile, [System.Text.Encoding]::UTF8.GetBytes([Encodkit]::Decompress($Compresed)));
        return [IO.File]::ReadAllLines($OutFile)
    }
}
#endregion Classes
<#
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
#Export-ModuleMember -Alias @('<Aliases>')
#>