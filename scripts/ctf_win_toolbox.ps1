# CTF 零安装工具箱（Windows PowerShell 5.1 / 机房机器适用）
#
# 现场不能装东西、不一定有 Python 时用它顶替 binwalk / strings / zsteg / xxd：
#
#   powershell -ExecutionPolicy Bypass -File ctf-win.ps1 info     .\x
#   powershell -ExecutionPolicy Bypass -File ctf-win.ps1 strings  .\x -pat 'flag|ctf'
#   powershell -ExecutionPolicy Bypass -File ctf-win.ps1 carve    .\x -out .\out
#   powershell -ExecutionPolicy Bypass -File ctf-win.ps1 lsb      .\x.png
#   powershell -ExecutionPolicy Bypass -File ctf-win.ps1 tail     .\x.png
#   powershell -ExecutionPolicy Bypass -File ctf-win.ps1 unpack   .\x.zip -out .\out
#   powershell -ExecutionPolicy Bypass -File ctf-win.ps1 b64      decode .\x.b64 .\out.bin
#   powershell -ExecutionPolicy Bypass -File ctf-win.ps1 hex      decode .\x.hex .\out.bin
#   powershell -ExecutionPolicy Bypass -File ctf-win.ps1 hex      encode .\x.bin  .\out.hex
#   powershell -ExecutionPolicy Bypass -File ctf-win.ps1 scan     .\dir
#
# 只用 .NET 自带能力（System.Drawing 读图、DeflateStream 解压），不依赖任何外部工具。

param(
    [Parameter(Position = 0)][string]$Cmd = "help",
    [Parameter(Position = 1)][string]$Path,
    [Parameter(Position = 2)][string]$InFile,
    [string]$Pat = "flag|ctf|DASCTF|passw|secret",
    [string]$Out,
    [int]$Min = 6,
    [switch]$All
)

$ErrorActionPreference = "Stop"
$script:All = $All.IsPresent

# Magic signatures: (label, hex of the leading bytes). Longest first so ZIP local
# header wins over the generic "PK".
$Sigs = @(
    @{ n = "PNG";   h = "89504E47" },
    @{ n = "JPEG";  h = "FFD8FF" },
    @{ n = "GIF";   h = "474946383961" },
    @{ n = "BMP";   h = "424D" },
    @{ n = "PDF";   h = "25504446" },
    @{ n = "ZIP";   h = "504B0304" },
    @{ n = "ZIP-E"; h = "504B0506" },
    @{ n = "RAR";   h = "526172211A07" },
    @{ n = "7Z";    h = "377ABCAF271C" },
    @{ n = "GZIP";  h = "1F8B08" },
    @{ n = "BZIP2"; h = "425A68" },
    @{ n = "XZ";    h = "FD377A585A00" },
    @{ n = "ELF";   h = "7F454C46" },
    @{ n = "PE";    h = "4D5A" },
    @{ n = "WAV";   h = "52494646" },
    @{ n = "OGG";   h = "4F676753" },
    @{ n = "SQLite"; h = "53514C69746520666F726D6174203300" },
    @{ n = "PCAP";  h = "D4C3B2A1" },
    @{ n = "PCAPNG"; h = "0A0D0D0A" }
)

$CSharp = @'
using System;
using System.Text;

public static class CtfTools
{
    // LSB extraction, row-major, all three channels, 8 bits per byte.
    public static string Lsb(string path, int bitPlane, int maxChars)
    {
        var bmp = new System.Drawing.Bitmap(path);
        int w = bmp.Width, h = bmp.Height;
        var sb = new StringBuilder();
        int acc = 0, n = 0;
        for (int y = 0; y < h; y++)
        {
            for (int x = 0; x < w; x++)
            {
                var c = bmp.GetPixel(x, y);
                foreach (int v in new int[] { c.R, c.G, c.B })
                {
                    acc = (acc << 1) | ((v >> bitPlane) & 1);
                    n++;
                    if (n == 8)
                    {
                        if (acc == 0) { bmp.Dispose(); return sb.ToString(); }
                        char ch = (char)acc;
                        if (ch >= 32 && ch < 127) sb.Append(ch); else sb.Append('.');
                        if (sb.Length >= maxChars) { bmp.Dispose(); return sb.ToString(); }
                        acc = 0; n = 0;
                    }
                }
            }
        }
        bmp.Dispose();
        return sb.ToString();
    }
}
'@

function Get-Sig([byte[]]$Data, [int]$Offset) {
    foreach ($s in $Sigs) {
        if ($s.h.Length % 2) { continue }   # a malformed signature must not crash the scan
        $bytes = @()
        for ($i = 0; $i -lt $s.h.Length; $i += 2) { $bytes += [Convert]::ToByte($s.h.Substring($i, 2), 16) }
        if ($Offset + $bytes.Count -gt $Data.Length) { continue }
        $ok = $true
        for ($i = 0; $i -lt $bytes.Count; $i++) {
            if ($Data[$Offset + $i] -ne $bytes[$i]) { $ok = $false; break }
        }
        if ($ok) { return $s.n }
    }
    return $null
}

function Show-Info {
    $f = Get-Item -LiteralPath $Path
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    $head = $bytes[0..([Math]::Min(15, $bytes.Length - 1))]
    $sig = Get-Sig $bytes 0
    "file      : $($f.Name)"
    "size      : $($f.Length) bytes"
    "magic     : $(if ($sig) { $sig } else { 'unknown' })  [$([BitConverter]::ToString($head))]"
    "sha256    : $((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower())"
    "md5       : $((Get-FileHash -LiteralPath $f.FullName -Algorithm MD5).Hash.ToLower())"
    $inner = @()
    for ($i = 1; $i -lt $bytes.Length - 3; $i++) {
        $s = Get-Sig $bytes $i
        if ($s) { $inner += ("{0}@0x{1:X}" -f $s, $i) }
    }
    if ($inner.Count -gt 0) {
        "inner     : " + (($inner | Select-Object -First 12) -join ", ")
    }
    if ($sig -eq "PNG" -and $bytes.Length -gt 8) {
        # Anything after IEND is appended data -- the usual "flag in the tail" spot.
        $iend = -1
        for ($i = $bytes.Length - 12; $i -ge 0; $i--) {
            if ($bytes[$i] -eq 0x49 -and $bytes[$i + 1] -eq 0x45 -and $bytes[$i + 2] -eq 0x4E -and $bytes[$i + 3] -eq 0x44) { $iend = $i; break }
        }
        if ($iend -ge 0) {
            $tailLen = $bytes.Length - ($iend + 8)
            if ($tailLen -gt 0) {
                $tailText = [Text.Encoding]::ASCII.GetString($bytes[($iend + 8)..($bytes.Length - 1)])
                "png-tail  : $tailLen bytes after IEND -> " + ($tailText -replace '[^\x20-\x7E]', '.')
            }
        }
    }
}

function Show-Strings {
    $bytes = [IO.File]::ReadAllBytes((Get-Item -LiteralPath $Path).FullName)
    $text = [Text.Encoding]::ASCII.GetString($bytes)
    $parts = $text -split '[^\x20-\x7E]+' | Where-Object { $_.Length -ge $Min }
    if (-not $script:All) { $parts = $parts | Where-Object { $_ -match $Pat } }
    if (-not $parts) { "(no match; try -All to dump every printable run)" ; return }
    $parts | Select-Object -First 200 | ForEach-Object { $_ }
    "--- total: $($parts.Count) run(s) >= $Min chars"
}

function Invoke-Carve {
    $bytes = [IO.File]::ReadAllBytes((Get-Item -LiteralPath $Path).FullName)
    if (-not $Out) { $Out = Join-Path (Get-Location) ($(Split-Path $Path -Leaf) + "_carved") }
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    $hits = 0
    for ($i = 0; $i -lt $bytes.Length - 3; $i++) {
        $s = Get-Sig $bytes $i
        if (-not $s) { continue }
        # From a hit to the next header (or EOF) is the candidate payload; greedy but
        # enough to hand the right bytes to a decoder.
        $end = $bytes.Length
        for ($j = $i + 4; $j -lt $bytes.Length - 3; $j++) {
            if (Get-Sig $bytes $j) { $end = $j; break }
        }
        # A ZIP's end-of-central-directory record (PK) is NOT a new header, so
        # "cut at the next signature" would drop it and produce a file zip tools reject.
        # Extend the slice to cover the EOCD plus its comment.
        if ($s -eq "ZIP") {
            for ($k = $i; $k -lt $bytes.Length - 21; $k++) {
                if ($bytes[$k] -eq 0x50 -and $bytes[$k + 1] -eq 0x4B -and $bytes[$k + 2] -eq 0x05 -and $bytes[$k + 3] -eq 0x06) {
                    $commentLen = $bytes[$k + 20] + ($bytes[$k + 21] -shl 8)
                    $end = [Math]::Min($bytes.Length, $k + 22 + $commentLen)
                }
            }
        }
        $len = $end - $i
        if ($len -lt 64) { continue }
        $ext = switch ($s) {
            "PNG" { "png" } "JPEG" { "jpg" } "GIF" { "gif" } "BMP" { "bmp" } "PDF" { "pdf" }
            "ZIP" { "zip" } "ZIP-E" { "zip" } "RAR" { "rar" } "7Z" { "7z" } "GZIP" { "gz" }
            "BZIP2" { "bz2" } "XZ" { "xz" } "ELF" { "elf" } "PE" { "exe" } "WAV" { "wav" }
            "OGG" { "ogg" } "SQLite" { "db" } "PCAP" { "pcap" } "PCAPNG" { "pcapng" }
            default { "bin" }
        }
        $file = Join-Path $Out ("{0}_{1:X8}.{2}" -f $s, $i, $ext)
        $slice = New-Object byte[] $len
        [Array]::Copy($bytes, $i, $slice, 0, $len)
        [IO.File]::WriteAllBytes($file, $slice)
        "{0} @0x{1:X} len={2} -> {3}" -f $s, $i, $len, $file
        $hits++
        if ($hits -ge 40) { "(stopped after 40 hits)"; break }
    }
    if ($hits -eq 0) { "no embedded signature found" }
}

function Invoke-Lsb {
    Add-Type -AssemblyName System.Drawing
    Add-Type -TypeDefinition $CSharp -ReferencedAssemblies System.Drawing
    if (-not $Out) { $planes = 0..2 } else { $planes = @([int]$Out) }
    foreach ($p in $planes) {
        $text = [CtfTools]::Lsb((Get-Item -LiteralPath $Path).FullName, $p, 4000)
        "--- bit plane $p ---"
        if ($text.Length -lt 8) { "(nothing printable; try another plane or a different channel order)" }
        else { $text }
    }
}

function Invoke-Tail {
    $bytes = [IO.File]::ReadAllBytes((Get-Item -LiteralPath $Path).FullName)
    $n = [Math]::Min(512, $bytes.Length)
    $slice = $bytes[($bytes.Length - $n)..($bytes.Length - 1)]
    "last $n bytes (hex) : $([BitConverter]::ToString($slice))"
    "last $n bytes (txt) : " + ([Text.Encoding]::ASCII.GetString($slice) -replace '[^\x20-\x7E]', '.')
}

function Invoke-Unpack {
    if (-not $Out) { $Out = Join-Path (Get-Location) ($(Split-Path $Path -Leaf) + "_out") }
    New-Item -ItemType Directory -Force -Path $Out | Out-Null
    $tar = Join-Path $env:SystemRoot "System32\tar.exe"
    & $tar -xf $Path -C $Out 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { "unpacked -> $Out"; Get-ChildItem -Recurse $Out | Select-Object -First 50 FullName, Length | Format-Table -AutoSize | Out-String }
    else {
        try { Expand-Archive -LiteralPath $Path -DestinationPath $Out -Force; "unpacked (Expand-Archive) -> $Out" }
        catch { "unpack failed: $($_.Exception.Message)"; "hint: .7z/.rar need 7-Zip; .tar/.gz/.zip work with tar.exe" }
    }
}

function Invoke-Codec([string]$mode, [string]$src) {
    if ($Cmd -eq "b64") {
        if ($mode -eq "decode") {
            $raw = [IO.File]::ReadAllText($src) -replace '\s', ''
            [IO.File]::WriteAllBytes($Out, [Convert]::FromBase64String($raw))
            "decoded -> $Out ($((Get-Item $Out).Length) bytes)"
        } else {
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($src)) | Set-Content -NoNewline $Out
            "encoded -> $Out"
        }
        return
    }
    if ($mode -eq "decode") {
        $hex = ([IO.File]::ReadAllText($src) -replace '[^0-9A-Fa-f]', '')
        if ($hex.Length % 2) { $hex = $hex.Substring(0, $hex.Length - 1) }
        # [Convert]::FromHexString is .NET 5+ only; Windows PowerShell 5.1 has no such
        # API, so decode by hand -- this is the version the venue machine will have.
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $hex.Length; $i += 2) {
            $bytes[$i / 2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
        }
        [IO.File]::WriteAllBytes($Out, $bytes)
        "decoded -> $Out ($((Get-Item $Out).Length) bytes)"
    } else {
        [BitConverter]::ToString([IO.File]::ReadAllBytes($src)).Replace('-', '').ToLower() | Set-Content -NoNewline $Out
        "encoded -> $Out"
    }
}

function Invoke-Scan {
    Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        $b = [IO.File]::ReadAllBytes($_.FullName)
        if ($b.Length -lt 4) { return }
        $sig = Get-Sig $b 0
        $hit = Select-String -LiteralPath $_.FullName -Pattern 'flag\{|ctf\{|DASCTF\{' -AllMatches -Encoding ASCII -ErrorAction SilentlyContinue
        "{0,-10} {1,10} {2}" -f $(if ($sig) { $sig } else { "?" }), $b.Length, $_.FullName
        if ($hit) { "           ^ contains flag-like text" }
    }
}

switch ($Cmd.ToLower()) {
    "info"    { Show-Info }
    "strings" { Show-Strings }
    "carve"   { Invoke-Carve }
    "lsb"     { Invoke-Lsb }
    "tail"    { Invoke-Tail }
    "unpack"  { Invoke-Unpack }
    "scan"    { Invoke-Scan }
    "b64"     { if (-not $InFile) { "用法: b64 decode|encode <文件> -Out <输出>" } else { Invoke-Codec $Path $InFile } }
    "hex"     { if (-not $InFile) { "用法: hex decode|encode <文件> -Out <输出>" } elseif (-not $Out) { "-Out required, e.g. -Out out.bin" } else { Invoke-Codec $Path $InFile } }
    default {
@"
CTF 零安装工具箱 —— 用法（在文件所在目录打开 PowerShell）

  .\ctf-win.ps1 info     <文件>                    类型/魔数/哈希/内嵌签名/PNG 尾部附加数据
  .\ctf-win.ps1 strings  <文件> [-pat 'flag|ctf']   可打印串（-All 全量）
  .\ctf-win.ps1 carve    <文件> [-out 目录]         按签名切出内嵌文件（binwalk 的替代）
  .\ctf-win.ps1 lsb      <图片> [-out 0|1|2]        LSB 隐写读取（默认三个位面都试）
  .\ctf-win.ps1 tail     <文件>                    末尾 512 字节（追加数据的常见位置）
  .\ctf-win.ps1 unpack   <压缩包> [-out 目录]       zip/tar/gz（tar.exe 自带）
  .\ctf-win.ps1 scan     <目录>                     递归列出类型 + 标出含 flag 文本的文件
  .\ctf-win.ps1 b64      decode|encode <文件> -Out <输出>
  .\ctf-win.ps1 hex      decode|encode <文件> -Out <输出>

如果脚本被策略拦：powershell -ExecutionPolicy Bypass -File .\ctf-win.ps1 ...
"@
    }
}
