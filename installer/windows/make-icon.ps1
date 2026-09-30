# Generates installer\windows\homelab-rmm.ico from code, so the icon is
# reproducible and reviewable rather than a binary nobody can regenerate.
#
# The glyph is a monitor with a pulse line across it: a display for "the device
# you are managing", a pulse for "and you are watching it". Drawn bold on
# purpose, because the 16 px entry is the one Windows shows most often (the
# Programs and Features row, a shortcut, the taskbar).
#
#   powershell -ExecutionPolicy Bypass -File installer\windows\make-icon.ps1
#
# Two things learned the hard way, both load-bearing:
#
#   * Every entry is a 32 bpp uncompressed DIB, written here. PNG-compressed
#     entries are legal and the modern shell reads them, but GDI+ refuses to
#     open an .ico that contains one at all, so a single PNG entry makes the
#     whole file unusable to anything going through GDI+. Bitmap.GetHicon is
#     no shortcut either: it hands back 4 bpp, which turns the glyph to mud.
#   * An ICONDIRENTRY has to describe the image it points at. Claiming 32 bpp
#     over an image that is not gets the file rejected outright.
[CmdletBinding()]
param(
    # Defaults to homelab-rmm.ico beside this script. Resolved in the body
    # because $PSScriptRoot is not populated during parameter binding.
    [string]$Out = '',
    # Dark obsidian tile background, matching the modern web console.
    [string]$Accent = '#111216'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

if (-not $Out) {
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    $Out = Join-Path $here 'homelab-rmm.ico'
}

$sizes = 16, 20, 24, 32, 48, 64, 128, 256

# Parse the accent to plain integers. Passing a Color struct through a
# PowerShell variable can hit a type-identity mismatch between the two
# System.Drawing assemblies a session may have loaded, so every brush and pen
# below builds its colour inline from these.
$hex = $Accent.TrimStart("#")
$aR = [Convert]::ToInt32($hex.Substring(0, 2), 16)
$aG = [Convert]::ToInt32($hex.Substring(2, 2), 16)
$aB = [Convert]::ToInt32($hex.Substring(4, 2), 16)

function New-Glyph([int]$px) {
    $bmp = [System.Drawing.Bitmap]::new([int]$px, [int]$px, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    $u = $px / 32.0            # design on a 32x32 grid, then scale
    $radius = [Math]::Max(2, [int](6 * $u))

    # Rounded-square background in the accent colour.
    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $d = $radius * 2
    $path.AddArc(0, 0, $d, $d, 180, 90)
    $path.AddArc($px - $d, 0, $d, $d, 270, 90)
    $path.AddArc($px - $d, $px - $d, $d, $d, 0, 90)
    $path.AddArc(0, $px - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    $bg = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, $aR, $aG, $aB))
    $g.FillPath($bg, $path)

    $wb = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 255, 255, 255))

    # Monitor body, hollow.
    $mx = 5 * $u; $my = 7 * $u; $mw = 22 * $u; $mh = 14 * $u
    $pen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 255, 255, 255), [float][Math]::Max(1.0, 2.0 * $u))
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
    $mr = [Math]::Max(1, [int](2 * $u))
    $mpath = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $md = $mr * 2
    $mpath.AddArc($mx, $my, $md, $md, 180, 90)
    $mpath.AddArc($mx + $mw - $md, $my, $md, $md, 270, 90)
    $mpath.AddArc($mx + $mw - $md, $my + $mh - $md, $md, $md, 0, 90)
    $mpath.AddArc($mx, $my + $mh - $md, $md, $md, 90, 90)
    $mpath.CloseFigure()
    $g.DrawPath($pen, $mpath)

    # Stand: neck plus foot.
    $neckW = [Math]::Max(1.0, 3.0 * $u)
    $g.FillRectangle($wb, ($px / 2.0) - ($neckW / 2.0), $my + $mh, $neckW, 3.0 * $u)
    $footW = 12.0 * $u
    $g.FillRectangle($wb, ($px / 2.0) - ($footW / 2.0), $my + $mh + (3.0 * $u), $footW, [Math]::Max(1.0, 2.0 * $u))

    # Pulse line inside the screen. Dropped below 20 px, where it turns to mud
    # and the monitor silhouette alone reads better.
    if ($px -ge 20) {
        $pp = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(255, 16, 185, 129), [float][Math]::Max(1.0, 1.8 * $u))
        $pp.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pp.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pp.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $cy = $my + ($mh / 2.0)
        $pts = @(
            ([System.Drawing.PointF]::new(($mx + 3.0 * $u), $cy)),
            ([System.Drawing.PointF]::new(($mx + 7.0 * $u), $cy)),
            ([System.Drawing.PointF]::new(($mx + 9.5 * $u), ($cy - 3.5 * $u))),
            ([System.Drawing.PointF]::new(($mx + 12.5 * $u), ($cy + 3.0 * $u))),
            ([System.Drawing.PointF]::new(($mx + 15.0 * $u), $cy)),
            ([System.Drawing.PointF]::new(($mx + 19.0 * $u), $cy))
        )
        $g.DrawLines($pp, [System.Drawing.PointF[]]$pts)
        $pp.Dispose()
    }

    $pen.Dispose(); $wb.Dispose(); $bg.Dispose(); $path.Dispose(); $mpath.Dispose(); $g.Dispose()
    return $bmp
}

# Get-DibBytes encodes one bitmap as a 32 bpp icon image: a BITMAPINFOHEADER
# whose height is doubled (colour rows, then the AND mask), BGRA rows bottom
# up. LockBits takes the whole buffer in one call; GetPixel per pixel would be
# 65,536 round trips at 256 px.
function Get-DibBytes([System.Drawing.Bitmap]$bmp) {
    $w = $bmp.Width; $h = $bmp.Height
    $rect = [System.Drawing.Rectangle]::new(0, 0, $w, $h)
    $data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        $stride = $data.Stride
        $buf = New-Object byte[] ($stride * $h)
        [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $buf, 0, $buf.Length)
    } finally {
        $bmp.UnlockBits($data)
    }

    $ms = [System.IO.MemoryStream]::new()
    $bw = [System.IO.BinaryWriter]::new($ms)
    $bw.Write([uint32]40)             # biSize
    $bw.Write([int32]$w)              # biWidth
    $bw.Write([int32]($h * 2))        # biHeight: colour rows + AND mask
    $bw.Write([uint16]1)              # biPlanes
    $bw.Write([uint16]32)             # biBitCount
    $bw.Write([uint32]0)              # biCompression = BI_RGB
    $bw.Write([uint32]($w * $h * 4))  # biSizeImage
    $bw.Write([int32]0); $bw.Write([int32]0)
    $bw.Write([uint32]0); $bw.Write([uint32]0)

    # LockBits gives top-down rows; an icon DIB is bottom-up.
    for ($y = $h - 1; $y -ge 0; $y--) {
        $bw.Write($buf, $y * $stride, $w * 4)
    }
    # AND mask, one bit per pixel, rows padded to 4 bytes. The alpha channel
    # already carries transparency so every bit is zero, but the field is not
    # optional: consumers read the image height through it.
    $maskRow = [int][Math]::Ceiling($w / 32.0) * 4
    $bw.Write((New-Object byte[] ($maskRow * $h)))

    $bw.Flush()
    $out = $ms.ToArray()
    $bw.Dispose(); $ms.Dispose()
    # The comma matters: PowerShell unrolls an array on return, which turned
    # the byte[] into a stream of individual bytes and wrote a 142-byte icon.
    return ,$out
}

$images = @()
foreach ($s in $sizes) {
    $bmp = New-Glyph $s
    $images += , @{ Size = $s; Bytes = (Get-DibBytes $bmp) }
    $bmp.Dispose()
}

$fs = [System.IO.File]::Create($Out)
$bw = [System.IO.BinaryWriter]::new($fs)
$bw.Write([uint16]0)                  # reserved
$bw.Write([uint16]1)                  # type: icon
$bw.Write([uint16]$images.Count)
$offset = 6 + (16 * $images.Count)
foreach ($p in $images) {
    $dim = if ($p.Size -ge 256) { 0 } else { $p.Size }   # 0 means 256 in ICONDIRENTRY
    $bw.Write([byte]$dim)             # width
    $bw.Write([byte]$dim)             # height
    $bw.Write([byte]0)                # palette count: 0 at 32 bpp
    $bw.Write([byte]0)                # reserved
    $bw.Write([uint16]1)              # colour planes
    $bw.Write([uint16]32)             # bits per pixel
    $bw.Write([uint32]$p.Bytes.Length)
    $bw.Write([uint32]$offset)
    $offset += $p.Bytes.Length
}
foreach ($p in $images) { $bw.Write([byte[]]$p.Bytes, 0, $p.Bytes.Length) }
$bw.Flush(); $bw.Dispose(); $fs.Dispose()

foreach ($p in $images) { Write-Host ("  {0,3} px  {1,9:N0} bytes  32 bpp DIB" -f $p.Size, $p.Bytes.Length) }
Write-Host ("wrote {0} ({1:N0} bytes, {2} sizes)" -f $Out, (Get-Item $Out).Length, $images.Count)
