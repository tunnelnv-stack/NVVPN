$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$frames=@()
foreach($size in @(256,64,32,16)){
    $bitmap=[Drawing.Bitmap]::new($size,$size)
    $g=[Drawing.Graphics]::FromImage($bitmap)
    $g.SmoothingMode='AntiAlias';$g.TextRenderingHint='AntiAliasGridFit'
    $g.Clear([Drawing.Color]::FromArgb(17,29,39))
    $paper=[Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(232,240,245))
    $red=[Drawing.Pen]::new([Drawing.Color]::FromArgb(73,207,181),[Math]::Max(1,$size/55))
    $subtle=[Drawing.Pen]::new([Drawing.Color]::FromArgb(42,105,95),[Math]::Max(1,$size/150))
    $font=[Drawing.Font]::new('Segoe UI',[single]($size*.49),[Drawing.FontStyle]::Bold,[Drawing.GraphicsUnit]::Pixel)
    $format=[Drawing.StringFormat]::new();$format.Alignment='Center';$format.LineAlignment='Center'
    $g.DrawString('NV',$font,$paper,[Drawing.RectangleF]::new(0,0,$size,$size),$format)
    $g.DrawLine($red,[single]($size*.30),[single]($size*.82),[single]($size*.70),[single]($size*.82))
    $stream=[IO.MemoryStream]::new();$bitmap.Save($stream,[Drawing.Imaging.ImageFormat]::Png)
    $frames+=,@{size=$size;bytes=$stream.ToArray()}
    if($size -eq 256){$bitmap.Save((Join-Path $PSScriptRoot 'NVVPN.png'),[Drawing.Imaging.ImageFormat]::Png)}
    $stream.Dispose();$g.Dispose();$font.Dispose();$paper.Dispose();$red.Dispose();$subtle.Dispose();$format.Dispose();$bitmap.Dispose()
}
$file=[IO.File]::Create((Join-Path $PSScriptRoot 'NVVPN.ico'));$writer=[IO.BinaryWriter]::new($file)
try{
    $writer.Write([uint16]0);$writer.Write([uint16]1);$writer.Write([uint16]$frames.Count)
    $offset=6+16*$frames.Count
    foreach($frame in $frames){$dimension=if($frame.size -eq 256){0}else{$frame.size};$writer.Write([byte]$dimension);$writer.Write([byte]$dimension);$writer.Write([byte]0);$writer.Write([byte]0);$writer.Write([uint16]1);$writer.Write([uint16]32);$writer.Write([uint32]$frame.bytes.Length);$writer.Write([uint32]$offset);$offset+=$frame.bytes.Length}
    foreach($frame in $frames){$writer.Write([byte[]]$frame.bytes)}
}finally{$writer.Dispose();$file.Dispose()}
