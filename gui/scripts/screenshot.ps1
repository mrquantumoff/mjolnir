param(
    [Parameter(Mandatory)] [string] $Exe,
    [Parameter(Mandatory)] [string] $Out,
    [int] $DelayMs = 2500,
    [string[]] $Arguments = @(),
    [switch] $KeepRunning
)

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int attr, out RECT r, int size);
}
"@

$startArgs = @{ FilePath = $Exe; PassThru = $true }
if ($Arguments.Count -gt 0) { $startArgs.ArgumentList = $Arguments }
$proc = Start-Process @startArgs
try {
    $deadline = (Get-Date).AddSeconds(30)
    while ($proc.MainWindowHandle -eq 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 200
        $proc.Refresh()
        if ($proc.HasExited) { throw "process exited with code $($proc.ExitCode)" }
    }
    if ($proc.MainWindowHandle -eq 0) { throw "no window appeared" }
    $h = $proc.MainWindowHandle
    [void][Win]::SetForegroundWindow($h)
    Start-Sleep -Milliseconds $DelayMs

    $r = New-Object Win+RECT
    if ([Win]::DwmGetWindowAttribute($h, 9, [ref]$r, 16) -ne 0) { [void][Win]::GetWindowRect($h, [ref]$r) }
    $w = $r.Right - $r.Left; $hgt = $r.Bottom - $r.Top
    $bmp = New-Object System.Drawing.Bitmap $w, $hgt
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.Left, $r.Top, 0, 0, $bmp.Size)
    $g.Dispose()
    $bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Output "saved $Out (${w}x${hgt})"
}
finally {
    if (-not $KeepRunning -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
}
