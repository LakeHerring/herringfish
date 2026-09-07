$ErrorActionPreference = 'Stop'
$env:Path = "$env:USERPROFILE\.cargo\bin;" + $env:Path
rustup toolchain install stable-x86_64-pc-windows-gnu
$tc = Join-Path $env:USERPROFILE '.rustup\toolchains\stable-x86_64-pc-windows-gnu\bin'
Write-Host "--- toolchain bin contents:"
Get-ChildItem $tc | Where-Object { $_.Name -match 'gcc|\.exe' } | Select-Object Name | Format-Table -AutoSize
Get-ChildItem $tc -Filter '*gcc*' | Select-Object Name
