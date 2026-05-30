# Instala binários em third_party/windows-amd64
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
python vulndix.py --install-tools
