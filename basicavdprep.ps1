New-Item -ItemType Directory c:\InstallLogs
Start-Transcript -Path C:\InstallLogs\finalize-avdhost.log -Append

Set-TimeZone -ID "Mountain Standard Time"

Set-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VHDLocations" -Value "\\fileshare.file.core.windows.net\wvdprofile1\"
Set-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "Enabled" -Value 1

Set-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "OutlookCachedMode" -Value 1
# Disables Cached mode when profile not mounted
Set-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "ProfileType" -Value 3
# allows concurrent access to VHD
Set-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "SizeInMBs" -Value 50000
# Default size 30GB
