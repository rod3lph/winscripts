- ``` 
  
  New-Item -ItemType Directory c:\InstallLogs
  Start-Transcript -Path C:\InstallLogs\finalize-wipro.log -Append
  
  Set-TimeZone -ID "Eastern Standard Time"
  
  Set-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "VHDLocations" -Value "\\inframanagefs2.file.core.windows.net\wvdprofile1\WiproProfile1"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles" -Name "Enabled" -Value 1
  get-ItemProperty -Path "HKLM:\SOFTWARE\FSLogix\Profiles"
  write-host "FSlogix done."
  
  $insecureCiphers = 'RC4 40/128','RC4 56/128','RC4 64/128','RC4 128/128','Triple DES 168','Triple DES 168/168'
  Foreach ($insecureCipher in $insecureCiphers) {
    $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
  
    $key.SetValue('Enabled', 0, 'DWord')
  
    $key.close()
  
    Write-Host "$insecureCipher has been disabled"
  
  }
  
    
  New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
      
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
      
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
  Write-Host 'TLS 1.0 has been disabled.'
  
  
  Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force
  write-host "security done"
  
  Add-Type -TypeDefinition @"
      using System;
      using System.Runtime.InteropServices;
      [StructLayout(LayoutKind.Sequential)] public struct ANIMATIONINFO {
          public uint cbSize;
          public bool iMinAnimate;
      }
      public class PInvoke { 
          [DllImport("user32.dll")] public static extern bool SystemParametersInfoW(uint uiAction, uint uiParam, ref ANIMATIONINFO pvParam, uint fWinIni);
      }
  "@
  $animInfo = New-Object ANIMATIONINFO
  $animInfo.cbSize = 8
  $animInfo.iMinAnimate = $false
  [PInvoke]::SystemParametersInfoW(0x49, 0, [ref]$animInfo, 3)
  write-host "animation done"
  
  #### Start-Process powershell -verb runas -ArgumentList "-file services.ps1"
  #   Description:
  # This script disables unwanted Windows services. If you do not want to disable
  # certain services comment out the corresponding lines below.
  
  $services = @(
      "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
      "DiagTrack"                                # Diagnostics Tracking Service
      "dmwappushservice"                         # WAP Push Message Routing Service (see known issues)
      "lfsvc"                                    # Geolocation Service
      "MapsBroker"                               # Downloaded Maps Manager
      "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
      #"RemoteAccess"                             # Routing and Remote Access
      #"RemoteRegistry"                           # Remote Registry
      "SharedAccess"                             # Internet Connection Sharing (ICS)
      "TrkWks"                                   # Distributed Link Tracking Client
      "WbioSrvc"                                 # Windows Biometric Service (required for Fingerprint reader / facial detection)
      #"WlanSvc"                                 # WLAN AutoConfig
      "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
      #"wscsvc"                                  # Windows Security Center Service
      #"WSearch"                                 # Windows Search
      "XblAuthManager"                           # Xbox Live Auth Manager
      "XblGameSave"                              # Xbox Live Game Save Service
      "XboxNetApiSvc"                            # Xbox Live Networking Service
      "ndu"                                      # Windows Network Data Usage Monitor
      # Services which cannot be disabled
      #"WdNisSvc"
  )
  
  foreach ($service in $services) {
      Write-Output "Trying to disable $service"
      Get-Service -Name $service | Set-Service -StartupType Disabled
  }
  
  
  #### Start-Process powershell -verb runas -ArgumentList "-file appx.ps1"
  Write-Output "Uninstalling default apps"
  $apps = @(
      # default Windows 10 apps
      "Microsoft.3DBuilder"
  #    "Microsoft.Appconnector"
      "Microsoft.BingFinance"
      "Microsoft.BingNews"
      "Microsoft.BingSports"
      "Microsoft.BingTranslator"
      "Microsoft.BingWeather"
      #"Microsoft.FreshPaint"
      "Microsoft.GamingServices"
      "Microsoft.Microsoft3DViewer"
      "Microsoft.MicrosoftOfficeHub"
      "Microsoft.MicrosoftPowerBIForWindows"
      "Microsoft.MicrosoftSolitaireCollection"
      #"Microsoft.MicrosoftStickyNotes"
      "Microsoft.MinecraftUWP"
      "Microsoft.NetworkSpeedTest"
      "Microsoft.People"
      "Microsoft.Print3D"
      "Microsoft.SkypeApp"
      "Microsoft.Wallet"
      #"Microsoft.Windows.Photos"
      #"Microsoft.WindowsAlarms"
      #"Microsoft.WindowsCalculator"
      "Microsoft.WindowsCamera"
      #"microsoft.windowscommunicationsapps"
      "Microsoft.WindowsMaps"
      "Microsoft.WindowsPhone"
      "Microsoft.WindowsSoundRecorder"
      #"Microsoft.WindowsStore"   # can't be re-installed
      "Microsoft.Xbox.TCUI"
      "Microsoft.XboxApp"
      "Microsoft.XboxGameOverlay"
      "Microsoft.XboxGamingOverlay"
      "Microsoft.XboxSpeechToTextOverlay"
      "Microsoft.YourPhone"
      "Microsoft.ZuneMusic"
      "Microsoft.ZuneVideo"
  
      # Threshold 2 apps
      "Microsoft.CommsPhone"
      #"Microsoft.ConnectivityStore"
      "Microsoft.GetHelp"
      "Microsoft.Getstarted"
      # "Microsoft.Messaging"
      "Microsoft.Office.Sway"
      #"Microsoft.OneConnect"
      #"Microsoft.WindowsFeedbackHub"
  
      # Creators Update apps
      "Microsoft.Microsoft3DViewer"
      #"Microsoft.MSPaint"
  
      #Redstone apps
      "Microsoft.BingFoodAndDrink"
      "Microsoft.BingHealthAndFitness"
      "Microsoft.BingTravel"
      "Microsoft.WindowsReadingList"
  
      # Redstone 5 apps
      "Microsoft.MixedReality.Portal"
      "Microsoft.ScreenSketch"
      "Microsoft.XboxGamingOverlay"
      "Microsoft.YourPhone"
  
      # non-Microsoft
      "2FE3CB00.PicsArt-PhotoStudio"
      "46928bounde.EclipseManager"
      "4DF9E0F8.Netflix"
      "613EBCEA.PolarrPhotoEditorAcademicEdition"
      "6Wunderkinder.Wunderlist"
      "7EE7776C.LinkedInforWindows"
      "89006A2E.AutodeskSketchBook"
      "9E2F88E3.Twitter"
      "A278AB0D.DisneyMagicKingdoms"
      "A278AB0D.MarchofEmpires"
      "ActiproSoftwareLLC.562882FEEB491" # next one is for the Code Writer from Actipro Software LLC
      "CAF9E577.Plex"  
      "ClearChannelRadioDigital.iHeartRadio"
      "D52A8D61.FarmVille2CountryEscape"
      "D5EA27B7.Duolingo-LearnLanguagesforFree"
      "DB6EA5DB.CyberLinkMediaSuiteEssentials"
      "DolbyLaboratories.DolbyAccess"
      "DolbyLaboratories.DolbyAccess"
      "Drawboard.DrawboardPDF"
      "Facebook.Facebook"
      "Fitbit.FitbitCoach"
      "Flipboard.Flipboard"
      "GAMELOFTSA.Asphalt8Airborne"
      "KeeperSecurityInc.Keeper"
      "NORDCURRENT.COOKINGFEVER"
      "PandoraMediaInc.29680B314EFC2"
      "Playtika.CaesarsSlotsFreeCasino"
      "ShazamEntertainmentLtd.Shazam"
      "SlingTVLLC.SlingTV"
      "SpotifyAB.SpotifyMusic"
      #"TheNewYorkTimes.NYTCrossword"
      "ThumbmunkeysLtd.PhototasticCollage"
      "TuneIn.TuneInRadio"
      "WinZipComputing.WinZipUniversal"
      "XINGAG.XING"
      "flaregamesGmbH.RoyalRevolt2"
      "king.com.*"
      "king.com.BubbleWitch3Saga"
      "king.com.CandyCrushSaga"
      "king.com.CandyCrushSodaSaga"
  
  
  )
  
  foreach ($app in $apps) {
      Write-Output "Trying to remove $app"
  
      Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers
  
      Get-AppXProvisionedPackage -Online |
          Where-Object DisplayName -EQ $app |
          Remove-AppxProvisionedPackage -Online
  }
  
  write-host "installing cisco amp"
  #### Start-Process powershell -verb runas -ArgumentList "-file ciscoamp.cmd"
  & .\amp_RoundPoint_Servers_RDS_Protect.exe /R /S /desktopicon 0 /contextmenu 1 /startmenu 1 /skipdfc 1 /skiptetra 1 | Out-Null
  
  
  write-host "Disable MS Defender"
  Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "AllowFastServiceStartup" -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Value 1
  Get-MpComputerStatus
  get-process msmpeng*
  
  cd ..
  remove-item "C:\WVDInstallers" -recurse -force
  pause
  restart-computer
  ```