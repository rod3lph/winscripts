- start-process powershell.exe -verb runas 
  ``` 
  powershell -Command "Start-Process cmd -Verb RunAs"
  ```
- add to script to escalate/runas admin [[Powershell - self-escalate run as admin]]
- powershell command history file - (Get-PSReadlineOption).HistorySavePath
- install chocolatey [[powershell chocolatey]]
- Security: Harden Windows Workstation [[pscript to finalize windows workstation]]
- Security: Harden Windows 2019 [[Windows 2019 CIS Hardening]]
- Security: ((63598d19-d89e-41ff-9a43-7698e73b6c93))
- [[Local User]]
- [[Prep VM for Azure]]
- [[Powershell Networking and Firewall]]
- [[Powershell - Active Directory]]
- [[Azure AD]]
- [[w32tm troubleshooting]]
- [[FileSystem]]
- [[Printers]]
- [[powershell chocolatey]]
- [[Azure]]
- [[Entra Connect Sync]]
- [[Azure File Sync]]
- [[Azure Virtual Desktop]]
- [[Remote Desktop Services]]
- [[Install KMS Server]]
- [[Extract priv key on windows]]
- [[Export TLS certificate chain]]
- [[Azure Blob download and File transfer script]]
- [[Get a list of SID plus Profile Path]]
- [[Win Home to Pro]]
- [[MSTeams]]
- [[Windows FileShares]]
- [[Exchange]]
- [[Exchange Online]]
- [[Sharepoint Online]]
- [[AzureAutomation]]
- [[Intune]]
- [[SystemCheck]]
- [[Network Capture]]
- [[Windows Hello]]
- [[List Patches]]
- [[IIS SMTP Relay]]
- [[Wini11 Home to Pro]]
- [[Win11 bypass checks]]
- [[Windows RDS]]
- [[MSGraph - Office365]]
- [[Popup Window prompt]]
- [[Bitlocker]]
- [[Enable RDP Shortpath]]
- [[Check if Oulook is installed]]
- [[Windows Login Options]]
- sysprep 
  ``` 
  sysprep.exe /generalize /shutdown /oobe /mode:vm
  ```
- Get your public ip 
  
  ``` 
  invoke-webrequest ifconfig.me/ip
  ```
- Get boot time 
  ``` 
  systeminfo | find "System Boot Time"
  ```
- Get-Content 
  ``` 
  # Last 10 rows
  get-content file.log -tail 10
  
  # First 10 rows
  get-content file.log -first 10
  
  # monitor file
  get-content file.log -wait
  ```
- win 11 issue with keyboard on powershell 
  ``` 
  # known issue with psreadline module 2.0.0 to resolve run command, close session and reopen powershell
  # does not manifest on powershell ise because modules are not loaded when opening ise
  
  Install-Module -Name PSReadLine -RequiredVersion 2.2.5
  ```
- Unable to resolve package source ‘https://www.powershellgallery.com/api/v2
	- ``` 
	  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	  ```
	- ``` 
	  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
	  Register-PSRepository -Default -Verbose
	  Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
	  ```
- rename powershell console window 
  ``` 
  $host.ui.RawUI.WindowTitle = “Changed Title”
  ```
- Pause 
  ``` 
  #pause and wait for input
  pause
  
  #wait for some time
  Start-Sleep -Seconds 2 -Milliseconds 300
  ```
- get uptime 
  ``` 
  Get-CimInstance -ClassName Win32_OperatingSystem | Select LastBootUpTime
  ```
- Netstat 
  ``` 
   Get-NetTCPConnection | where-object -FilterScript {$_.RemotePort -eq "445"}
   Get-NetUDPConnection | where-object -FilterScript {$_.RemotePort -eq "53"}
   Get-NetTCPConnection | where-object -FilterScript {$_.state -eq "Listen"}
   Get-NetTCPConnection -State Listen
   Get-NetTCPConnection | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}
   
   Get-NetTCPConnection | Group-Object -Property State, OwningProcess | Select -Property Count, Name, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}}, Group | Sort Count -Descending
  ```
- Disable IPv6 
  ``` 
  reg add hklm\system\currentcontrolset\services\tcpip6\parameters /v DisabledComponents /t REG_DWORD /d 0xFF /f
  Disable Tunneling ()
  Get-NetAdapterBinding -ComponentID "ms_tcpip6" | disable-NetAdapterBinding -ComponentID "ms_tcpip6" –PassThru
  ```
- Use current system credential 
  ``` 
  $Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
  $Username = $Credentials.UserName
  $Password = $Credentials.Password
  ```
- Use current credentials for scripts 
  ``` 
  $Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
  
  *** OR prompt credentials on start of script
  get-credential
  ```
- Enable RDP 
  ``` 
  Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
  Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
  ```
- $comp=@(comp1,comp2)
  foreach ($computer in $comp) { Invoke-Command -ComputerName $computer -ScriptBlock {Get-CimInstance -ClassName win32_operatingsystem | select csname, lastbootuptime}; get-hotfix -ComputerName $computer | Select Description, Hotfixid,installedby, installedon -last 10 | Sort-Object -Property Installedon |ft }
- Azure File Share
	- List all file shares of a storage account with quota and usage 
	  ``` 
	  $report = @()
	  $object = @()
	  $azshare = @()
	  $azshare = Get-AzRmStorageShare -ResourceGroupName InfraManaged-RG -StorageAccountName departmentfolder
	  foreach($sharez in $azshare.Name) {
	  $object = Get-AzRmStorageShare -ResourceGroupName InfraManaged-RG -StorageAccountName departmentfolder -Name $sharez -GetShareUsage | select Name,QuotaGiB,@{LABEL='UsedinGB';EXPRESSION={[math]::round($_.ShareUsageBytes/1GB,4)}},AccessTier
	  $report += $object
	  }
	  $report | sort -property Name | ft -auto
	  ```
- Unhide folder 
  ``` 
  Set-ItemProperty -Path $FolderPath -Name Attributes -Value Normal
  
  attrib -s -h F:\*.* /s /d
  ```
- Add AD as identity for AVS
	- make sure to add domain dns to fqdn zone (https://docs.microsoft.com/en-us/azure/azure-vmware/configure-dns-azure-vmware-solution)
	- Use run command on SDDC portal page to add with your domain information
- debloat windows
	- iwr -useb https://git.io/debloat|iex
- KMS keys reference - https://gist.github.com/jerodg/502bd80a715347662e79af526c98f187
- Check KMS server 
  ``` 
  Get-WmiObject –computer $ComputerName -class SoftwareLicensingService
  ```
-
- Get list of latest patches installed 
  ``` 
  Get-HotFix | Where-Object { $_.InstalledOn -gt (get-date).adddays(-360) }
  ```
- Configure PS to run windows update 
  #+BEGIN_QUOTE
  Install-Module PSWindowsUpdate
  Get-Command –module PSWindowsUpdate
  
  Then you will need to register to use the Microsoft Update Service not just the default Windows Update Service.
  
  Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d
  Then run:
  
  Get-WUInstall –MicrosoftUpdate –AcceptAll –AutoReboot
  
  
  $Updates = Start-WUScan
  Write-Host "Updates Found: " $Updates.Count
  Install-WUUpdates -Updates $Updates
  
  Get-WUlist
  Install-WindowsUpdate -AcceptAll -AutoReboot
  Get-WindowsUpdate -KBArticleID KB2267602, KB4533002 -Install
  Install-WindowsUpdate -NotCategory "Drivers" -NotTitle OneDrive -NotKBArticleID KB4011670 -AcceptAll -IgnoreReboot
  
  Download-WindowsUpdate
  
  $HideList = "KB4489873", "KB4489243"
  Get-WindowsUpdate -KBArticleID $HideList –Hide
  
  Get-WindowsUpdate –IsHidden
  
  Get-WindowsUpdate -KBArticleID $HideList -WithHidden -Hide:$false
  Show-WindowsUpdate -KBArticleID $HideList
  
  get-hotfix
  gwmi win32_quickfixengineering |sort installedon -desc
  
  Get-WUUninstall -KBArticleID KBXXX
  
  #+END_QUOTE
- Disable TLS1 and 1.1 
  ``` 
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
  Write-Host 'TLS 1.0 has been disabled.
  New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
  New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
  Write-Host 'TLS 1.1 has been disabled.
  ```
- Show current logged on user sessions 
  ``` 
  query user
  qwinsta
  quser
  Get-WmiObject Win32_LoggedOnUser
  Get-WmiObject Win32_LoggedOnUser | Select Antecedent -Unique | %{"{0}\{1}" -f $_.Antecedent.ToString().Split('"')[1],$_.Antecedent.ToString().Split('"')[3]}
  ```
- Enable remote registry 
  ``` 
  Set-Service RemoteRegistry –startuptype automatic –passthru
  Start-Service RemoteRegistry
  ```
- Enable WinRM via psexec 
  ``` 
  PsExec.exe \\computername -u domain\username -h -d powershell.exe "Enable-PSRemoting -Force"
  psexec \\ComputerName -s winrm.cmd quickconfig -q
  psexec @c:\ALLComputerNames.txt -s winrm.cmd quickconfig -q
  ```
- Import certificate to personal folder 
  ``` 
  Invoke-Command -ComputerName computername -ScriptBlock { Set-Service -Name RemoteRegistry -StartupType Manual; Start-Service -Name RemoteRegistry -Force ; Import-Certificate -FilePath "C:\temp\docvelocity.cer" -CertStoreLocation cert:\LocalMachine\My\}
  ```
- FileServer enable Access-based Enumeration 
  ``` 
  Get-SmbShare <Share Name> | Set-SmbShare -FolderEnumerationMode AccessBased
  # Disable
  Get-SmbShare <Share Name> | Set-SmbShare -FolderEnumerationMode Unrestricted
  ```
- List all file shares on remote server 
  ``` 
  PS C:\windows\system32> New-CimSession -ComputerName cltfs02
    Id           : 2
    Name         : CimSession2
    InstanceId   : 48d7de93-a632-4604-acad-59256ac0e032
    ComputerName : cltfs02
    Protocol     : WSMAN
   PS C:\windows\system32> Get-SmbShare -CimSession $(Get-CimSession -id 2) | select Name, Path, Description | Export-csv -NoClobber -NoTypeInformation -Path D:resultscltfs01shares.csv
  ```
- List all open smb files 
  ``` 
  $sessnum=(read-host "session number"); $cimoutfile = ((get-cimsession -id $sessnum).computername + (get-date -format "yyyyMMddHHmm") + ".csv"); Get-SmbOpenFile -CimSession (Get-CimSession -id $sessnum) | Select-Object -Property ClientComputerName,ClientUserName,Locks,Path,ShareRelativePath | export-csv -Path $cimoutfile
  ```
- Event log filtered  (identify the logname and port number)
  ``` 
  ### With Parameters to enter servername and minutes passed
  Param (
  	[string]$vmname,
      [string]$minutes
  	)
  $mytime = "-" + $minutes 
  $args = @{}
  #$args.Add("StartTime", ((Get-Date).AddHours(-1)))
  $args.Add("StartTime", ((Get-Date).AddMinutes($mytime)))
  $args.Add("EndTime", (Get-Date))
  $args.Add("LogName", "Microsoft-FileSync-Agent/Telemetry")
  $args.Add("ID", "7006")
  Get-WinEvent -FilterHashtable $args -Computername $vmname |Format-Table TimeCreated, Message -AutoSize –Wrap
  
  
  <#Param (
  	[string]$vmname,
  	[string]$portnum
  )
  $filter = @{
  	Logname = 'Application'
  	ID = $portnum
  	Data = $sname
  	StartTime =  [datetime]::Today.AddDays(-1)
  	EndTime = [datetime]::Today
  }
  Get-WinEvent -ListLog * -FilterHashtable $filter 
   #-computername $vmname -FilterHashtable $filter
  
  OR BELOW
  
  Get-WinEvent -ListLog * -EA silentlycontinue |
  where-object { $_.recordcount -AND $_.lastwritetime -gt [datetime]::today} |
  foreach-object { get-winevent -LogName $_.logname -MaxEvents 1 } |
  Format-Table TimeCreated, ID, ProviderName, Message -AutoSize –Wrap
  #>
  
  #Below works
  <#
  $args = @{}
  #$args.Add("StartTime", ((Get-Date).AddHours(-1)))
  $args.Add("StartTime", ((Get-Date).AddMinutes(-5)))
  $args.Add("EndTime", (Get-Date))
  $args.Add("LogName", "Microsoft-FileSync-Agent/Telemetry")
  $args.Add("ID", "7006")
  Get-WinEvent -FilterHashtable $args -Computername cltfs01 | Format-Table TimeCreated, ID, ProviderName, Message -AutoSize –Wrap
  #>
  ```
- Registry to enable printer redirection on RDP 
  ``` 
  Windows Registry Editor Version 5.00
  
  [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd]
  "fEnablePrintRDR"=dword:00000001
  "fEnableRDR"=dword:00000001
  ```
- display file content 
  ``` 
  get-content filename
  type filename
  
  # tail -f equivalent
  get-content filename.txt -wait
  ```
- remark 
  ``` 
  # cmd equivalent - rem
  # 
  <# #>
  ```
- set system to follow symlinks 
  #+BEGIN_QUOTE
  fsutil.exe can be made to show what arguments it takes by simply running:
  
  fsutil behavior set /?
  
  To report the current configuration, run fsutil behavior query SymlinkEvaluation - see @Jake1164's answer, particularly with respect to how a group policy may be controlling the behavior.
  
  The symbolic-link resolution behavior is set on the machine that accesses a given link, not the machine that hosts it.
  
  The behavior codes for fsutil behavior set SymlinkEvaluation - namely L2L, L2R, R2L, and R2R - mean the following:
  
  L stands for "Local", and R for "Remote"
  The FIRST L or R - before the 2 - refers to the location of the link itself (as opposed to its target) relative to the machine ACCESSING the link.
  The SECOND L or R - after the 2 - refers to the location of the link's target relative to the machine where the LINK itself is located.
  Thus, for instance, executing fsutil behavior set SymlinkEvaluation R2L means that you can access links:
  
  located on a remote machine (R)
  that point to targets on that same remote machine (L)
  
  #+END_QUOTE
- Load a function from a ps1 file (dot sourcing)
  #+BEGIN_QUOTE
  PS C:\Users\larntz\Documents\Scripts\functions>  . .\du-function.ps1
  
  In the example above I dot sourced the file du-function.ps1 by simply enter a period followed by a space and the file name containing my function.
  
  ``` 
  # du-function.ps1 content
  function du($path=".") {
      Get-ChildItem $path |
      ForEach-Object {
          $file = $_
          Get-ChildItem -File -Recurse $_.FullName | Measure-Object -Property length -Sum |
          Select-Object -Property @{Name="Name";Expression={$file}},
                                  @{Name="Size(MB)";Expression={[math]::round(($_.Sum / 1MB),2)}} # round 2 decimal places
      }
  }
  ``` 
  
  #+END_QUOTE
- load function from ps1 files inside a folder 
  ``` 
  Get-ChildItem C:\Users\larntz\Documents\Scripts\functions\*Function.ps1 | %{. $_ }
  ```
-
- KMS activation 
  ``` 
  # check for KMS servers: 
  nslookup -q=SRV _VLMCS._TCP.roundpoint.local
  
  # configure client to use specific kms server
  cscript slmgr.vbs /skms cwkmsinf01pv.roundpoint.local:1688
  
  # activate:
  cscript slmgr.vbs /ato
  ```
- Activate Windows 10 (1-liner) 
  ``` 
  Invoke-Command -ComputerName wvdpss01-9 -ScriptBlock { cscript C:\Windows\System32\slmgr.vbs /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX ; cscript C:\Windows\System32\slmgr.vbs /skms cltsrvkms01.roundpoint.local; cscript C:\Windows\System32\slmgr.vbs /ato; cscript C:\Windows\System32\slmgr.vbs /dli }
  ```
- Activate Office 2016 
  ``` 
  Invoke-Command -ComputerName wvdpss01-4 -ScriptBlock { cscript 'C:\Program Files\Microsoft Office\Office16\ospp.vbs' /sethst:cltsrvkms01.roundpoint.local; cscript 'C:\Program Files\Microsoft Office\Office16\ospp.vbs' /act; cscript 'C:\Program Files\Microsoft Office\Office16\ospp.vbs' /dstatusall }
  ```
- Get DNS server list 
  ``` 
  Invoke-Command -ComputerName cltfs02 -ScriptBlock { Get-DnsClientServerAddress | where {$_.serveraddresses -ne $Null} | where {$_.elementname -notlike "*Pseudo*" } | select PSComputerName,elementname,interfaceindex,serveraddresses } | ft
  ```
- Install windows admin center on server core 
  ``` 
  msiexec /i <WindowsAdminCenterInstallerName>.msi /qn /L*v log.txt SME_PORT=<port> SME_THUMBPRINT=<thumbprint> SSL_CERTIFICATE_OPTION=installed
  msiexec /i <WindowsAdminCenterInstallerName>.msi /qn /L*v log.txt SME_PORT=<port> SSL_CERTIFICATE_OPTION=generate
  ```
- list installed applications 
  ``` 
  Get-WmiObject -Class Win32_Product
  Get-WmiObject -Class Win32_Product | where vendor -eq CodeTwo | select Name, Version
  
  $InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}
  
  $InstalledSoftware = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
  foreach($obj in $InstalledSoftware){write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')}
  ```
- create 128mb dummy file 
  ``` 
  echo "This is just a sample line appended  to create a big file. " > dummy.txt
  for /L %i in (1,1,24) do type dummy.txt >> dummy.txt
  Explanation:
  The first command(echo…) creates the file dummy.txt with 64 bytes.
  The second command, runs in a loop for 24 times, and each times doubles the size of the file, by appending it to itself.
  
  ```
- Fix hidden folder 
  ``` 
  attrib -s -h F:\*.* /s /d
  ```
- Remove text from filenames 
  ``` 
  get-childitem *.pdf | foreach { rename-item $_ $_.Name.Replace("<text to remove>", "") }
  ```
- Sysprep /generalize /oobe /mode:vm /shutdown
- Get .net version 
  ``` 
  Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select PSChildName, version
  ```
- Test WinRM 
  ``` 
  Test-WSMan -ComputerName Test1-Win2k12
  ```
- Restart all msexchange services startuptype automatic
  ``` 
  $services = get-wmiobject win32_service | ? {$_.name -like "MSExchange*" -and $_.StartMode -eq "Auto"};foreach ($service in $services) {Restart-Service $service.name -Force}
  ```
- Restart all msexchange running services 
  ``` 
  $services = Get-Service | ? { $_.name -like "MSExchange*" -and $_.Status -eq "Running"};foreach ($service in $services) {Restart-Service $service.name -Force}
  ```
- Restart ALL exchange services 
  ``` 
  Get-Service *Exchange* | Where {$_.DisplayName -notlike "*Hyper-V*"} | Restart-Service -Force
  ```
- List services 
  ``` 
  Get-Service | Where {$_.DisplayName -like "*Exchange*"} | Where {$_.DisplayName -notlike "*Hyper-V*"} | Format-Table DisplayName, Name, Status
  ```
- List last 10 windows logs 
  ``` 
  "Application","Security","System" | ForEach-Object { Get-Eventlog -Newest 10 -LogName $_ } | Sort-Object -Property Time -Descending | Select-Object -First 10
  ```
- AD Password Audit 
  ``` 
  get-addomain | get-adobject -properties * | select *pwd*
  Get-ADDefaultDomainPasswordPolicy
  get-adfinegrainedpasswordpolicy -filter *
  Get-ADUserResultantPasswordPolicy netwize.admin
  ```