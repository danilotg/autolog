<#
.SYNOPSIS
   Collect traces for Windows
.DESCRIPTION
   Collect Logs/ETW/WPP traces for Windows components 
.NOTES  
   Author     : Danilo Thome (danilog@microsoft.com)
   Requires   : PowerShell V4 (Supported from Windows 8.1/Windows Server 2012 R2)
.LINK
	AutoLog https://aka.ms/AutoLog
.PARAMETER CollectLog
Collect logs for each component:
      PS> .\AutoLog.ps1 -CollectLog Basic
#>

[CmdletBinding(DefaultParameterSetName='Start')]
Param (
	[Parameter(ParameterSetName='CollectLog', Position=0)]
	[String[]]$CollectLog,
	[switch]$Defender,
	[Parameter(ParameterSetName='Help', Position=0)]
	[Switch]$Help,
#region ----- DND POD providers -----
	[switch]$DND_CBS,
	[switch]$DND_CodeIntegrity,
	[switch]$DND_PNP,
	[switch]$DND_Servicing,
#endregion ----- DND POD providers -----
#region ----- SEC POD providers -----
	[Int]$DefenderDurInMin,
#endregion ----- SEC POD providers -----
	[switch]$DebugMode,
	[Switch]$NewSession,
	[switch]$AcceptEula = $True,
	[Switch]$RemoteRun = $True
)
$global:TssVerDate = "2022.07.25.0"	# Plz. update if releasing a new POD module version TssVerDate<POD>
#region ----- SEC description -----
$TraceSwitches = [Ordered]@{
	'Basic' = 'Collect basic OS logs in general'
	'Full' = 'Collect full OS information including registry hives'
	'Wu' = 'Windows Update logs + Basic'
	'Defender' = 'Collect Defender Get-Logs'
}
#endregion ----- SEC description -----
# Create global variables for noSwitches
$noSwitchList = ($NoOPTIONS.Keys | sort)
$ControlSwitches = @(
	'AcceptEula'
	'CollectLog'
	'Compress'
	'DebugMode'
	'DefenderDurInMin'
	'Help'
	'NewSession'
)
$ControlSwitches += $noSwitchList
$TraceStatus = @{
	'Success' = 0
	'Running' = 1
	'AutoLoggerRunning' = 2
	'Started' = 3
	'Stopped' = 4
	'ErrorInStart' = 5
	'ErrorInStop' = 6
	'NotSupported' = 7
	'NoStopFunction' = 8
}
$global:LogLevel = @{
	'Normal' = 0
	'Info' = 1
	'Warning' = 2
	'Error' = 3
	'Debug' = 4
	'ErrorLogFileOnly' = 5
	'WarnLogFileOnly' = 6
	'InfoLogFileOnly' = 7
}

#------------------------------------------------------------------
#							 FUNCTIONS 
#------------------------------------------------------------------

#region common functions used by POD module
Function global:EnterFunc([String]$FunctionName){
	LogMessage $LogLevel.Debug "---> Enter $FunctionName" "Cyan"
}

Function global:EndFunc([String]$FunctionName){
	LogMessage $LogLevel.Debug "<--- End $FunctionName" "Cyan"
}

Function global:LogMessage{
	param(
		[ValidateNotNullOrEmpty()]
		[Int]$Level,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[ValidateNotNullOrEmpty()]
		[String]$Color,
		[Switch]$LogMsg=$False
	)

	If($Level -eq $Null){
		$Level = $LogLevel.Normal
	}

	If(($Level -eq $LogLevel.Debug) -and !($DebugMode.IsPresent)){
	   Return # Early return. This is LogMessage $LogLevel.Debug but DebugMode switch is not set.
	}

	Switch($Level){
		'0'{ # Normal
			$MessageColor = 'White'
			$LogConsole = $True
			$LogMessage = $Message
		}
		'1'{ # Info / Normal console message
			$MessageColor = 'Yellow'
			$LogConsole = $True
			$LogMessage = $Message  # Simple message
		}
		'2'{ # Warning
			$Levelstr = 'WARNING'
			$MessageColor = 'Magenta'
			$LogConsole = $True
		}
		'3'{ # Error
			$Levelstr = 'ERROR'
			$MessageColor = 'Red'
			$LogConsole = $True
		}
		'4'{ # Debug
			$Levelstr = 'DEBUG'
			$MessageColor = 'Green'
			If($DebugMode.IsPresent){
				$LogConsole = $True
			}Else{
				$LogConsole = $False
			}
		}
		'5'{ # ErrorLogFileOnly
			$Levelstr = 'ERROR'
			$LogConsole = $False
		}
		'6'{ # WarnLogFileOnly
			$Levelstr = 'WARNING'
			$LogConsole = $False
		}
		'7'{ # InfoLogFileOnly / Normal LogFile message
			$Levelstr = 'INFO'
			$LogMessage = $Message  # Simple message
			$LogConsole = $False
		}
	}

	# If color is specifed, overwrite it.
	If($Color -ne $Null -and $Color.Length -ne 0){
		$MessageColor = $Color
	}

	$Index = 1
	# In case of Warning/Error/Debug, add a function name and a line numberand to message.
	If($Level -eq $LogLevel.Warning -or $Level -eq $LogLevel.Error -or $Level -eq $LogLevel.Debug -or $Level -eq $LogLevel.ErrorLogFileOnly -or $Level -eq $LogLevel.WarnLogFileOnly -or $Level -eq $LogLevel.InfoLogFileOnly){
		$CallStack = Get-PSCallStack
		$CallerInfo = $CallStack[$Index]
		$2ndCallerInfo = $CallStack[$Index+1]
		$3rdCallerInfo = $CallStack[$Index+2]

		# LogMessage() is called from wrapper function like LogInfo() and EnterFun(). In this case, we show caller of the wrapper function.
		If($CallerInfo.FunctionName -notlike "*LogException" -and ($CallerInfo.FunctionName -like "global:Log*" -or $CallerInfo.FunctionName -like "*EnterFunc" -or $CallerInfo.FunctionName -like "*EndFunc")){
			$CallerInfo = $2ndCallerInfo # Set actual function name calling LogInfo/LogWarn/LogError
			If($CallerInfo.FunctionName -like "*LogException"){
				$CallerInfo = $3rdCallerInfo
			}
		}
		$FuncName = $CallerInfo.FunctionName.Replace("global:","")
		If($FuncName -eq "<ScriptBlock>"){
			$FuncName = "Main"
		}

		# If this is from POD module, add the module name in front of the function name.
		If($CallerInfo.ScriptName -notlike "*$global:ScriptName"){ # ScriptName = 'AutoLog.ps1'
			$FuncName = (((Split-path $CallerInfo.ScriptName -leaf) -replace "AutoLog_","") + ":" + $FuncName)
		}
		$LogMessage = ((Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + ' [' + $FuncName + '(' + $CallerInfo.ScriptLineNumber + ')]'+ " $Levelstr" + ": " + $Message)
	}Else{
		$LogMessage = (Get-Date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $Message
	}

	If($LogConsole){ #we# may need additional check for '-and !(running in Azure serial Console)' ? (#675)
		Write-Host $LogMessage -ForegroundColor $MessageColor
	}

	# In case of error, warning, ErrorLogFileOnly, WarnLogFileOnly and InfoLogFileOnly, we log the message to error log file.
	If(![String]::IsNullOrEmpty($global:LogFolder) -and $LogMsg){
		If(!(Test-Path -Path $global:LogFolder)){
			FwCreateLogFolder $global:LogFolder
		}
		If($global:ErrorLogFile -ne $Null){
			If(!(Test-Path $global:ErrorLogFile)){
				New-Item $global:ErrorLogFile -type file -Force | Out-Null
			}
			$LogMessage | Out-File -Append $global:ErrorLogFile
		}Else{
			Write-Host "ErrorLogFile is not initalized."
		}
	}
}

Function global:LogInfo{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.info $Message
	}Else{
		LogMessage $Loglevel.info $Message $Color
		#_# Accessibility Mode -Assist
		if ($global:ParameterArray -Contains 'Assist') { Add-Type -AssemblyName System.Speech; (New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak("$Message") }
	}
}

Function global:LogWarn{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.Warning $Message -LogMsg
	}Else{
		LogMessage $Loglevel.Warning $Message $Color -LogMsg
	}
}

Function global:LogError{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.Error $Message -LogMsg
	}Else{
		LogMessage $Loglevel.Error $Message $Color -LogMsg
	}
}

Function global:LogDebug{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.Debug $Message
	}Else{
		LogMessage $Loglevel.Debug $Message $Color
	}
}

Function global:LogInfoFile {
	#we# to write additional info to $global:ErrorLogFile
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	# In case of -Status, we won't log message to log file to prevent log folder from being created.
	If($Status.IsPresent){
		Return # Early return 
	}

	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.InfoLogFileOnly $Message -LogMsg
	}Else{
		LogMessage $Loglevel.InfoLogFileOnly $Message $Color -LogMsg
	}
}

Function global:LogWarnFile {
	#we# to write additional warning to $global:ErrorLogFile
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.WarnLogFileOnly $Message -LogMsg
	}Else{
		LogMessage $Loglevel.WarnLogFileOnly $Message $Color -LogMsg
	}
}

Function global:LogErrorFile {
	#we# to write additional error to $global:ErrorLogFile
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$false)] # color is just optional.
		[String]$Color
	)
	If([string]::IsNullOrEmpty($Color)){
		LogMessage $Loglevel.ErrorLogFileOnly $Message -LogMsg
	}Else{
		LogMessage $Loglevel.ErrorLogFileOnly $Message $Color -LogMsg
	}
}

Function global:LogException{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.ErrorRecord]$ErrObj,
		[Bool]$fErrorLogFileOnly
	)
	$ErrorCode = "0x" + [Convert]::ToString($ErrObj.Exception.HResult,16)
	$ExternalException = [System.ComponentModel.Win32Exception]$ErrObj.Exception.HResult
	$ErrorMessage = $Message + "`n" `
		+ "Command/Function: " + $ErrObj.CategoryInfo.Activity + " failed with $ErrorCode => " + $ExternalException.Message + "`n" `
		+ $ErrObj.CategoryInfo.Reason + ": " + $ErrObj.Exception.Message + "`n" `
		+ "ScriptStack:" + "`n" `
		+ $ErrObj.ScriptStackTrace
	If($fErrorLogFileOnly){
		LogErrorFile $ErrorMessage
	}Else{
		LogError $ErrorMessage
	}
}

Function global:LogExceptionFile{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.ErrorRecord]$ErrObj
	)
	$ErrorCode = "0x" + [Convert]::ToString($ErrObj.Exception.HResult,16)
	$ExternalException = [System.ComponentModel.Win32Exception]$ErrObj.Exception.HResult
	$ErrorMessage = $Message + "`n" `
		+ "Command/Function: " + $ErrObj.CategoryInfo.Activity + " failed with $ErrorCode => " + $ExternalException.Message + "`n" `
		+ $ErrObj.CategoryInfo.Reason + ": " + $ErrObj.Exception.Message + "`n" `
		+ "ScriptStack:" + "`n" `
		+ $ErrObj.ScriptStackTrace
	LogErrorFile $ErrorMessage
}

Function global:FwIsElevated{
	$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent();
	$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity);
	$administratorRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator;
	return $currentPrincipal.IsInRole($administratorRole);
}

Function global:FwIsSupportedOSVersion{
	[OutputType([Bool])]
	param(
		[parameter(Mandatory=$true)]
		[AllowNull()]
		[Hashtable]$SupportedOSVersion
	)
	EnterFunc $MyInvocation.MyCommand.Name

	[Version]$Global:OSVersion = [environment]::OSVersion.Version
	[Bool]$fResult = $False

	If($OSVersion -eq $Null){
		$fResult = $True 
		$SupportVersionStr = 'Any'
	}Else{
		$SupportVersionStr = $SupportedOSVersion.OS.ToString() + "." + $SupportedOSVersion.Build.ToString()
	}
	LogDebug ("Current OS = " + $OSVersion.Major + "." + $OSVersion.Build + "   Supported OS = " + $SupportVersionStr)

	If($OSVersion.Major -ge $SupportedOSVersion.OS -and $OSVersion.Build -ge $SupportedOSVersion.Build){
		$fResult =  $True
	}
	If($fResult){
		LogDebug ('This command is supported.')
	}Else{
		LogDebug ('Warning: This command not supported.')
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function FwRunAdminCheck{
	EnterFunc $MyInvocation.MyCommand.Name
	If(!(FwIsElevated)){
		LogInfo 'This script needs to run from elevated command/PowerShell prompt.' "Red"
		If($Host.Name -match "ISE Host"){
			LogInfo "Exiting on ISE Host."
			CleanUpandExit
		}
		If(!$noAsk.IsPresent){
			# Issue#373 - AutoLog hang in ISE
			$Answer = FwRead-Host-YN -Message "Do you want to re-run AutoLog from elevated PowerShell? (timeout=10s)" -Choices 'yn' -TimeOut 10
			#CHOICE /T 10 /C yn /D y /M " Do you want to re-run AutoLog from elevated PowerShell?"
			If(!$Answer){
				LogInfoFile "=== User declined to run AutoLog from elevated PowerShell ==="
				LogInfo "Run script from elevated command or PowerShell prompt" "Red"
				CleanUpandExit
			}
		}
		$cmdline = $Script:AutoLogCommandline.Replace($MyInvocation.InvocationName,$MyInvocation.MyCommand.Path)
		Start-Process "PowerShell.exe" -ArgumentList " -noExit $cmdline" -Verb runAs	#fix #355
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetProductTypeFromReg{
	switch ((Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\ProductOptions).ProductType)
	{
	  "WinNT" {
			return "WinNT"
		}
	  "ServerNT" {
			return "ServerNT"
		}
	  "LanmanNT" {
			return "LanmanNT"
		}
	  Default {
		"EmptyProductType"
		}
	}
}

Function global:RunCommands{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogPrefix,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String[]]$CmdletArray,
		[parameter(Mandatory=$false)]
		[Bool]$ThrowException=$false,
		[parameter(Mandatory=$false)]
		[Bool]$ShowMessage=$True,
		[parameter(Mandatory=$False)]
		[Bool]$ShowError=$False
	)
	EnterFunc $MyInvocation.MyCommand.Name
	ForEach($CommandLine in $CmdletArray){
		# Get file name of output file. This is used later to add command header line.
		$HasOutFile = $CommandLine -like "*Out-File*"
		If($HasOutFile){
			$OutputFile = $Null
			$Token = $CommandLine -split ' '
			$OutputFileCandidate = $Token[$Token.count-1] # Last token should be output file.
			#If($OutputFileCandidate -like '*.txt*' -or $OutputFileCandidate -like '*.log*'){
			If($OutputFileCandidate -match '\.txt' -or $OutputFileCandidate -match '\.log'){
				$OutputFile = $OutputFileCandidate
				#$OutputFile= $OutputFile -replace ('^"','')
			}
		}
		$tmpMsg = $CommandLine -replace "\|.*Out-File.*$",""
		$tmpMsg = $tmpMsg -replace "\| Out-Null.*$",""
		$tmpMsg = $tmpMsg -replace "\-ErrorAction Stop",""
		$tmpMsg = $tmpMsg -replace "\-ErrorAction SilentlyContinue",""
		$tmpMsg = $tmpMsg -replace "\-ErrorAction Ignore",""
		$tmpMsg = $tmpMsg -replace "cmd /r ",""
		$CmdlineForDisplayMessage = $tmpMsg -replace "2>&1",""

		# In case of reg.exe, see if it is available can be run.
		$cmd = ($CommandLine -split ' ')[0]
		If($cmd -eq 'reg' -or $cmd -eq 'reg.exe'){
			If(!$global:RegAvailable){
				LogInfo "Skipping running `'$CommandLine`' as reg command is not available on this system."
				Continue
			}
		}

		Try{
			If($ShowMessage){
				LogInfo ("[$LogPrefix] Running $CmdlineForDisplayMessage")
			}
			If($DebugMode.IsPresent){
				LogDebug "Running $CommandLine"
			}
			# There are some cases where Invoke-Expression does not reset $LASTEXITCODE and $LASTEXITCODE has old error value. 
			# Hence we initialize the $LASTEXITCODE(PowerShell managed value) if it has error before running command.
			If($global:LASTEXITCODE -ne $Null -and $global:LASTEXITCODE -ne 0){
				$global:LASTEXITCODE = 0
			}
			# Add a header if there is an output file.
			If($OutputFile -ne $Null){
				Write-Output "======================================" | Out-File -Append $OutputFile
				Write-Output "$((Get-Date).ToString("yyyyMMdd HH:mm:ss.fff")) : $CmdlineForDisplayMessage" | Out-File -Append $OutputFile
				Write-Output "======================================" | Out-File -Append $OutputFile
			}
			# Run actual command here.
			# We redirect all streams to temporary error file as some commands output an error to warning stream(3) and others are to error stream(2).
			Invoke-Expression -Command $CommandLine -ErrorAction Stop *> $TempCommandErrorFile

			# It is possible $LASTEXITCODE becomes null in some sucessful case, so perform null check and examine error code.
			If($global:LASTEXITCODE -ne $Null -and $global:LASTEXITCODE -ne 0){
				$Message = "An error happened during running `'$CommandLine` " + '(Error=0x' + [Convert]::ToString($global:LASTEXITCODE,16) + ')'
				LogErrorFile $Message
				If(Test-Path -Path $TempCommandErrorFile){
					# Always log error to error file.
					Get-Content $TempCommandErrorFile -ErrorAction Ignore | Out-File -Append $global:ErrorLogFile
					# If -ShowError:$True, show the error to console.
					If($ShowError -or $DebugMode.IsPresent){
						LogInfo ($Message) "Red"
						Write-Host ('---------- ERROR MESSAGE ----------')
						Get-Content $TempCommandErrorFile -ErrorAction Ignore
						Write-Host ('-----------------------------------')
					}
				}
				Remove-Item $TempCommandErrorFile -Force -ErrorAction Ignore | Out-Null

				If($DebugMode.IsPresent){
					Read-Host ("[DBG - hit ENTER to continue] Error happened in Runcommands. See above error message")
				}
				If($ThrowException){
					Throw($Message)
				}
			}Else{
				Remove-Item $TempCommandErrorFile -Force -ErrorAction Ignore | Out-Null
			}
		}Catch{
			If($DebugMode.IsPresent){
				Read-Host ("[DBG - hit ENTER to continue] Exception in Runcommands")
			}
			If($ThrowException){
				Throw $_   # Leave the error handling to upper function.
			}Else{
				$Message = "An error happened in Invoke-Expression with $CommandLine"
				LogException ($Message) $_ $fLogFileOnly
				If($ShowError){
						Write-Host ("ERROR: $Message") -ForegroundColor Red
						Write-Host ('---------- ERROR MESSAGE ----------')
						$_
						Write-Host ('-----------------------------------')
				}
				Continue
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwCreateFolder{
	<#
	.SYNOPSIS
		Creates Folder on the given path and handles various problems that might occur during that operation.
	.DESCRIPTION
		The Function will check if the folder on the given path exists and if it does NOT exist it will create it.
		global:FwCreateFolder expects 1 parameter: $Path
	.EXAMPLE
		
	.NOTES
		Date:   01.04.2021
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Path
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if (!(Test-Path $Path)){
		Try{
			New-Item -ItemType directory -Path $Path | Out-Null
		}Catch{
			LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
			return
		}
		if (!(Test-Path $Path))
		{
			LogInfo ("New log folder " + $Path + " is NOT created! Something went wrong!")
		}
		else
		{
			LogDebug ("New log folder " + $Path + " created")
		}
	}
	else
	{
		LogDebug ($Path + " -- Note: this Folder already exists")
		LogInfo ($Path + " -- Note: this Folder already exists") "Cyan"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwNew-TemporaryFolder {
	 <#
	.SYNOPSIS
	 Creates a temporary subfolder underneath $RelativeFolder 
	.DESCRIPTION
	 Creates a temporary subfolder underneath $RelativeFolder; if parameter $RelativeFolder is empty it creates the folder in $Env:temp.
	 This is useful for temporary folders, i.e. needed for $LogTTD 
	.EXAMPLE
	 FwNew-TemporaryFolder -RelativeFolder "%localappdata%\AutoLog"
	.PARAMETER RelativeFolder
	 The full path to the top folder for the new temporary subfolder.
	 #>
	param(
		$RelativeFolder = $Env:temp
	)
	# Make a new folder based upon a TempFileName
	$T="$($RelativeFolder)\tmp$([convert]::tostring((get-random 65535),16).padleft(4,'0')).tmp"
	New-Item -ItemType Directory -Path $T
}

Function global:FwCreateLogFolder{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[string]$LogFolder
	)
	$CallStack = Get-PSCallStack
	$CallerInfo = $CallStack[1]
	If($CallerInfo.FunctionName -eq '<ScriptBlock>'){
		 $FuncName = 'Main'
	}Else{
		$FuncName = $CallerInfo.FunctionName
	}
	EnterFunc ("$($MyInvocation.MyCommand.Name)" + "(Caller - $($FuncName):$($CallerInfo.ScriptLineNumber))")
	If(!(test-path -Path $LogFolder)){
		#LogInfo ".. creating log folder $LogFolder" # LogInfoFile would fail as $LogFolder does not exist
		New-Item $LogFolder -ItemType Directory -ErrorAction Stop | Out-Null
		LogDebug ".. created log folder $LogFolder"
	}Else{
		LogDebug ("$LogFolder already exist.")
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwCopyFiles{
	<#
	.SYNOPSIS
		The function copies Source to Destination defined in [System.Collections.Generic.List[Object]]$SourceDestination

	.DESCRIPTION
		The function copies Source to Destination defined in [System.Collections.Generic.List[Object]]$SourceDestination
		If source member containes * character, the function will copy all files that match critieria to the destination folder (folder path).
		If source file does not contains * character, the function will simply copy source file (file path) to destination (file path).

		global:FwCopyFiles expects 1 parameters: [System.Collections.Generic.List[Object]]$SourceDestination
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[Object]]$SourceDestination,
		[Bool]$ShowMessage=$True
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($SourceDestination.Count -eq 0){
		LogWarn "No file name to copy passed."
		Return
	}

	foreach ($item in $SourceDestination)
	{
		If($item.gettype().BaseType.Name -ne "Array"){
			LogWarn "Copied files and destination need to be passed as array but `'$item`' isn't an array"
			continue
		}

		$filename = Split-Path $item[0] -Leaf
		$foldername = Split-Path $item[0]
		Try{
			if (($item[0].ToCharArray()) -contains '*'){ #wildcard copy
					if (!((Test-Path $foldername) -and (Test-Path $item[1]))){
						if (!(Test-Path $foldername)) {
							LogInfoFile "Skipping copying files as folder `'$foldername`' does not exist."
							continue
						}
						if (!(Test-Path $item[1])) {
							LogInfoFile "Skipping copying files as file `'$($item[1])`' does not exist."
							continue
						}
					}
					If($ShowMessage){LogInfo "Copying $($item[0]) to $($item[1])"}
					Copy-Item -Path $item[0] -Destination $item[1] -Recurse -Force 2>&1 | Out-Null
					#Get-ChildItem -Path $item[1] -Filter $filename | Rename-Item -NewName {$global:LogPrefix + $_.Name}
			}
			else {
					if (!((Test-Path $item[0]) -and (Test-Path $foldername))){
						if (!(Test-Path $item[0])) {
							LogInfoFile "Skipping copying files as file `'$($item[0])`' does not exist."
							continue
						}
						if (!(Test-Path $foldername)) {
							LogInfoFile "Skipping copying files as folder `'$foldername`' does not exist."
							continue
						}
					}
					If($ShowMessage){LogInfo "Copying $($item[0]) to $($item[1])"}
					Copy-Item -Path $item[0] -Destination $item[1] -Force 2>&1 | Out-Null
			}
		}Catch{
			$Message = "Failed to copy $($item[0])"
			LogWarn $Message
			LogException $Message $_ $fLogFileOnly
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetDSregCmd {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	If($global:OSVersion.Major -ge 10){ # Commands from Windows 10
		LogInfo "[$($MyInvocation.MyCommand.Name)] running 'DSregcmd /status' at $TssPhase"
		if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "DSregCmd" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_DSregCmd.txt"}
		$Commands += @(
			"dsregcmd.exe /status -ErrorAction Ignore | Out-File -Append $outFile"	#ToDo: need to ignore error msg
			"dsregcmd.exe /status /debug /all -ErrorAction Ignore | Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	} else { LogInfoFile "dsregcmd.exe is not available in downlevel OS"}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetOperatingSystemInfo{
	<#
	.SYNOPSIS
		Collect Operating System info from the monitored machines and returns it to the caller.
	.DESCRIPTION
		Collect Operating System info from the monitored machines and stores it in global:FwBuildInfo variable
	.EXAMPLE
		Framework always runs this function at start and sets global:OperatingSystemInfo
	.NOTES
		Date:   20.04.2021
	#>
	EnterFunc $MyInvocation.MyCommand.Name
	# *** OperatingSystem info 
	$OSInfo = New-Object System.Collections.Generic.Dictionary"[String,String]"
	$OSInfo.Add("ProductName",(Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ProductName)
	$OSInfo.Add("OSVersion", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentMajorVersionNumber)
	$OSInfo.Add("CurrentVersion", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentVersion)
	$OSInfo.Add("ReleaseId", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ReleaseId)
	$OSInfo.Add("BuildLabEx", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").BuildLabEx  )
	$OSInfo.Add("CurrentBuildHex", (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").CurrentBuild)
	EndFunc ($MyInvocation.MyCommand.Name + "($OSInfo)")
	return $OSInfo
}

Function global:FwGetBuildInfo {
	EnterFunc ($MyInvocation.MyCommand.Name)
	$outFile = $PrefixTime + "BuildInfo.txt"
	FwGetOperatingSystemInfo | Out-File -Append $outFile
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetHotfix {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] running 'Get-Hotfix'"
	$outFile = $PrefixTime + "Hotfixes.txt"
	Get-Hotfix | Out-File -Append $outFile -Encoding ascii -Width 200
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetLogmanInfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfoFile "[$($MyInvocation.MyCommand.Name)] running 'logman query -ets' at $TssPhase"
	$outFile = $PrefixTime + "LogmanInfo" + $TssPhase + ".txt"
	try {logman query -ets | Out-File -Append $outFile -Encoding ascii -Width 200; $TotProvCnt=$($(logman query -ets).count -5); "`nTotal # of Sessions: " + $TotProvCnt| Out-File -Append $outFile -Encoding ascii; if ($TotProvCnt -gt 55) {write-host -ForegroundColor red "[ERROR]: This data collection exceeds 55 ETL Trace Sessions, stop unnecessary ones.`nTo do so, stop current AutoLog, run 'Logman Query -ets', then: Logman stop -ets -n 'name of unrelated ETL session', then restart AutoLog"} } 
	catch {Throw $error[0].Exception.Message; exit 1}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetPowerCfg {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting Power Configuration settings at $TssPhase"
	$outFile = $PrefixTime + "PowerConfig" + $TssPhase + ".txt"
	$Commands = @(
		"PowerCfg.exe /list 2>&1	| Out-File -Append $outFile"
		"PowerCfg.exe /a 2>&1		| Out-File -Append $outFile"
		"PowerCfg.exe /qh 2>&1		| Out-File -Append $outFile"
		)
	if (!$IsServerSKU) {
		$Commands += @(
			"PowerCfg.exe /sleepstudy /duration 14 /output $PrefixTime`Powercfg-sleepstudy.html 2>&1"
		)
	}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	$PowerKeys = @(
		('HKLM:System\CurrentControlSet\Control\Power', "$PrefixCn`Reg_Power.txt"),
		('HKLM:System\CurrentControlSet\Control\Session Manager\Power', "$PrefixCn`Reg_SessMgr_Power.txt")
	)
	FwExportRegistry $LogPrefix $PowerKeys
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGetSrvWkstaInfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] Collecting IP/Server/Workstation infos at $TssPhase"
	$outFile = $PrefixTime + "IP_Srv_Wks_Info" + $TssPhase + ".txt"
	$Commands = @(
		"IPCONFIG /ALL 						| Out-File -Append $outFile"
		"netsh interface IP show config 	| Out-File -Append $outFile"
		"netsh interface IPv4 show int 		| Out-File -Append $outFile"
		"netsh interface IPv4 show subint 	| Out-File -Append $outFile"
		"Route Print 						| Out-File -Append $outFile"
		"IPCONFIG /DisplayDNS 				| Out-File -Append $outFile"
		"NETSTAT -anob 						| Out-File -Append $outFile"
		"arp -a -v 							| Out-File -Append $outFile"
	)
	If($OSVER3 -ge 9600){ $Commands += @( "NETSTAT -anoq 						| Out-File -Append $outFile") }
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	$LMServerStatus = (Get-Service -Name "LanmanServer").status
	if ($LMServerStatus -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
		$Commands = @(
			"NET CONFIG SERVER 					| Out-File -Append $outFile"
			"NET SESSION 						| Out-File -Append $outFile"
			"Get-SmbShare | select Name, FolderEnumerationMode, Path, ShareState, ScopeName, CachingMode, LeasingMode, ContinuouslyAvailable, CATimeout, AvailabilityType |ft -auto |Out-String -Width 999 | Out-File -Append $outFile"
			"Get-SmbShare | select Name, EncryptData, SecurityDescriptor, Description |ft -auto |Out-String -Width 999 | Out-File -Append $outFile"
			"Get-SmbShare -ErrorAction SilentlyContinue | fl * | Out-File -Append $($PrefixTime + "SMBshare_Info" + $TssPhase + ".txt")"
		)
		if ($global:ProductType -ne "LanmanNT") {
			$Commands += @(
				"NET USER | Out-File -Append $outFile"
			)
		} else { LogInfo "[$($MyInvocation.MyCommand.Name)] ProductType: $global:ProductType - skip NET USER on BDC or PDC"}
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	} 
	else { LogInfo "[$($MyInvocation.MyCommand.Name)] [FAIL] LanmanWorkstation is not started" }
	$WKSStatus = (Get-Service -Name "LanmanWorkstation").status
	if ($WKSStatus -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
		$Commands = @(
		"NET USE 						| Out-File -Append $outFile"
		"NET CONFIG WKSTA 				| Out-File -Append $outFile"
		"NET STATISTICS Workstation 	| Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		$outFile = $PrefixTime + "SmbConnection" + $TssPhase + ".txt"
		Get-SmbConnection 				| Out-File -Append $outFile
	} 
	else { LogInfo "[$($MyInvocation.MyCommand.Name)] [FAIL] LanmanWorkstation is not started" }
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportRegistry{
	<#
	.SYNOPSIS
		Exports registry key to log file(s) by using REG QUERY or REG EXPORT (-RealExport $true)
	.DESCRIPTION
		If $RegKeysAndLogfileArray(2nd argument) has a set of reg key and log file like 
		below example of Case 1, this function exports multiple keys to each corresponding log file.

		If the array does not have file and just an array of reg keys, this function requires 
		$Logfile(3rd argument) and exports all keys into the single file specified by $LogFile (Case 2).
		FwExportRegToOneFile() function has the same functionality.
	.PARAMETER RealExport
		If you need to export large key structures like HKLM\SOFTWARE it's way faster if you append
		the parameter -RealExport $true to the function call. This will use REG EXPORT then, instead of REG QUERY
		-RealExport will overwrite any existing file. See Case 4.


	.EXAMPLE
		There are multiple ways to use this function.
		Case 1: Export multiple registry keys to each corresponding log file.
		$RegKeys = @(
			('HKLM:System\CurrentControlSet\Control\CrashControl', "$LogFolder\_Reg_CrashControl.txt"),
			('HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management', "$LogFolder\_Reg_MemoryManagement.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug', "$LogFolder\_Reg_AeDebug.txt")
		)
		FwExportRegistry "MyLogPrefix" $RegKeys

		Case 2: Export single or multiple registry keys to a single file. But better way for this usage is to use FwExportRegToOneFile().
		$RegKeys = @(
			'HKLM:System\CurrentControlSet\Control\CrashControl',
			'HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management',
			'HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug'
		)
		FwExportRegistry "MyLogPrefix" $RegKeys "$LogFolder\_Reg_Recovery.txt"
			
		Case 3: Export multiple registry keys and a property to each corresponding log file.
		$RegKeys = @(
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'BuildLab', "$PrefixCn`Reg_BuildInfo.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'BuildLabEx', "$PrefixCn`Reg_BuildInfo.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'UBR', "$PrefixCn`Reg_BuildInfo.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion', 'ProductName', "$PrefixCn`Reg_BuildInfo.txt"),
			('HKLM:Software\Microsoft\Windows\CurrentVersion\AppModel', 'Version', "$PrefixCn`Reg_AppModelVersion.txt")
		)
		FwExportRegistry "MyLogPrefix" $RegKeys

		Case 4: Use "reg export" instead "reg query". -RealExport will overwrite any existing file
		$RegKeys = @(
			('HKLM:System\CurrentControlSet\Control\CrashControl', "$LogFolder\_Reg_CrashControl.txt"),
			('HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management', "$LogFolder\_Reg_MemoryManagement.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug', "$LogFolder\_Reg_AeDebug.txt")
		)
		FwExportRegistry "MyLogPrefix" $RegKeys -RealExport $true

	.NOTES
		Date:   30.11.2021
	#>
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogPrefix,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Array]$RegKeysAndLogfileArray,
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[String]$LogFile=$Null,
		[Bool]$ShowMessage=$True,
		[parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[Bool]$RealExport
	)
	EnterFunc $MyInvocation.MyCommand.Name
	ForEach($RegKeyAndLogFile in $RegKeysAndLogfileArray){
		If($RegKeyAndLogFile.Count -eq 3){ # Case for exporting to multiple files and properties.
			$ExportKey = $RegKeyAndLogFile[0] # Reg key
			$Property = $RegKeyAndLogFile[1]   # Property name
			$OutFile = $RegKeyAndLogFile[2]   # Output file name
			$ExportProperty = $true
		}ElseIf($RegKeyAndLogFile.Count -eq 2){ # Case for exporting to multiple files.
			$ExportKey = $RegKeyAndLogFile[0] # Reg key
			$OutFile = $RegKeyAndLogFile[1]   # Output file name
		}ElseIf($RegKeyAndLogFile.Count -eq 1){ # Case for exporting to one file(always use $LogFile).
			$ExportKey = $RegKeyAndLogFile
			$OutFile = $LogFile
		}
		LogDebug "Exporting Reg=$ExportKey LogFile=$LogFile"

		If(!(Test-Path -Path $ExportKey)){
		   #LogInfo "[$($MyInvocation.MyCommand.Name)] `'$ExportKey`' does not exist."
			"[WARNING] `"$ExportKey`" does not exist." | Out-File -Append $OutFile	#we# report to file
			Continue
		}
		$ExportKey = Convert-Path -Path $ExportKey

		# RunCommands takes care of header added to a log file. So we don't add a header here.
		#Write-Output "=== $((Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) : REG QUERY $ExportKey /s" | Out-File $LogFile -Append
		If ($ExportProperty -eq $true) {
			$Commands = @(
				"REG QUERY `"$ExportKey`" /v `"$Property`" | Out-File -Append $OutFile"
			)	
		}Else{
			$Commands = @(
				if ($RealExport) {
					"REG EXPORT `"$ExportKey`" `"$OutFile`" /y 2>&1 | Out-Null"
				} else {
				   "REG QUERY `"$ExportKey`" /s | Out-File -Append $OutFile"
				}
			)
		}
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$ShowMessage

		# We keep below code for the export using Get-ChildItem for a while just in case of future use.
		#Try{
		#	$Key = Get-Item $ExportKey -ErrorAction Stop
		#}Catch{
		#	LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
		#	Continue
		#}
		#
		#Write-Output("[" + $Key.Name + "]") | Out-File -Append $LogFile
		#ForEach($Property in $Key.Property){
		#	Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
		#}
		#
		#Try{
		#	$ChildKeys = Get-ChildItem $ExportKey -Recurse -ErrorAction Stop
		#}Catch{
		#	LogException ("Error: An exception happens in Get-ChildItem $RegistryKey.") $_ $fLogFileOnly
		#	Continue 
		#}
		#
		#ForEach($ChildKey in $ChildKeys){
		#	Write-Output("[" + $ChildKey.Name + "]") | Out-File -Append $LogFile
		#	Try{
		#		$Key = Get-Item $ChildKey.PSPath -ErrorAction Stop
		#	}Catch{
		#		LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
		#		Continue
		#	}
		#	ForEach($Property in $Key.Property){
		#		Try{
		#			Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
		#		}Catch{
		#			LogException ("Error: An exception happens in Write-Output $Key.") $_ $fLogFileOnly
		#		}
		#	}
		#}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportRegToOneFile{
	<#
	.SYNOPSIS
		Exports registry key to a single log file by using REG QUERY
	.DESCRIPTION
		This is a wrapper function for FwExportRegistry. Requires $Logfile(3rd argument). 
		Exports all reg keys into the single file specified by $LogFile.

	.EXAMPLE
		$RegKeys = @(
			'HKLM:System\CurrentControlSet\Control\CrashControl',
			'HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management',
			'HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug'
		)
		FwExportRegToOneFile "TEST" $RegKeys "$LogFolder\_Reg_Recovery.txt"
	.NOTES
		Date:   27.07.2021
	#>
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogPrefix,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Array]$RegistryKeys,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogFile,
		[Bool]$ShowMessage
	)
	EnterFunc $MyInvocation.MyCommand.Name
	FwExportRegistry $LogPrefix $RegistryKeys -LogFile $LogFile -ShowMessage:$ShowMessage

	# We keep below code for the export using Get-ChildItem for a while just in case of future use.
	#ForEach($RegistryKey in $RegistryKeys){
	#	If(!(Test-Path -Path $RegistryKey)){
	#		LogWarnFile ("$RegistryKey does not exist.")
	#		Continue
	#	}
	#	If($ShowMessage){
	#		LogInfo ("[$LogPrefix] Exporting $RegistryKey")
	#	}
	#	Try{
	#		$Key = Get-Item $RegistryKey -ErrorAction Stop
	#	}Catch{
	#		LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
	#		Continue
	#	}
	#   
	#	Write-Output("[" + $Key.Name + "]") | Out-File -Append $LogFile
	#	ForEach($Property in $Key.Property){
	#		Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
	#	}
	#
	#	Try{
	#		$ChildKeys = Get-ChildItem $RegistryKey -Recurse -ErrorAction Stop
	#	}Catch{
	#		LogException ("Error: An exception happens in Get-ChildItem $RegistryKey.") $_ $fLogFileOnly
	#		Return # This is critical and return.
	#	}
	#
	#	ForEach($ChildKey in $ChildKeys){
	#		Write-Output("[" + $ChildKey.Name + "]") | Out-File -Append $LogFile
	#		Try{
	#			$Key = Get-Item $ChildKey.PSPath -ErrorAction Stop
	#		}Catch{
	#			LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
	#			Continue
	#		}
	#		ForEach($Property in $Key.Property){
	#			Try{
	#				Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
	#			}Catch{
	#				LogException ("Error: An exception happens in Write-Output $Key.") $_ $fLogFileOnly
	#			}
	#		}
	#	}
	#}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-RegistryValue {
	<#
	.SYNOPSIS
		Fetsches reg value from the registry key
	.DESCRIPTION
		FwGet-RegistryValue expects 2 parameters: $Path and $Value
	.EXAMPLE
	# Ex: FwGet-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath
	#>
	param (
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$Path,
		[parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]$Value
	)

	if (Test-Path -path $Path) {
		return Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction "SilentlyContinue"
	}
	else {
		return $false
	}
}

Function global:FwTestRegistryValue($key,$name){
	<#
	.SYNOPSIS
		Test, if a reg value exists for reg.name $name under the registry key $key
	.DESCRIPTION
		returns $True if $name exists
	.EXAMPLE
		FwTestRegistryValue "HKCU:\Software\Sysinternals\Process Monitor" "Logfile"
	#>
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		if(Get-Member -InputObject (Get-ItemProperty -Path $key) -Name $name -ErrorAction SilentlyContinue) 
		{
			LogInfoFile ("[$($MyInvocation.MyCommand.Name)] RegCheck is True: $key\$name")
			return $true
		}
	}Catch{
			LogException ("Error: An exception happens in Get-ItemProperty -Path $key.") $_ $fLogFileOnly
			LogWarn "[$($MyInvocation.MyCommand.Name)] reg value $key '$name' does not exist"
			Continue
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($false)")
	return $false
}

function global:FwAddRegItem {
	<#
	.SYNOPSIS
		Adds new Registry item(s) to the global list of registry keys to be collected
	.DESCRIPTION
		Adds new Registry item(s) to the list of registry keys to be collected at Collect Phase ($global:RegKeysModules array)
		Parameter TssPhase is optional. FW will use _Start_ or _Stop_, depending on phase of datacollection.
		Individual RegKeysModules aredefined in <_POD.psm1> specific #region Registry Keys modules
	.EXAMPLE
		global:FWaddRegItem @("Tcp", "Rpc")
	#>
	param(
		[Parameter(Mandatory=$True)]
		[String[]]$AddToRegKeyModules,	# which Reg module(s) to add to $global:RegKeysModules, i.e @("Tcp") or @("Tcp", "Rpc")
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase		# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] adding Registry item(s): $AddToRegKeyModules at $TssPhase"
	$global:RegKeysModules += $AddToRegKeyModules
	LogDebug "___ after FWaddRegItem, list: $global:RegKeysModules"
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetRegList {
	<# 
	.SYNOPSIS 
		Bulk collection of Registry keys at Collect Phase
	.DESCRIPTION
		It will process FwExportRegToOneFile for each RegKey module at phase TssPhase.
		You can add Registry keys to this list using function FWaddRegItem
	.EXAMPLE
		FWgetRegList _Stop_
	#>
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if ($global:RegKeysModules.count -gt 0){
		if ($TssPhase -eq '_Stop_') { global:FWaddRegItem "KIRMyKnobs" $TssPhase }
		LogInfo "[$($MyInvocation.MyCommand.Name)] Processing Registry output Logs at $($TssPhase)"
		LogInfoFile "___ RegKeysModules before: $global:RegKeysModules"
		$RegKeysSum = $global:RegKeysModules |sort -Unique
		LogInfoFile "___ UniqueRegList at $TssPhase : $RegKeysSum"
		foreach ($module in $RegKeysSum) {	# dynamic variables
			Set-Variable -Name ("Keys"  + $module) -scope Global
			$Keys = Get-Variable -Scope Global -Name ("Keys" + $module) -ValueOnly
			LogDebug "___ at $TssPhase : RegModule_short = $module - RegModuleName = Keys$module -- RegModuleValue = $Keys" #we# 
			$KeyFileName = $PrefixTime + "Reg_" + $module + $TssPhase +".txt"
			LogInfoFile "___ resulting Keys $module : $Keys"
			LogDebug "___ Reg KeyFileName: $KeyFileName"
			$duration = Measure-Command {
			 ($Keys) | ForEach-Object { FwExportRegToOneFile $LogPrefix $_ $KeyFileName -ShowMessage:$False}
			}
			LogInfoFile "___ [$duration FwExportRegToOneFile]: $module"
		}
		LogInfoFile "___ done all RegKeysModules: $RegKeysSum"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportEventLog{
	#we# ToDo: - better consolidate FwExportSingleEventLog and FwExportEventLog into one function
	#		   - currently Get-Winevent produces different results on Win11 and Srv2022, maybe related to bug #35871962 - Problems with PowerShell EventLogReader command ..
	<# .SYNOPSIS
		Exports one or more EventLogs in evtx format and calls FwExportEventLogWithTXTFormat (unless -noEventConvert)
	.DESCRIPTION
		global:FwExportEventLog expects 2 mandatory parameters: $EventLogArray and 2 optional parameters $ExportFolder, $NoExportWithText
	.EXAMPLE
		FwExportEventLog @("Microsoft-Windows-NTFS/Operational","Microsoft-Windows-NTFS/WHC") $global:LogFolder
	#>
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[Array]$EventLogArray,
		[Parameter(Mandatory=$False)]
		[ValidateNotNullOrEmpty()]
		[String]$ExportFolder = $global:LogFolder, #we# add default
		[Parameter(Mandatory=$False)]
		[Switch]$NoExportWithText,
		[Parameter(Mandatory=$False)]
		[Int]$DaysBack=0
	)
	EnterFunc $MyInvocation.MyCommand.Name
	# By default, use $EvtDaysBack(script parameter). But if $DaysBack is passed, use it.
	If($DaysBack -eq 0){
		$DaysBack=$global:EvtDaysBack 
	}
	If($global:RunningCollect -eq "Full"){
		$DaysBack=($global:EvtDaysBack*2)
	}

	$EventLogs = @()
	ForEach($EventLogCandidate in $EventLogArray){
		$EventObject = $Null
		$EventObject = Get-Winevent -ListLog $EventLogCandidate -ErrorAction Ignore
		If($EventObject -ne $Null){
			LogDebug ("Adding $EventLogCandidate to export list")
			$EventLogs +=$EventLogCandidate
		}Else{
			LogDebug ("$EventLogCandidate does not exist or `'Get-Winevent -ListLog`' failed.")
		}
	}
	ForEach($EventLog in $EventLogs){
		$EventLogFileName = $EventLog -replace "/","-" -replace " ","-" 	#we# fix space in EvtLog
		If(Test-Path -Path "$ExportFolder\$env:computerName-$EventLogFileName.evtx"){
			LogInfo "[$($MyInvocation.MyCommand.Name)] $env:computerName-$EventLogFileName.evtx already exist. Skipping exporting the event log." "Gray"
			Continue
		}
		If($global:RunningCollect -eq "Basic"){
			LogInfo "[$($MyInvocation.MyCommand.Name)] We do nothing on Basic mode, logs will be only last 30 days in txt and csv format"
		}Else{
			LogInfo "[$($MyInvocation.MyCommand.Name)] Copying evtx events for $EventLog"
			$Commands =@(
			"wevtutil epl `"$EventLog`" `"$ExportFolder\$script:BasicSubFolder\$env:computerName-$EventLogFileName.evtx`"",
			"wevtutil al `"$ExportFolder\$script:BasicSubFolder\$env:computerName-$EventLogFileName.evtx`" /l:en-us"
			)
			RunCommands "FwExportEventLog" $Commands -ThrowException:$False -ShowMessage:$False -ShowError:$True
		}
		
		LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting $EventLog"
		
		If (($EventLog -ne "Security") -and ($DaysBack -ne 0)) {
			FwExportEventLogWithTXTFormat $EventLog "$ExportFolder\$script:BasicSubFolder" -DaysBack $DaysBack
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportEventLogWithTXTFormat{
	<#
	.SYNOPSIS
		Export event log with text format
	.DESCRIPTION
		global:FwExportEventLogWithTXTFormat expects 2 parameters: $EventLogName, $ExportFolder
		This function is also called from FwExportEventLog.
	.PARAMETER EventLogName
	 Event log name to be converted to txt file.
	.PARAMETER ExportFolder
	 Folder name converted event log is stored.
	.EXAMPLE
		To export event with text format:
		global:FwExportEventLogWithTXTFormat "Microsoft-Windows-TWinUI/Operational" "%localappdata%\AutoLog\XXX"
	.NOTES
		Date:   21.04.2021
	#>
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $EventLogName,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $ExportFolder,
		[Parameter(Mandatory=$False)]
		[Int]$DaysBack=0
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If($DaysBack -eq 0){
		$DaysBack=$global:EvtDaysBack 
	}
	If($global:RunningCollect -eq "Full"){
		$DaysBack=($global:EvtDaysBack*2)
	}

	# Use below logic based on https://microsoft.githubenterprise.com/css-windows/WindowsCSSToolsDevRep/issues/64
	$ExportLogName = $EventLogName -replace "/","-" -replace " ","-"  # #we# # XXX/Operational => XXX-Operational
	$EventTXTFile	= "$ExportFolder\$env:computerName-$ExportLogName" + ".txt"
	$tmpEventFile	= "$ExportFolder\$env:computerName-$ExportLogName" + ".csv"
	$EventLogDaysBack = (get-date).AddDays(-$DaysBack)	#we# part2 of issue #510
	$Command = "Get-WinEvent -Oldest -FilterHashTable @{LogName = `"$EventLogName`";StartTime = `"$EventLogDaysBack`";} -ErrorAction Ignore | Select-Object LevelDisplayName,TimeCreated,ProviderName,ID,UserId,Message | Export-Csv -path $tmpEventFile -UseCulture -NoTypeInformation -Encoding utf8"
	#we# $Command = "Get-WinEvent -Oldest -LogName `"$EventLogName`" -ErrorAction Ignore | Select-Object LevelDisplayName,TimeCreated,ProviderName,ID,UserId,Message | Export-Csv -path $tmpEventFile -UseCulture -NoTypeInformation -Encoding utf8"
	Try{
		LogInfo "[EventLog] Converting $EventLogName to *.txt format (last $DaysBack days)."
		$durationCSV = Measure-Command { RunCommands "FwExportEventLogWithTXTFormat" $Command -ThrowException:$True -ShowMessage:$False -ShowError:$True }
	}Catch{
		LogException "Error happened in Get-WinEvent for $EventLogName" $_
		Return
	}

	$durationTXT = Measure-Command {
		# $tmpEventFile is csv. Hence remove comma and double quotes
		$tmp = $(Get-Content "$tmpEventFile") -replace ('^"','')
		$tmp = $tmp -replace ('","',"`t") # replace comma with tab space.
		$tmp = $tmp -replace ('",,"',"") # This happens in Security event log
		$tmp = $tmp -replace ('"$',"") # double quotes at line end.
		$tmp | Out-File -FilePath $EventTXTFile
		#Remove-Item $tmpEventFile -ErrorAction Ignore
	}

	LogInfoFile "[EventLog] Converting last $DaysBack days of $EventLogName event log to text format has completed. Duration .CSV: $durationCSV - Duration .TXT: $durationTXT"
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwSetEventLog{
	<#
	.SYNOPSIS
		Set a event log property and enable the event log
	.DESCRIPTION
		Sets a event log property such as eventlog size and enable the event log.
		global:FwSetEventLog expects 3 parameters: $EventLogName(Mandatory), $EvtxLogSize(Optional), $ClearLog(Optional)
		This function changes a event log settings but before changing them, it preserves the previous setting. 
		If you need to restore the setting, you can use FwResetEventLog to set the setting back to the previous setting.
	.PARAMETER EventLogName
		Array of the event log name that setting to be changed.
	.PARAMETER EvtxLogSize
		Maxmum size in byte of event log to be set. EvtxLogSize is also configurable through config parameter '_EvtxLogSize'.
	.PARAMETER ClearLog
		Exports eventlog to "$LogFolder\SavedEventLog" folder and then clear the event log before enabling the event log.
	.EXAMPLE
		FwSetEventLog "Microsoft-Windows-CAPI2/Operational" -EvtxLogSize:102400000 -ClearLog
			 or
		$global:EvtLogsPowerShell = @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
		FwSetEventLog $global:EvtLogsPowerShell
	.NOTES
		Date:   07.09.2021
	#>
	param(
		[parameter(Mandatory=$true)]
		[String[]]$EventLogNames,
		[parameter(Mandatory=$false)]
		[Int]$EvtxLogSize=0,  # Max eventlog size in byte with Integer
		[parameter(Mandatory=$false)]
		[Switch]$ClearLog=$False
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$SavedLogFolder = "$global:LogFolder\SavedEventLog"
	ForEach ($EventLogName in $EventLogNames){
		Try{
			$logDetails = Get-LogProperties -Name $EventLogName -ErrorAction Stop
		}Catch{
			$ErrorMessage = '[FwSetEventLog] An Exception happened in Get-LogProperties.' + 'HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + 'Exception=' + $_.CategoryInfo.Reason + ' Eventlog=' + $EventLogName
			LogException $ErrorMessage $_ $fLogFileOnly
			Throw($ErrorMessage)
		}
		
		# Before enabling and changing the log settings, we remember all previous settings by copying registry.
		Try {
			# Save registry key for this event log.
			If(!(Test-Path "$global:AutoLogRegKey\EventLog")){
				RunCommands "FwSetEventLog" "New-Item -Path `"$global:AutoLogRegKey\EventLog`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
			}
			
			If(Test-Path -PathType Container "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$EventLogName"){
				RunCommands "FwSetEventLog" "Copy-Item -Path `"HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$EventLogName`" -Destination `"$global:AutoLogRegKey\EventLog`" -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
			}Else{
				LogInfo "[FwSetEventLog] Registry for $EventLogName was not found."
			}
			
			# If the log is enabled, we disable it first since some of changes will get error if the log is enabled.
			If($logDetails.Enabled){
				# Currently the event log is already enabled. In this case, we disable it first and enable it later.
				$logDetails.Enabled = $False
				LogInfo "[FwSetEventLog] Disabling $EventLogName as it has been already enabled."
				Set-LogProperties -LogDetails $logDetails -Force -ErrorAction Stop | Out-Null
		
				# In case of Analytic log and if it's already enabled, we save it to 'SavedEventLog' folder before making change
				If($logDetails.Type -eq "Analytic" -or $logDetails.Type -eq "Debug"){
					# Save the log and clear it.
					$EventProperty = Get-Winevent -ListLog $EventLogName
					$EventLogFileName = Split-Path $EventProperty.LogFilePath -Leaf
					If(Test-Path -Path "C:\Windows\System32\Winevt\Logs\$EventLogFileName"){
						FwCreateLogFolder $SavedLogFolder
						LogInfo "[FwSetEventLog] Saving previously enabled analytic log to $SavedLogFolder"
						Copy-Item "C:\Windows\System32\Winevt\Logs\$EventLogFileName" $SavedLogFolder
					}Else{
						Write-Host "C:\Windows\System32\Winevt\Logs\$EventLogFileName"
					}
				}
			}
		
			# First if $ClearLog is specified, save the log and clear it.
			If($ClearLog){
				FwCreateLogFolder $SavedLogFolder
				$tmpStr = $EventLogName.Replace('/','-')
				$SavedEventLogName = ($tmpStr.Replace(' ','-') + '.evtx')
				# Save the log and clear it.
				LogInfo "[FwSetEventLog] Saving and clearing $EventLogName"
				$Commands = @(
					"wevtutil epl $EventLogName $SavedLogFolder\$SavedEventLogName 2>&1 | Out-Null",
					"wevtutil clear-log $EventLogName"
				)
				RunCommands "FwSetEventLog" $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
			}
		
			# If event log size(_EvtxLogSize) is set through tss_config file, use it(default is 100MB).
			If(!([string]::IsNullOrEmpty($script:FwEvtxLogSize))){ 
				$EvtxLogSize = $script:FwEvtxLogSize
			}
		
			# Setting log size
			If($EvtxLogSize -ne 0){
				# $EvtxLogSize should be larger than 1028KB.
				If($EvtxLogSize -lt 1052672){
					$DefaultMinLogSize = 1028*1024
					LogInfo "Specified size($EvtxLogSize) is too small and set it with $DefaultMinLogSize(default minimum size)"
					$EvtxLogSize = $DefaultMinLogSize
				}
				$logDetails.MaxLogSize = $EvtxLogSize
				$EvtxLogSizeinKB = [Math]::Floor($EvtxLogSize/1024)
				LogInfo "[FwSetEventLog] Setting EvtxLogSize to $EvtxLogSize($($EvtxLogSizeinKB)KB) for $EventLogName"
				Set-LogProperties -LogDetails $logDetails -Force -ErrorAction Stop | Out-Null
			}
		
			# Enabling the log.
			LogInfo "[FwSetEventLog] Enabling $EventLogName"
			$logDetails.Enabled = $True
			Set-LogProperties -LogDetails $logDetails -Force -ErrorAction Stop | Out-Null
		} Catch {
			$ErrorMessage = '[FwSetEventLog] ERROR: Encountered an error during changing event log ' + $EventLogName
			LogException $ErrorMessage $_ $fLogFileOnly
			Throw($ErrorMessage)
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwResetEventLog{
	<#
	.SYNOPSIS
		Restore event log setting by using previously saved data by FwSetEventLog().
	.DESCRIPTION
		Restores event log settings that was changed previously by FwSetEventLog()
		global:FwResetEventLog expects 1 parameters: $EventLogName(Mandatory).
		FwSetEventLog() saves previous event log setting to under "HKCU:\Software\Microsoft\AutoLog\EventLog" registry.
		This function restores the settings by using the registry. If there is no registry, this function returns immediately.
	.PARAMETER EventLogName
		Array of event log name.
	.EXAMPLE
		FwResetEventLog "Microsoft-Windows-CAPI2/Operational"
			or
		$global:EvtLogsPowerShell = @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
		FwResetEventLog $global:EvtLogsPowerShell
	.NOTES
		Date:   07.09.2021
	#>
	param(
		[parameter(Mandatory=$true)]
		[String[]]$EventLogNames
	)
	EnterFunc $MyInvocation.MyCommand.Name
	ForEach ($EventLogName in $EventLogNames){
		LogDebug ("Restoring event log setting for $EventLogName")
		Try{
			$regKey = Get-Item "$global:AutoLogRegKey\EventLog\$EventLogName" -ErrorAction Stop 
		}Catch{
			# It seems no change was made when SetEventLog. So just return.
			LogInfo "FwResetEventLog was called but there was no saved setting data for $EventLogName."
			Return
		}
		
		Try{
			$logDetails = Get-LogProperties -Name $EventLogName -ErrorAction Stop
		}Catch{
			$ErrorMessage = '[ResetEventLog] An exception happened in Get-LogProperties.'  + 'HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + 'Exception=' + $_.CategoryInfo.Reason + ' Eventlog=' + $EventLogName
			LogException $ErrorMessage $_ $fLogFileOnly
			Throw($ErrorMessage)
		}
		
		# If the log is enabled, we disable it first since some of changes will get error if the log is enabled.
		If($logDetails.Enabled){
			$logDetails.Enabled = $False
			LogInfo "[FwResetEventLog] Disabling $EventLogName."
			Set-LogProperties -LogDetails $logDetails -Force -ErrorAction Stop | Out-Null
		}
		
		# Get values in registry that were previously saved by FwSetEventLog()
		$Enabled = $regKey.GetValue("Enabled")
		$MaxLogSize = $regKey.GetValue("MaxSize")

		# Disable log here as the log is originally disabled.
		# If the log is originally enabled, we don't re-enable it here, as log export might happen later and that could fail if we enable log here.
		# Therefore, the logs that is originally enabled are enabled after all data collections are completed, which means we re-enable log if $Script:DataCollectionCompleted=$True.
		If(!$Enabled -or ($Enabled -and $Script:DataCollectionCompleted)){
			Try{
				LogInfo "[FwResetEventLog] Restoring setting of $EventLogName with Enabled=$Enabled and MaxSize=$MaxLogSize"
				
				# Restoring log size.
				$logDetails.MaxLogSize = $MaxLogSize
				Set-LogProperties -LogDetails $logDetails -Force | Out-Null
				
				# Enable or Disable the log depending on previous setting.
				$logDetails.Enabled = $Enabled
				If($Enabled){
					LogInfo "Re-enabling $EventLogName as it was previously enabled."
				}
				Set-LogProperties -LogDetails $logDetails -Force | Out-Null
				
				# Remove the registry only for this event log.
				Remove-Item -Path "$global:AutoLogRegKey\EventLog\$EventLogName" -Recurse -ErrorAction Ignore | Out-Null 
			}Catch{
				$ErrorMessage = '[ResetEventLog] ERROR: Encountered an error during restoring event log. Eventlog=' + $EventLogName + ' Command=' + $_.CategoryInfo.Activity + ' HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + ' Exception=' + $_.CategoryInfo.Reason
				LogException $ErrorMessage $_ $fLogFileOnly
				Throw($ErrorMessage)
			}
		}Else{
			LogInfo "[FwResetEventLog] $EventLogName will be reset to Enabled=$Enabled and MaxSize=$MaxLogSize later"
		}
	}
	# If there is no entries under 'EventLog' registry, delete the top 'AutoLog' registry
	If((get-childitem "$global:AutoLogRegKey\EventLog") -eq $Null){
		Remove-Item -Path "$global:AutoLogRegKey\EventLog" -Recurse -ErrorAction Ignore | Out-Null #we# commented in order to keep EulaAccepted, but now EULA is in "HKCU:Software\Microsoft\CESDiagnosticTools"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwResetAllEventLogs{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Getting list of event logs to reset."
	$EventLogNames = Get-ChildItem "$global:AutoLogRegKey\EventLog" -ErrorAction Ignore
	If($EventLogNames.count -eq 0){
		LogDebug "No event log in $global:AutoLogRegKey"
	}Else{
		LogInfo "Resetting below event logs."
		ForEach($EventLogName in $EventLogNames){
			LogInfo "  - $($EventLogName.PSChildName)"
		}
		global:FwResetEventLog $EventLogNames.PSChildName
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwAddEvtLog {
	<#
	.SYNOPSIS
		Adds new Event Log to the list of Event Logs to be collected
	.DESCRIPTION
		Adds new Event Log item to the list of Event Logs to be collected at TssPhase
	.EXAMPLE
		FWaddEvtLog @("Microsoft-Windows-PowerShell/Admin", "Microsoft-Windows-PowerShell/Operational")
		POD/module specific groups of EvtLogs can be defined in <_POD.psm1> #region groups of Eventlogs
	#>
	param(
		[Parameter(Mandatory=$True)]
		[String[]]$AddToEvtLogNames,# which Evt name(s) to add to $global:EvtLogNames
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase	# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] adding Eventlog $AddToEvtLogNames at $TssPhase"
	$global:EvtLogNames += $AddToEvtLogNames
	#LogInfoFile "___ after global:FWaddEvtLog, list: $global:EvtLogNames"
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetEvtLogList {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if ($global:EvtLogNames.count -gt 0){
		LogInfo "[$($MyInvocation.MyCommand.Name)] Processing Eventlogs at $TssPhase"
		LogInfoFile "Eventlog List at $TssPhase : $global:EvtLogNames"
		$global:EvtLogNames = $global:EvtLogNames |sort -Unique
		LogInfoFile "___ UniqueEvtList at $TssPhase : $global:EvtLogNames"
		FwExportEventLog $global:EvtLogNames $global:LogFolder
		LogInfoFile "___ done all Eventlog collections"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwEvtLogDetails{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $LogName,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $LogFolderName
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo ("[EventLog] Collecting the details for the " + $LogName + " log")
	$Commands = @(
		"wevtutil gl `"$LogName`" | Out-File -Append  $LogFolderName\EventLogs.txt",
		"wevtutil gli `"$LogName`" | Out-File -Append  $LogFolderName\EventLogs.txt"
	)
	RunCommands "FwEvtLogDetails" $Commands -ThrowException:$False -ShowMessage:$True
	"" | Out-File -Append "$LogFolderName\EventLogs.txt"

	If($logname -ne "ForwardedEvents"){
		Try{
			LogInfo ("[EventLog] Running Get-WinEvent -Logname $LogName -MaxEvents 1 -Oldest")
			$evt = (Get-WinEvent -Logname $LogName -MaxEvents 1 -Oldest -ErrorAction Stop)
			"Oldest " + $evt.TimeCreated + " (" + $evt.RecordID + ")" | Out-File -Append "$LogFolderName\EventLogs.txt"
			LogInfo ("[EventLog] Running Get-WinEvent -Logname $LogName -MaxEvents 1")
			$evt = (Get-WinEvent -Logname $LogName -MaxEvents 1 -ErrorAction Stop)
			"Newest " + $evt.TimeCreated + " (" + $evt.RecordID + ")" | Out-File -Append "$LogFolderName\EventLogs.txt"
			"" | Out-File -Append "$LogFolderName\EventLogs.txt"
		}Catch{
			LogErrorFile ("An error happend during getting event log for $LogName")
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

#region --- FwBasicLog functions & common helper functions
function global:FwClearCaches {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] deleting DNS, NetBIOS, Kerberos and DFS caches at $TssPhase"
	$Commands = @(
		"IPconfig /flushDNS"
		"NBTstat -RR"
		"$($env:windir)\system32\KLIST.exe purge -li 0x3e7"
		"$($env:windir)\system32\KLIST.exe purge"
	)
	if (Test-Path $DFSutilPath) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] running 'DFSutil.exe /PKTflush' at $TssPhase"
		$Commands += "DFSutil.exe /PKTflush"
	} else {LogWarn "[$($MyInvocation.MyCommand.Name)] 'DFSutil.exe' not found in PATH"}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwCopyWindirTracing { 
	param(
		[Parameter(Mandatory=$True)]
		[String]$ToLogSubFolder
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] copying '$Env:SystemRoot\tracing' $ToLogSubFolder logs"
	$Commands = @(
		"xcopy /s/e/i/q/y $Env:SystemRoot\tracing $global:LogFolder\$ToLogSubFolder"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwDoCrash {
	EnterFunc $MyInvocation.MyCommand.Name
	if (!$noCrash.IsPresent) {
		$Script:IsCrashInProgress = $True
		$NotMyFault = Get-Command $global:NotMyFaultPath -ErrorAction Ignore
		If($NotMyFault -eq $Null){
			LogError "$global:NotMyFaultPath not found."
			Return
		}
		LogInfo "[$($MyInvocation.MyCommand.Name)] ##### forcing a memory dump/crash now using '$global:NotMyFaultPath /crash' #####" "Magenta"
		LogInfo "[$($MyInvocation.MyCommand.Name)] Please run command '$DirScript\AutoLog -stop -noCrash' after reboot and collect $env:SystemRoot\memory.dmp." "Magenta"
		$Commands = @(
			"$global:NotMyFaultPath /AcceptEula /crash"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True -ShowError:$True
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetCertsInfo { 
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,	# _Start_ or _Stop_
		[String]$CertMode,						# optional mode: Full or Basic
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] Get certificates and credentials with CertUtil.exe at $TssPhase  ...may take some minutes"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Credman" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Credman.txt"}
	"===== $(Get-Date) : List available credentials: cmdkey.exe /list " | Out-File -Append $outFile
	logLine $outFile
	$Commands = @(
		"$Sys32\cmdkey.exe /list | Out-File -Append $outFile"
		"$Sys32\certutil.exe -v -silent -enterprise -store NTAuth | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_NTAuth-store.txt"
		"$Sys32\certutil.exe -v -silent -enterprise -store root | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-Root-AD-store.txt"
		"$Sys32\certutil.exe -v -silent -store root | Out-File -Append $global:LogFolder\$(LogPrefix$LogPrefix)Cert_Machine-Root-Registry-store.txt"
		"$Sys32\certutil.exe -v -silent -store CA | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-CA-Registry-store.txt"
	)
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Cert_machine-store" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Cert_machine-store.txt"}
	"======== certutil.exe might take some minutes ... =============================================" | Out-File -Append $outFile
	$Commands += @("$Sys32\certutil.exe -v -silent -store my | Out-File -Append $outFile")
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	if ( $CertMode -ieq "Full") {
		$Commands = @(
			"$Sys32\certutil.exe -v -silent -user -store my | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_user-store.txt"
			"$Sys32\certutil.exe -v -silent -scinfo | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_ScInfo.txt"
			"$Sys32\certutil.exe -tpminfo | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_TpmInfo.txt"
			"$Sys32\certutil.exe -v -silent -user -store my 'Microsoft Smart Card Key Storage Provider' | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_My_SmartCard.txt"
			"$Sys32\certutil.exe -v -silent -user -key -csp 'Microsoft Passport Key Storage Provider' | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_MPassportKey.txt"
			"$Sys32\certutil.exe -v -silent -store 'Homegroup Machine Certificates' | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Homegroup-Machine-Store.txt"
			"$Sys32\certutil.exe -v -silent -enterprise -store CA | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-CA-AD-store.txt"
			"$Sys32\certutil.exe -v -silent store authroot | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-ThirdParty-store.txt"
			"$Sys32\certutil.exe -v -silent -store -grouppolicy root | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-GP-Root-Store.txt"
			"$Sys32\certutil.exe -v -silent -store -grouppolicy CA | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-GP-CA-Store.txt"
			"$Sys32\wevtutil.exe query-events Application `"/q:*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll']]]`" | Out-File -Append $global:LogFolder\$($LogPrefix)CertificateServicesClientLog.xml"
			"$Sys32\certutil.exe -policycache `"$global:LogFolder\$($LogPrefix)CertificateServicesClientLog.xml`" | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_ReadableClientLog.txt"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		#wevtutil.exe  query-events Application "/q:*[System[Provider[@Name='Microsoft-Windows-CertificateServicesClient-CertEnroll']]]" > "$global:LogFolder\$($LogPrefix)CertificateServicesClientLog.xml" 2>&1 | Out-Null
		#certutil.exe  -policycache "$global:LogFolder\$($LogPrefix)CertificateServicesClientLog.xml" > "$global:LogFolder\$($LogPrefix)Cert_ReadableClientLog.txt" 2>&1 | Out-Null
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwCheckAuthenticodeSignature{
	param(
	[Parameter(Mandatory=$False)]
	[String]$TssPhase = $pathToCheck,				# 
	[Parameter(Mandatory=$False)]
	[String]$resultOutputDir						# resulting output folder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	If($resultOutputDir){
		if (test-path $resultOutputDir -ErrorAction SilentlyContinue) {
			$issuerInfo = "$resultOutputDir\issuerInfo.txt"
		} else {
			$issuerInfo = "$global:LogFolder\issuerInfo.txt"
		}
	} else {$issuerInfo = "$global:LogFolder\issuerInfo.txt"}
	if ($pathToCheck) {
		if (Test-Path -path $pathToCheck -ErrorAction SilentlyContinue) {
			$AuthenticodeSig = (Get-AuthenticodeSignature -FilePath $pathToCheck)
			$cert = $AuthenticodeSig.SignerCertificate
			$FileInfo = (get-command $pathToCheck).FileVersionInfo			
			$issuer = $cert.Issuer
			#OS is older than 2016 and some built-in processes will not be signed
			if (($OSBuild -lt 14393) -and (!$AuthenticodeSig.SignerCertificate)) {
				if (($FileInfo.CompanyName -eq "Microsoft Corporation")) {
					return
				}
				else {
					Write-Error "Script execution terminated because a process or script that does not have any signature was detected" | Out-File $issuerInfo -append
					$pathToCheck | Out-File $issuerInfo -append
					$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
					$cert | Format-List * | Out-File $issuerInfo -append
					[Environment]::Exit(1)
				}
			}
			#check if valid
			if ($AuthenticodeSig.Status -ne "Valid") {
				Write-Error "Script execution terminated because a process or script that does not have a valid Signature was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}
			#check issuer
			if (($issuer -ne "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Code Signing PCA 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US") -and ($issuer -ne "CN=Microsoft Development PCA 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")) {
				Write-Error "Script execution terminated because a process or script that is not Microsoft signed was detected" | Out-File $issuerInfo -append
				$pathToCheck | Out-File $issuerInfo -append
				$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
				$cert | Format-List * | Out-File $issuerInfo -append
				[Environment]::Exit(1)
			}	
			if ($AuthenticodeSig.IsOSBinary -ne "True") {
				#If revocation is offline then test below will fail
				$IsOnline = (Get-NetConnectionProfile).IPv4Connectivity -like "*Internet*"
				if ($IsOnline) {
					$IsWindowsSystemComponent = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.10.3.6" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable OsCertWarnVar -ErrorVariable OsCertErrVar)
					$IsMicrosoftPublisher = (Test-Certificate -Cert $cert -EKU "1.3.6.1.4.1.311.76.8.1" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable MsPublisherWarnVar -ErrorVariable MsPublisherErrVar)
					if (($IsWindowsSystemComponent -eq $False) -and ($IsMicrosoftPublisher -eq $False)) {
						#Defender AV and some OS processes will have an old signature if older version is installed
						#Ignore if cert is OK and only signature is old
						if (($OsCertWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($MsPublisherWarnVar -like "*CERT_TRUST_IS_NOT_TIME_VALID*") -or ($OsCertWarnVar -like "*CERT_TRUST_IS_OFFLINE_REVOCATION*") -or ($MsPublisherWarnVar -like "CERT_TRUST_IS_OFFLINE_REVOCATION")) {
							return
						}
						Write-Error "Script execution terminated because the process or script certificate failed trust check" | Out-File $issuerInfo -append
						$pathToCheck | Out-File $issuerInfo -append
						$AuthenticodeSig | Format-List * | Out-File $issuerInfo -append
						$cert | Format-List * | Out-File $issuerInfo -append
						[Environment]::Exit(1)
					}
				}
			}
		}
	 else {
			Write-Error ("Path " + $pathToCheck + " was not found") | Out-File $issuerInfo -append
		}
	}
}

function global:FwCheck-Command-verified($checkCommand) {
	#gets path of command and check signature
	$command = Get-Command $CheckCommand -ErrorAction SilentlyContinue
	FwCheckAuthenticodeSignature $command.path
}

function global:FwGetDFScache {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase				# _Start_ or _Stop_
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if (Test-Path $DFSutilPath) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] running 'DFSutil.exe' commands at $TssPhase"
		$outFile = $PrefixTime + "DFScache" + $TssPhase + ".txt"
		$Commands = @(
			"DFSutil.exe /PKTinfo | Out-File -Append $outFile"
			"DFSutil.exe /SPCinfo | Out-File -Append $outFile"
			"DFSutil.exe /displayMupCache | Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	} else {LogWarn "[$($MyInvocation.MyCommand.Name)] 'DFSutil.exe' not found in PATH"}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetEnv {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] Get Environment settings"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Env" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Env.txt"}
	(gci env:*).GetEnumerator() | Sort-Object Name | Out-File -FilePath $outFile -Append -Encoding ascii -Width 200
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetKlist {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] running 'KLIST.exe' at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "kList_Tickets" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_kList_Tickets.txt"}
	$Commands = @(
		"$($env:windir)\system32\KLIST.exe 				| Out-File -Append $outFile"
		"$($env:windir)\system32\KLIST.exe -li 0x3e7 	| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
	
function global:FwGetMsInfo32 {
	<# 
	.SYNOPSIS 
		 collects MsInfo32 in .nfo and/or .txt format; use FwWaitForProcess to wait for background process completion
	#>
	param(
		[Parameter(Mandatory=$False)]
		[String[]]$Formats=@("nfo","txt"),					# default is .nfo and .txt format, use "txt" to collect only msinfo.txt,
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder									# optional subfolder-name
	)
	EnterFunc $MyInvocation.MyCommand.Name
	# instead of msinfo32.exe consider PS command: Get-ComputerInfo
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting MsInfo32 in '$Formats' format(s) at $TssPhase"
	$ExeFile = "msinfo32.exe"
	if (test-path (join-path ([Environment]::GetFolderPath("System")) $ExeFile)){
			$MsInfo32Path = (join-path ([Environment]::GetFolderPath("System")) $ExeFile)
	}
	ForEach($Format in $Formats){
		if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixCn + "msinfo32.$Format"} else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_msinfo32.$Format"}
		if ($Format -match "txt"){
			$ArgumentList = " /report `"$outFile`""
			LogInfo "[$($MyInvocation.MyCommand.Name)] Starting msinfo32.exe $ArgumentList"
			$global:msinfo32TXT = Start-Process -FilePath 'msinfo32' -ArgumentList $ArgumentList -PassThru
		}
		if ($Format -match "nfo"){
			$ArgumentList = " /nfo `"$outFile`""
			LogInfo "[$($MyInvocation.MyCommand.Name)] Starting msinfo32.exe $ArgumentList"
			$global:msinfo32NFO = Start-Process -FilePath 'msinfo32' -ArgumentList $ArgumentList -PassThru
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetNltestDomInfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if ((Get-CimInstance win32_computersystem).partofdomain -eq $true) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] NLTEST Domain information at $TssPhase"
		if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "NLTEST_DomInfo" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_NLTEST_DomInfo.txt"}
		$Commands = @(
			"nltest /dsgetsite 						| Out-File -Append $outFile"
			"nltest /dsgetdc: /kdc /force 			| Out-File -Append $outFile"
			"nltest /dclist: 						| Out-File -Append $outFile"
			"nltest /trusted_domains 				| Out-File -Append $outFile"
			"nltest /domain_trusts /ALL_TRUSTS /V 	| Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	} else {
	  LogInfo "[$($MyInvocation.MyCommand.Name)] This machine is not domain-joined; at $TssPhase"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetPoolmon {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,	# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if ($global:noPoolMon -ne $True) {
		if (Test-Path $global:PoolmonPath) {
			LogInfo "[$($MyInvocation.MyCommand.Name)] Poolmon.exe at $TssPhase"
			if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Poolmon" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Poolmon.txt"}
			get-date | Out-File $outFile -Encoding ascii
			$Commands = @(
				"Poolmon.exe -t -b -r -n $outFile"
			)
			RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		} else {LogWarn "[$($MyInvocation.MyCommand.Name)] 'Poolmon.exe' not found in PATH"}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetProxyInfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting Proxy settings 'winhttp show proxy' and Reg. settings at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Proxy" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Proxy.txt"}
	$Commands = @(
		"netsh winhttp show proxy 					| Out-File -Append $outFile"
		"bitsadmin /util /getieproxy localsystem 	| Out-File -Append $outFile"
		"bitsadmin /util /getieproxy networkservice | Out-File -Append $outFile"
		"bitsadmin /util /getieproxy localservice 	| Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	FwAddRegItem @("Proxy") $TssPhase
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:GetOwnerCim{
	param( $prc )
	EnterFunc $MyInvocation.MyCommand.Name
	$ret = Invoke-CimMethod -InputObject $prc -MethodName GetOwner
	EndFunc ($MyInvocation.MyCommand.Name + "$($ret.Domain)" + "\" + "$($ret.User)")
	return ($ret.Domain + "\" + $ret.User)
}

Function global:GetOwnerWmi{
	param( $prc )
	EnterFunc $MyInvocation.MyCommand.Name
	$ret = $prc.GetOwner()
	EndFunc ($MyInvocation.MyCommand.Name + "$($ret.Domain)" + "\" + "$($ret.User)")
	return ($ret.Domain + "\" + $ret.User)
}

Function global:FwListProcsAndSvcs {
	<# .SYNOPSIS
		The function will list running processes, services and FilesVersions in $global:LogFolder or under \$Subfolder
		P1: TssPhase
		P2: output subfolder
	#>
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if ([string]::IsNullOrEmpty($Subfolder)) { $outDir = $global:LogFolder} else { $outDir = $global:LogFolder + "\" + $Subfolder }
	$proc = FwExecWMIQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, SessionId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath from Win32_Process"
	if ($PSVersionTable.psversion.ToString() -ge "3.0") {
		$StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
		$Owner = @{N="User";E={(GetOwnerCim($_))}}
	} else {
		$StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
		$Owner = @{N="User";E={(GetOwnerWmi($_))}}
	}
	# Processes
	if ($proc) {
		LogInfo "[ListProcsAndSvcs] Collecting processes details"
		$proc | Sort-Object Name |
		Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name, @{e={$_.SessionId};n="Session"},
		@{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
		@{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
		@{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, $Owner, CommandLine |
		Out-String -Width 500 | Out-File -FilePath ($outDir + "\Processes$global:TssPhase.txt")
		# FilesVersions
		LogInfo "[ListProcsAndSvcs] Retrieving file version of running binaries"
		$binlist = $proc | Group-Object -Property ExecutablePath
		foreach ($file in $binlist) {
			if ($file.Name) {
				FwFileVersion -Filepath ($file.name) | Out-File -FilePath ($outDir + "\FilesVersions$global:TssPhase.csv") -Append
			}
		}
		# Services
		LogInfo "[ListProcsAndSvcs] Collecting services details"
		$svc = FwExecWMIQuery -NameSpace "root\cimv2" -Query "select ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"
		if ($svc) {
			$svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
			Out-String -Width 400 | Out-File -FilePath ($outDir + "\Services$global:TssPhase.txt")
		}
		EndFunc ($MyInvocation.MyCommand.Name + "($true)")
		return $true  | Out-Null
	} else {
		EndFunc ($MyInvocation.MyCommand.Name + "($false)")
		return $false | Out-Null
	}
}

function global:FwGetQwinsta {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting QWinSta status at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "QWinSta" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_QWinSta.txt"}
	$Commands = @(
		"$Sys32\QWINSTA.exe | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetRegHives {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if (-not (Test-Path "$PrefixCn`RegHive_Software.hiv")) {
		LogInfoFile "___ FwGetRegHives at $TssPhase"
		$Commands = @(
			"REG SAVE HKLM\SOFTWARE $global:LogFolder\$script:BasicSubFolder\`RegHive_Software.hiv /Y"
			"REG SAVE HKLM\SYSTEM $global:LogFolder\$script:BasicSubFolder\`RegHive_System.hiv /Y"
			"REG SAVE HKCU\SOFTWARE $global:LogFolder\$script:BasicSubFolder\`RegHive_Software_User.hiv /Y"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwRestartInOwnSvc {
	<# .SYNOPSIS
		The function will stop and restart a service in its own svchost
		Escpecially useful on downlevel OS, which start many services in a single svchost
	#>
	param(
		[Parameter(Mandatory=$True)]
		[String]$ServiceName
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] restarting $ServiceName service in own svchost"
	$Commands = @(
		"Stop-Service -Name $ServiceName -Force"
		"SC config $ServiceName type= own"
		"Start-Service -Name $ServiceName"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetSrvSKU {
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		$IsServerSKU = (Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop).Caption -like "*Server*"
	}Catch{
		LogException "An exception happened in Get-CimInstance for CIM_OperatingSystem" $_ $fLogFileOnly
		$IsServerSKU = $False
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($IsServerSKU)")
	Return $IsServerSKU
}

function global:FwGetSrvRole {
	EnterFunc $MyInvocation.MyCommand.Name
	# get Windows Feature and Role
	If($IsServerSKU){
		$Commands = @(
			"Get-WindowsFeature -ErrorAction Stop | Out-File -Append $PrefixCn`Roles_Features_All.txt"
		)
		RunCommands "GetSrvRole" $Commands -ThrowException:$False -ShowMessage:$False
		Get-WindowsFeature | Where-Object {$_.installed -eq $true} | Out-File -Append $PrefixCn`Roles_Features_Installed.txt
	} else {
		If($OSBuild -ge 9200) {
			Get-WindowsOptionalFeature -Online | ft -AutoSize | Out-File -Append $PrefixCn`Roles_Features_Optional.txt
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetSVC {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] running 'SC.exe queryex type= all state= all' at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Services" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Services.txt"}
	SC.exe queryex type= all state= all | out-file $outFile
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetSVCactive {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] running 'NET START' at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "ServicesActive" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_ServicesActive.txt"}
	NET START | out-file $outFile
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetSysInfo {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,		# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] running 'systeminfo.exe' at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "SystemInfo" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_SystemInfo.txt"}
	systeminfo.exe | out-file $outFile
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetTaskList {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] running 'Tasklist.exe /FO csv /svc' at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Tasklist" + $TssPhase } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Tasklist"}
	$outFileTXT = $outFile + ".txt"
	$outFileCSV = $outFile + ".csv"
	$outFileM = $PrefixTime + "Tasklist-M" + $TssPhase + ".txt"
	$Commands = @(
		"Tasklist.exe /FO csv /svc	| Out-File -Append $outFileCSV"
		"Tasklist.exe /v 			| Out-File -Append $outFileTXT"
	)
	RunCommands "TaskList" $Commands -ThrowException:$False -ShowMessage:$False
	if ($TssPhase -eq "_Stop_") {Tasklist.exe /M | Out-File -Append $outFileM}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetWhoAmI {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] collecting 'WhoAmI.exe -all' info at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "WhoAmI" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_WhoAmI.txt"}
	$Commands = @(
		"whoami.exe -all | Out-File -Append $outFile"
	)
	RunCommands "WhoAmI" $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

function Get-DNDDoLogs
{
    Param
    (
        [Alias("Prefix")]
            [Parameter(Mandatory=$true, Position=0)]
            [ValidateNotNullOrEmpty()]
            [string] $_prefix,
        [Alias("Temp")]
            [Parameter(Mandatory=$false, Position=1)]
            [string] $_tempdir=$null,
        [Alias("RobocopyLog")]
            [Parameter(Mandatory=$false, Position=2)]
            [string] $_robocopy_log=$null,
        [Alias("ErrorFile")]
            [Parameter(Mandatory=$false, Position=3)]
            [string] $_errorfile=$null,
        [Alias("Line")]
            [Parameter(Mandatory=$false, Position=4)]
            [string] $_line=$null,
        [Alias("FlushLogs")]
            [Parameter(Mandatory=$false, Position=5)]
            [string] $_flush_logs=$null
    )
    EnterFunc $MyInvocation.MyCommand.Name

    # Section Delivery Optimizaton logs and powershell for Win10+
    $LogPrefixDO = "DOSVC"
    if ($null -ne (Get-Service -Name dosvc -ErrorAction SilentlyContinue)) {
        if ($_FLUSH_LOGS -eq 1) {
            LogInfo ("[$LogPrefixDO] Flushing DO/USO/WU logs.")
            $CommandsFlushLogs = @(
                "Stop-Service -Name dosvc"
                "Stop-Service -Name usosvc"
                "Stop-Service -Name wuauserv"
            )
			RunCommands $LogPrefixDO $CommandsFlushLogs -ThrowException:$False -ShowMessage:$True
        }
        FwCreateFolder $_tempdir\logs\DOSVC
        LogInfo ("[$LogPrefixDO] Getting DeliveryOptimization logs.")
        $CommandsDOSVC = @(
            "robocopy `"$Env:windir\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs`" `"$_tempdir\logs\dosvc`" *.log *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log /S | Out-Null"
            "robocopy `"$Env:windir\SoftwareDistribution\DeliveryOptimization\SavedLogs`" `"$_tempdir\logs\dosvc`" *.log *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log /S | Out-Null"
        )
        RunCommands $LogPrefixDO $CommandsDOSVC -ThrowException:$False -ShowMessage:$True
        
        LogInfo ("[$LogPrefixDO] Getting DeliveryOptimization registry.")
        $RegKeysDOSVC = @(
            ('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization')
        )
        FwExportRegToOneFile $LogPrefixDO $RegKeysDOSVC "$_tempdir\logs\dosvc\registry_DeliveryOptimization.txt"

        LogInfo ("[$LogPrefixDO] Getting DeliveryOptimization perf data.")
		$outfile = "$_tempdir\logs\dosvc\DeliveryOptimization_info.txt"
		$Commands = @(
			"Get-DeliveryOptimizationPerfSnap	| Out-File -Append $outfile"
			"Get-DeliveryOptimizationStatus		| Out-File -Append $outfile"
		)
		RunCommands "MDT" $Commands -ThrowException:$False -ShowMessage:$True
    }
    EndFunc $MyInvocation.MyCommand.Name
}

function global:CollectWuLog {
		LogInfo "[$($MyInvocation.MyCommand.Name)] Is Running..."
		EnterFunc $MyInvocation.MyCommand.Name
		$_tempdir= "$LogFolder\WU_Logs$LogSuffix"
		FwCreateLogFolder $_tempdir
		$_prefix="$_tempdir\$Env:COMPUTERNAME" + "_"
		$_robocopy_log=$_prefix+'robocopy.log'
		$_errorfile= $_prefix+'Errorout.txt'
		$_flush_logs=0
		$_WUETLPATH="$Env:windir\Logs\WindowsUpdate"
		$_SIHETLPATH="$Env:windir\Logs\SIH"
		$_WUOLDETLPATH="$Env:windir.old\Windows\Logs\WindowsUpdate"
		$_OLDPROGRAMDATA="$Env:windir.old\ProgramData"
		$_robocopy_log="$_tempdir\robocopy.log"
		$_OLDLOCALAPPDATA="$Env:windir.old\" + "$Env:localappdata".Substring(2)
		$_major = [environment]::OSVersion.Version.Major
		$_minor = [environment]::OSVersion.Version.Minor
		$_build = [environment]::OSVersion.Version.Build
		LogInfo ("[OS] Version: $_major.$_minor.$_build")
		$_WIN8_OR_LATER = $false
		$_WINBLUE_OR_LATER = $false
		if ([int]$_major -ge 7)
		{
			$_WIN8_OR_LATER = $true
			$_WINBLUE_OR_LATER = $true
		}
		elseif ([int]$_major -eq 6)
		{
			if([int]$_minor -ge 2) { $_WIN8_OR_LATER = $true}    
			if([int]$_minor -ge 3) { $_WINBLUE_OR_LATER = $true}
		}
		FwGetSysInfo -Subfolder "WU_Logs$LogSuffix"
		LogInfo "[$($MyInvocation.MyCommand.Name)] Copying logs ..."
		$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
		$SourceDestinationPaths = @(
			@("$Env:windir\windowsupdate.log", "$($_prefix)WindowsUpdate.log"),
			@("$Env:windir\SoftwareDistribution\ReportingEvents.log", "$($_prefix)WindowsUpdate_ReportingEvents.log"),
			@("$Env:localappdata\microsoft\windows\windowsupdate.log", "$($_prefix)WindowsUpdatePerUser.log"),
			@("$Env:windir\windowsupdate (1).log", "$($_prefix)WindowsUpdate(1).log"),
			@("$Env:windir.old\Windows\windowsupdate.log", "$($_prefix)Old.WindowsUpdate.log"),
			@("$Env:windir.old\Windows\SoftwareDistribution\ReportingEvents.log", "$($_prefix)Old.ReportingEvents.log"),
			@("$_OLDLOCALAPPDATA\microsoft\windows\windowsupdate.log", "$($_prefix)Old.WindowsUpdatePerUser.log"),
			@("$Env:windir\SoftwareDistribution\Plugins\7D5F3CBA-03DB-4BE5-B4B36DBED19A6833\TokenRetrieval.log", "$($_prefix)WindowsUpdate_TokenRetrieval.log")
		)
		FwCopyFiles $SourceDestinationPaths -ShowMessage:$False
		
		# CBS & PNP logs
		$Commands = @(
			"robocopy.exe `"$Env:windir\logs\cbs`" 	$_tempdir *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
			"robocopy.exe `"$Env:windir\logs\cbs`" 	$_tempdir *.cab /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
			"robocopy.exe `"$Env:windir\logs\dpx`" 	$_tempdir *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
			"robocopy.exe `"$Env:windir\inf`" 		$_tempdir *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
			"robocopy.exe `"$Env:windir\WinSxS`" 	$_tempdir poqexec.log /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
			"robocopy.exe `"$Env:windir\WinSxS`" 	$_tempdir pending.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
			"robocopy.exe `"$Env:windir\servicing\sessions`" $_tempdir sessions.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log | Out-Null"
		)
		RunCommands "CBS_PNP" $Commands -ThrowException:$False -ShowMessage:$True
				
		# UUP logs and action list xmls
		robocopy "$Env:windir\SoftwareDistribution\Download" "$_tempdir\UUP" *.log *.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log
		
		# Windows Store logs.
		cmd /r Copy "$Env:temp\winstore.log" "$_tempdir\winstore-Broker.log" /y >$null 2>&1
		robocopy "$Env:userprofile\AppData\Local\Packages\WinStore_cw5n1h2txyewy\AC\Temp" "$_tempdir winstore.log" /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		
		# Older build has ETL in windir
		if (test-path -path "$Env:windir\windowsupdate.etl")
		{
		  # windowsupdate.etl is not flushed until service is stopped.
		  $LogPrefixFlushLogs = "FlushLogs"
		  LogInfo "[$($MyInvocation.MyCommand.Name)] Flushing USO/WU logs"
		  $CommandsFlushLogs = @(
			  "Stop-Service -Name usosvc"
			  "Stop-Service -Name wuauserv"
		  )
		  RunCommands $LogPrefixFlushLogs $CommandsFlushLogs -ThrowException:$False -ShowMessage:$True
		  robocopy "$Env:windir" $_tempdir windowsupdate.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		}
		
		# Newer build has multiple ETLs
		if (test-path -path $_WUETLPATH)
		{
			$LogPrefixFlushLogs = "FlushLogs"
			LogInfo "[$($MyInvocation.MyCommand.Name)] Flushing USO/WU logs"
			$CommandsFlushLogs = @(
				"Stop-Service -Name usosvc"
				"Stop-Service -Name wuauserv"
			)
			RunCommands $LogPrefixFlushLogs $CommandsFlushLogs -ThrowException:$False -ShowMessage:$True
				
			robocopy $_WUETLPATH $_tempdir *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		}
	
		# Copy SIH ETLs
		if (test-path -path $_SIHETLPATH)
		{
			robocopy $_SIHETLPATH $_tempdir *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		}
		
		# Verbose Logging redirects WU ETL to systemdrive
		if (test-path -path "$Env:systemdrive\windowsupdateverbose.etl")
		{
			# windowsupdateverbose.etl is not flushed until service is stopped.
			$LogPrefixFlushLogs = "FlushLogs"
			LogInfo "[$($MyInvocation.MyCommand.Name)] Flushing USO/WU logs"
			$CommandsFlushLogs = @(
				"Stop-Service -Name usosvc"
				"Stop-Service -Name wuauserv"
			)
			RunCommands $LogPrefixFlushLogs $CommandsFlushLogs -ThrowException:$False -ShowMessage:$True
			robocopy $Env:systemdrive $_tempdir windowsupdateverbose.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		}
			
		LogInfo "[$($MyInvocation.MyCommand.Name)] Copying upgrade logs"
		cmd /r mkdir "$_tempdir\UpgradeSetup" >$null 2>&1
		cmd /r mkdir "$_tempdir\UpgradeSetup\NewOS" >$null 2>&1
		cmd /r mkdir "$_tempdir\UpgradeSetup\UpgradeAdvisor" >$null 2>&1
		
		robocopy "$Env:systemdrive\Windows10Upgrade" "$_tempdir\UpgradeSetup\UpgradeAdvisor" Upgrader_default.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\Windows10Upgrade "$_tempdir\UpgradeSetup\UpgradeAdvisor" Upgrader_win10.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy "$Env:systemdrive\$GetCurrent\logs" "$_tempdir\UpgradeSetup\UpgradeAdvisor" *.* /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy "$Env:windir\logs\mosetup" "$_tempdir\UpgradeSetup" *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		cmd /r Copy "$Env:windir.old\windows\logs\mosetup\*.log" "$_tempdir\UpgradeSetup\bluebox_windowsold.log" /y >$null 2>&1
		robocopy "$Env:windir\Panther\NewOS" "$_tempdir\UpgradeSetup\NewOS" *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy "$Env:windir\Panther\NewOS" "$_tempdir\UpgradeSetup\NewOS" miglog.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy "$Env:windir\Panther" "$_tempdir\UpgradeSetup" *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy "$Env:windir\Panther" "$_tempdir\UpgradeSetup" miglog.xml /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		cmd /r Copy "$Env:systemdrive\`$Windows.~BT\Sources\Panther\setupact.log" "$_tempdir\UpgradeSetup\setupact_tildabt.log" /y >$null 2>&1
		cmd /r Copy "$Env:systemdrive\`$Windows.~BT\Sources\Panther\setuperr.log" "$_tempdir\UpgradeSetup\setuperr_tildabt.log" /y >$null 2>&1
		cmd /r Copy "$Env:systemdrive\`$Windows.~BT\Sources\Panther\miglog.xml" "$_tempdir\UpgradeSetup\miglog_tildabt.xml" /y >$null 2>&1
		if (test-path -path "$Env:systemdrive\`$Windows.~BT\Sources\Rollback")
		{
			robocopy "$Env:systemdrive\`$Windows.~BT\Sources\Rollback" "$_tempdir\UpgradeSetup\Rollback" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
		}
		if (test-path -path "$Env:windir\Panther\NewOS")
		{
			robocopy "$Env:windir\Panther\NewOS" "$_tempdir\UpgradeSetup\PantherNewOS" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
		}
		
		# Copying the datastore file
		if (test-path -path "$Env:windir\softwaredistribution\datastore\datastore.edb")
		{
		  Write-Output "Copying WU datastore ..."
		  Stop-Service -Name usosvc >$null 2>&1
		  Stop-Service -Name wuauserv >$null 2>&1
		  robocopy "$Env:windir\softwaredistribution\datastore" $_tempdir DataStore.edb /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		}
		
		# Also copy ETLs pre-upgrade
		if (test-path -path $_WUOLDETLPATH)
		{
		  robocopy $_WUOLDETLPATH "$_tempdir\Windows.old\WU" *.etl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		}
		
		# Copy DISM Logs and DISM output
		robocopy "$Env:windir\logs\dism" $_tempdir * /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		dism /online /get-packages /format:table > $_tempdir\DISM_GetPackages.txt
		dism /online /get-features /format:table > $_tempdir\DISM_GetFeatures.txt
		
		# MUSE logs for Win10+
		if($null -ne (Get-Service -Name usosvc -ErrorAction SilentlyContinue))
		{
		  LogInfo "[$($MyInvocation.MyCommand.Name)] Copying MUSE logs ..."
		  Stop-Service -Name usosvc >$null 2>&1
		  robocopy "$Env:programdata\UsoPrivate\UpdateStore" "$_tempdir\MUSE" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
		  robocopy "$Env:programdata\USOShared\Logs" "$_tempdir\MUSE" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
		  SCHTASKS /query /v /TN \Microsoft\Windows\UpdateOrchestrator\ > "$_tempdir\MUSE\updatetaskschedules.txt"
		  robocopy "$_OLDPROGRAMDATA\USOPrivate\UpdateStore" "$_tempdir\Windows.old\MUSE" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
		  robocopy "$_OLDPROGRAMDATA%\USOShared\Logs" "$_tempdir\Windows.old\MUSE" /W:1 /R:1 /NP /LOG+:$_robocopy_log /S >$null
		}
		
		# DO logs for Win10+
		Get-DNDDoLogs $_prefix $_tempdir $_robocopy_log $_errorfile $_line $_flush_logs
	
		# WU BVT logs.
		cmd /r mkdir $_tempdir\BVT >$null 2>&1
		robocopy $Env:systemdrive\wubvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\dcatebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\wuappxebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\wuuxebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\wuauebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\WUE2ETest  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\taef\wubvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\taef\wuappxebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\taef\wuuxebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\taef\wuauebvt  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\taef\WUE2ETest  $_tempdir\BVT *.log /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy $Env:systemdrive\taef\WUE2ETest  $_tempdir\BVT *.wtl /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		
		LogInfo "[$($MyInvocation.MyCommand.Name)] Copying token cache and license store ..."
		robocopy "$Env:windir\ServiceProfiles\LocalService\AppData\Local\Microsoft\WSLicense" $_tempdir tokens.dat /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		robocopy "$Env:windir\SoftwareDistribution\Plugins\7D5F3CBA-03DB-4BE5-B4B36DBED19A6833" $_tempdir 117CAB2D-82B1-4B5A-A08C-4D62DBEE7782.cache /W:1 /R:1 /NP /LOG+:$_robocopy_log >$null
		
		LogInfo "[$($MyInvocation.MyCommand.Name)] Copying event logs ..."
		cmd /r Copy "$Env:windir\System32\winevt\Logs\Microsoft-Windows-WindowsUpdateClient%4Operational.evtx" $_tempdir /y >$null 2>&1
		cmd /r Copy "$Env:windir\System32\winevt\Logs\Microsoft-Windows-Bits-Client%4Operational.evtx" $_tempdir /y >$null 2>&1
		cmd /r Copy "$Env:windir\System32\winevt\Logs\Application.evtx" $_tempdir /y >$null 2>&1
		cmd /r Copy "$Env:windir\System32\winevt\Logs\System.evtx" $_tempdir /y >$null 2>&1
		cmd /r Copy "$Env:windir\System32\Winevt\Logs\*AppX*.evtx" $_tempdir /y >$null 2>&1
		cmd /r Copy "$Env:windir\System32\Winevt\Logs\Microsoft-WS-Licensing%4Admin.evtx"  $_tempdir /y >$null 2>&1
		cmd /r Copy "$Env:windir\System32\winevt\Logs\Microsoft-Windows-Kernel-PnP%4Configuration.evtx" $_tempdir /y >$null 2>&1
		cmd /r Copy "$Env:windir\System32\winevt\Logs\Microsoft-Windows-Store%4Operational.evtx" $_tempdir /y >$null 2>&1
		
		LogInfo "[$($MyInvocation.MyCommand.Name)] Logging registry ..."
		$RegKeysMiscInfoExport = @(
			('HKLM:Software\Microsoft\Windows\CurrentVersion\WindowsUpdate', "$($_prefix)reg_wu.txt"),
			('HKLM:Software\Microsoft\Windows\CurrentVersion\SideBySide\', "$($_prefix)reg_sidebyside.txt"),
			('HKLM:Components\CorruptionDetectedDuringAcr', "$($_prefix)reg_comp_acr.txt"),
			('HKLM:Software\Policies\Microsoft\Windows\WindowsUpdate', "$($_prefix)reg_wupolicy.txt"),
			('HKLM:SYSTEM\CurrentControlSet\Control\MUI\UILanguages', "$($_prefix)reg_langpack.txt"),
			('HKLM:Software\Policies\Microsoft\WindowsStore', "$($_prefix)reg_StorePolicy.txt"),
			('HKLM:Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate', "$($_prefix)reg_StoreWUApproval.txt"),
			('HKLM:SYSTEM\CurrentControlSet\Control\FirmwareResources', "$($_prefix)reg_FirmwareResources.txt"),
			('HKLM:Software\Microsoft\WindowsSelfhost', "$($_prefix)reg_WindowsSelfhost.txt"),
			('HKLM:Software\Microsoft\WindowsUpdate', "$($_prefix)reg_wuhandlers.txt"),
			('HKLM:Software\Microsoft\Windows\CurrentVersion\Appx', "$($_prefix)reg_appx.txt"),
			('HKLM:Software\Microsoft\Windows NT\CurrentVersion\Superfetch', "$($_prefix)reg_superfetch.txt"),
			('HKLM:Software\Setup', "$($_prefix)reg_Setup.txt"),
			('HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate', "$($_prefix)reg_peruser_wupolicy.txt"),
			('HKLM:Software\Microsoft\PolicyManager\current\device\Update', "$($_prefix)reg_wupolicy_mdm.txt"),
			('HKLM:Software\Microsoft\WindowsUpdate\UX\Settings', "$($_prefix)reg_wupolicy_ux.txt"),
			('HKLM:Software\Microsoft\Windows\CurrentVersion\WaaSAssessment', "$($_prefix)reg_WaasAssessment.txt"),
			('HKLM:Software\Microsoft\sih', "$($_prefix)reg_sih.txt")
		)
		FwExportRegistry "MiscInfo" $RegKeysMiscInfoExport -RealExport $true
		
		$RegKeysMiscInfoProperty = @(
			('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'BuildLab', "$($_prefix)reg_BuildInfo.txt"),
			('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'BuildLabEx', "$($_prefix)reg_BuildInfo.txt"),
			('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'UBR', "$($_prefix)reg_BuildInfo.txt"),
			('HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'ProductName', "$($_prefix)reg_BuildInfo.txt"),
			('HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel', 'Version', "$($_prefix)reg_AppModelVersion.txt")
		)
		FwExportRegistry "MiscInfo" $RegKeysMiscInfoProperty
		
		LogInfo "[$($MyInvocation.MyCommand.Name)] Getting directory lists ..."
		$Commands = @(
			"cmd /r Dir $Env:windir\SoftwareDistribution /s  | Out-File -Append $($_prefix)dir_softwaredistribution.txt"
			"cmd /r Dir $Env:windir\SoftwareDistribution /ah | Out-File -Append $($_prefix)dir_softwaredistribution_hidden.txt"
		)
		RunCommands "directory_lists" $Commands -ThrowException:$False -ShowMessage:$True
		
		Write-Output "Getting app list ..."
		if ($_WIN8_OR_LATER -eq $true)    
		{ 
			try { Import-Module appx;get-appxpackage -allusers | Out-File -FilePath $_tempdir\GetAppxPackage.log }
			catch { LogException "Get-Appxpackage failed" $_ }
		}
		if ($_WINBLUE_OR_LATER -eq $true) 
		{ 
			try { Get-Appxpackage -packagetype bundle | Out-File -FilePath $_tempdir\GetAppxPackageBundle.log }
			catch { LogException "Get-Appxpackage failed" $_ }
		}
		LogInfo "[$($MyInvocation.MyCommand.Name)] Getting download list ..."
		bitsadmin /list /allusers /verbose > $_tempdir\bitsadmin.log
		
		LogInfo "[$($MyInvocation.MyCommand.Name)] Getting certificate list ..."
		certutil -store root > $_tempdir\certs.txt 2>&1
		
		LogInfo "[$($MyInvocation.MyCommand.Name)] Getting installed update list ..."
		$Commands = @(
			"Get-CimInstance -ClassName win32_quickfixengineering | Out-File -Append $($_prefix)InstalledUpdates.log"
			"sc.exe query wuauserv | Out-File -Append $($_prefix)wuauserv-state.txt"
		)
		RunCommands "installed_update" $Commands -ThrowException:$False -ShowMessage:$True
		
		LogInfo "[$($MyInvocation.MyCommand.Name)] Collecting file versions ..."
		
		$binaries = @("wuaext.dll", "wuapi.dll", "wuaueng.dll", "wucltux.dll", "wudriver.dll", "wups.dll", "wups2.dll", "wusettingsprovider.dll", "wushareduxresources.dll", "wuwebv.dll", "wuapp.exe", "wuauclt.exe", "storewuauth.dll", "wuuhext.dll", "wuuhmobile.dll", "wuau.dll", "wuautoappupdate.dll")
		foreach($file in $binaries)
		{
			FwFileVersion -Filepath ("$Env:windir\system32\$file") | Out-File -FilePath ($_prefix+"FilesVersion.txt") -Append
		}
	
		$muis = @("wuapi.dll.mui", "wuaueng.dll.mui", "wucltux.dll.mui", "wusettingsprovider.dll.mui", "wushareduxresources.dll.mui")
		foreach($file in $muis)
		{
			FwFileVersion -Filepath ("$Env:windir\system32\en-US\$file") | Out-File -FilePath ($_prefix+"FilesVersion.txt") -Append
		}
		
		# end
		LogInfo "[$($MyInvocation.MyCommand.Name)] Restarting services ..."
		$Commands = @(
			"Start-Service -Name dosvc"
			"Start-Service -Name usosvc"
			"Start-Service -Name wuauserv"
		)
		RunCommands "Restart_services" $Commands -ThrowException:$False -ShowMessage:$True
		LogInfo "[$($MyInvocation.MyCommand.Name)] Finished DND_WUlogs!"
		EndFunc $MyInvocation.MyCommand.Name
}


function global:CollectBasicLog {
	param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$False)]
		[String]$Stage=$Null
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "[$($MyInvocation.MyCommand.Name)] Running BasicLog"
	If([string]::IsNullOrEmpty($Stage)){
		$script:BasicSubFolder = "BasicLog$LogSuffix"
	}Else{
		$script:BasicSubFolder = "BasicLog$LogSuffix-$Stage"
	}
	$BasicLogFolder = $global:LogFolder + "\" + $script:BasicSubFolder
	$SetupLogFolder = "$BasicLogFolder\DnD-Setup"
	Try{
		FwCreateLogFolder $BasicLogFolder
		FwCreateLogFolder $SetupLogFolder
	}Catch{
		LogError ("Unable to create log folder. " + $_.Exception.Message)
		Return
	}
	FwGet-OSversion-Build
	FwGet-basic-system-info 
	FwGet-basic-setup-info
	FwGet-basic-networking-info
	FwGet-basic-UEX-info
	FwGet-basic-Storage-info
	FWgetRegList $global:TssPhase
	FWaddEvtLog @("System", "Application")
	FWgetEvtLogList $global:TssPhase
	EndFunc $MyInvocation.MyCommand.Name
}

function global:CollectFullLog {
		<#
	.SYNOPSIS
		The function collects basic logs, likely applicable for many different tracing scenarios
	.DESCRIPTION
		The function collects basic logs, likely applicable for many different tracing scenarios. 
		The list of logs is hardcoded.
	.NOTES
		Date:   19.04.2021, #we# 2021-12-05
	#>
	param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$False)]
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[switch]$Full			# select -Full to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] Running FullLog..."
	If([string]::IsNullOrEmpty($Stage)){
		$script:BasicSubFolder = "FullLog$LogSuffix"
		#$BasicLogFolder = "$global:LogFolder\BasicLog$LogSuffix"
	}Else{
		$script:BasicSubFolder = "FullLog$LogSuffix-$Stage"
		#$BasicLogFolder = "$global:LogFolder\FullLog$LogSuffix-$Stage"
	}
	$BasicLogFolder = $global:LogFolder + "\" + $script:BasicSubFolder
	$EventLogFolder = "$BasicLogFolder\EventLogs"
	$SetupLogFolder = "$BasicLogFolder\DnD-Setup"
	Try{
		FwCreateLogFolder $BasicLogFolder
		FwCreateLogFolder $EventLogFolder
		FwCreateLogFolder $SetupLogFolder
	}Catch{
		LogError ("Unable to create log folder. " + $_.Exception.Message)
		Return
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)] Exporting registry hives"
	FwGetRegHives

	Try{
		$IsServerSKU = (Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop).Caption -like "*Server*"
	}Catch{
		LogErrorFile ("Get-CimInstance for CIM_OperatingSystem failed.`n" + 'Command=' + $_.CategoryInfo.Activity + ' HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + ' Exception=' + $_.CategoryInfo.Reason + ' Message=' + $_.Exception.Message)
		$IsServerSKU = $False
	}

	FwGet-OSversion-Build
	FwGet-basic-system-info -FullBasic
	FWaddEvtLog @("System", "Application")
	FwGet-basic-setup-info -FullBasic
	FwGet-basic-networking-info -FullBasic
	FwGet-basic-UEX-info -FullBasic
	FwGet-basic-Storage-info -FullBasic
	FWgetRegList $global:TssPhase
	FWgetEvtLogList $global:TssPhase
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-OSversion-Build{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] Obtaining OS version with build number" # Note: #!# LogInfoFile would fail at this stage as $LogFolder does not exist
	$OutFile = $BasicLogFolder + "\OSVersion-Build.txt"
	$OSVersionReg = Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows NT\CurrentVersion'
	If($OperatingSystemInfo.OSVersion -ge 10){
		'OS Version: ' + $OSVersionReg.ReleaseID + '(OS Build ' + $OSVersionReg.CurrentMajorVersionNumber + '.' + $OSVersionReg.CurrentMinorVersionNumber + '.' + $OSVersionReg.CurrentBuildNumber + '.' + $OSVersionReg.UBR + ')' | Out-File -Append $OutFile
	}Else{
		'OS Version: ' + $OSVersionReg.CurrentVersion + '.' + $OSVersionReg.CurrentBuild | Out-File -Append $OutFile
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-basic-system-info{
	param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[switch]$FullBasic		# select -FullBasic to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($FullBasic){ $B_mode="Full" }else{$B_mode="Basic"}
	$LogPrefix = $B_mode + "Log-System"

	#------ Basic ------#
	LogInfo "[$LogPrefix] Obtaining system basic info using WMI"
	Get-CimInstance -Class Win32_Environment | Where-Object { $_.SystemVariable -eq 'True' } | Format-List Name,VariableValue | Out-File -Append $BasicLogFolder\Environment_SYSTEM.txt
	$Commands = @(
		# Basic
		"Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop | fl * | Out-File -Append $BasicLogFolder\OS_info.txt"
		"Get-CimInstance -Class CIM_ComputerSystem -ErrorAction Stop | fl * | Out-File -Append $BasicLogFolder\Computer_info.txt"
		# Hotfix
		"Get-HotFix | Sort-Object -Property InstalledOn | Out-File -Append $BasicLogFolder\hotfixes.txt"
		# User and profile
		"Whoami /user 2>&1 | Out-File -Append  $BasicLogFolder\Whoami.txt"
		"Get-CimInstance -Class Win32_UserProfile -ErrorAction Stop | Out-File -Append $BasicLogFolder\Win32_UserProfile.txt"
		"Get-ChildItem `'HKLM:Software\Microsoft\Windows NT\CurrentVersion\ProfileList`' -Recurse | Out-File -Append $BasicLogFolder\_Reg_Profilelist.txt"
		# Powercfg
		"PowerCfg.exe /list 2>&1 | Out-File -Append $BasicLogFolder\powercfg.txt"
		"PowerCfg.exe /a 2>&1 | Out-File -Append $BasicLogFolder\powercfg.txt"
		"PowerCfg.exe /qh 2>&1 | Out-File -Append $BasicLogFolder\powercfg.txt"
		# BCDEdit
		"bcdedit.exe /enum 2>&1 | Out-File -Append $BasicLogFolder\Bcdedit.txt"
		"bcdedit.exe /enum all 2>&1 | Out-File -Append $BasicLogFolder\Bcdedit-all.txt"
		"bcdedit.exe /enum all /v 2>&1 | Out-File -Append $BasicLogFolder\Bcdedit-all-v.txt"
		# Environment variables
		"Get-ChildItem env:| fl | Out-File -Append $BasicLogFolder\Environment_User.txt"
	)
	if ($FullBasic) {
		$Commands += @(
			# Basic
			"Get-CimInstance -Class CIM_Processor -ErrorAction Stop | fl * | Out-File -Append $BasicLogFolder\CPU_info.txt"
			# WER
			"Get-ChildItem `'HKLM:Software\Microsoft\Windows\Windows Error Reporting`' -Recurse | Out-File -Append $BasicLogFolder\_Reg_WER.txt"
			"Get-ItemProperty `'HKLM:System\CurrentControlSet\Control\CrashControl`' | Out-File -Append $BasicLogFolder\_Reg_Dump.txt"
			"Copy-Item `'C:\ProgramData\Microsoft\Windows\WER`' $BasicLogFolder -Recurse -ErrorAction SilentlyContinue"
			# KIR
			"Copy-Item `'C:\ProgramData\Microsoft\Windows\OneSettings\FeatureConfig.json`' $BasicLogFolder -Recurse -ErrorAction SilentlyContinue"
			"Copy-Item `'C:\ProgramData\Microsoft\Windows\OneSettings\FeatureConfig.bak.json`' $BasicLogFolder -Recurse -ErrorAction SilentlyContinue"
			"Get-Item `'C:\ProgramData\Microsoft\Windows\OneSettings\FeatureConfig.*`' | Select-Object FullName,LastWriteTime | Out-File -Append $BasicLogFolder\FeatureConfig_time.txt"
		)
	}
	# TPM
	If($global:OSVersion.Build -gt 9600){
		 $TPMObj = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -class win32_tpm -ErrorAction Ignore
		If($TPMObj -ne $Null){
			$Commands += "Get-Tpm -ErrorAction Ignore | Out-File -Append $BasicLogFolder\TPM.txt"
		}Else{
			Write-Output "TPM is not supported on this system." | Out-File -Append "$BasicLogFolder\TPM.txt"
		}
	}Else{
		$Commands += "Get-Tpm -ErrorAction Ignore | Out-File -Append $BasicLogFolder\TPM.txt"
	}
	# Windows feature
	FwGetSrvRole
	# CoreInfo
	$CoreInfoCommand = Get-Command "CoreInfo.exe" -ErrorAction Ignore
	If($CoreInfoCommand -ne $Null){
		$Commands += "CoreInfo.exe /AcceptEula | Out-File -Append $BasicLogFolder\CoreInfo.txt"
	} else { LogInfoFile " CoreInfo.exe not found"}
	# Windows 10 Defender
	If($OperatingSystemInfo.OSVersion -ge 10){
		$Commands += @(
			"Get-MpComputerStatus -ErrorAction Stop | Out-File -Append $BasicLogFolder\WindowsDefender.txt",
			"Get-MpPreference -ErrorAction Stop | Out-File -Append $BasicLogFolder\WindowsDefender.txt"
		)
	}
	if ($FullBasic) {
		FwGetDSregCmd -Subfolder $script:BasicSubFolder
		# Process info, services info and file version
		FwListProcsAndSvcs -Subfolder $script:BasicSubFolder
		# Driver info
		$Commands += @("driverquery /v | Out-File $BasicLogFolder\driverinfo.txt")
	}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True
	# Product info
	Write-Output "===== 32bit applications =====" | Out-File "$BasicLogFolder\Installed_products.txt"
	Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File -Append "$BasicLogFolder\Installed_Products.txt"
	Write-Output "`n===== 64bit applications =====" | Out-File -Append "$BasicLogFolder\Installed_products.txt"
	Get-ItemProperty "HKLM:Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File -Append "$BasicLogFolder\Installed_Products.txt"
	# Tasklist
	LogInfo "[$LogPrefix] Creating process list..."
	$Processes = Get-Process
	Write-Output(' ID		 ProcessName') | Out-File -Append "$BasicLogFolder\tasklist.txt"
	Write-Output('---------------------------') | Out-File -Append "$BasicLogFolder\tasklist.txt"
	ForEach($Process in $Processes){
		$PID16 = '0x' + [Convert]::ToString($Process.ID,16)
		Write-Output(($Process.ID).ToString() + '(' + $PID16 + ')	'  + $Process.ProcessName) | Out-File -Append "$BasicLogFolder\tasklist.txt"
	}
	Write-Output('=========================================================================') | Out-File -Append "$BasicLogFolder\tasklist.txt"
	tasklist /svc 2>&1 | Out-File -Append "$BasicLogFolder\tasklist.txt"
	LogInfo "[$LogPrefix] Running tasklist -v"
	tasklist /v 2>&1 | Out-File -Append "$BasicLogFolder\tasklist-v.txt"
	# .NET version
	If(test-path -path "HKLM:Software\Microsoft\NET Framework Setup\NDP\v4\Full"){
		$Full = Get-ItemProperty "HKLM:Software\Microsoft\NET Framework Setup\NDP\v4\Full"
		Write-Output(".NET version: $($Full.Version)") | Out-File -Append "$BasicLogFolder\DotNet-Version.txt"
		Write-Output("") | Out-File -Append "$BasicLogFolder\DotNet-Version.txt"
	}
	FwExportRegToOneFile $LogPrefix 'HKLM:Software\Microsoft\NET Framework Setup\NDP' "$BasicLogFolder\DotNet-Version.txt"
	# Installed .NET KB
	$DotNetVersions = Get-ChildItem HKLM:\Software\WOW6432Node\Microsoft\Updates | Where-Object {$_.name -like "*.NET Framework*"}
	ForEach($Version in $DotNetVersions){ 
		$Updates = Get-ChildItem $Version.PSPath
		$Version.PSChildName | Out-File -Append "$BasicLogFolder\Installed_DotNetKB.txt"
		ForEach ($Update in $Updates){
			$Update.PSChildName | Out-File -Append "$BasicLogFolder\Installed_DotNetKB.txt"
		}
	}

	Get-ComputerInfo | Out-File -Append "$BasicLogFolder\msinfo32.txt"
	LogInfo "[$($MyInvocation.MyCommand.Name)] Running Get-ComputerInfo..."
	
	LogInfo "[$LogPrefix] Exporting recovery registry keys"
	$RecoveryKeys = @(
		('HKLM:System\CurrentControlSet\Control\CrashControl', "$BasicLogFolder\_Reg_CrashControl.txt"),
		('HKLM:System\CurrentControlSet\Control\Session Manager\Memory Management', "$BasicLogFolder\_Reg_MemoryManagement.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion\AeDebug', "$BasicLogFolder\_Reg_AeDebug.txt"),
		('HKLM:Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Option', "$BasicLogFolder\_Reg_ImageFileExecutionOption.txt"),
		('HKLM:System\CurrentControlSet\Control\Session Manager\Power', "$BasicLogFolder\_Reg_Power.txt")
	)
	FwExportRegistry $LogPrefix $RecoveryKeys
	# RunOnce
	if ($FullBasic) {
		$StartupKeys = @(
			"HKCU:Software\Microsoft\Windows\CurrentVersion\Run"
			"HKCU:Software\Microsoft\Windows\CurrentVersion\Runonce"
			"HKCU:Software\Microsoft\Windows\CurrentVersion\RunonceEx"
			"HKCU:Software\Microsoft\Windows\CurrentVersion\RunServices"
			"HKCU:Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\policies\Explorer\Run"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\Run"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\Runonce"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\RunonceEx"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\RunServices"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
			"HKLM:Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
		)
		FwExportRegToOneFile $LogPrefix $StartupKeys "$BasicLogFolder\_Reg_RunOnce.txt"
		$WinlogonKeys = @(
			'HKCU:Software\Microsoft\Windows NT\CurrentVersion'
			'HKCU:Software\Microsoft\Windows NT\CurrentVersion\Windows'
			'HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
			'HKLM:Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
		)
		FwExportRegToOneFile $LogPrefix $WinlogonKeys "$BasicLogFolder\_Reg_Winlogon.txt"
		# Installed product
		If(FwIsElevated){
			LogInfo "[$LogPrefix] Getting installed product info"
			$UninstallKey = 'HKLM:Software\Microsoft\Windows\CurrentVersion\Uninstall'
			$Registries = Get-ChildItem $UninstallKey | Get-ItemProperty
			"Install date`tVersion`t`tProdcut Name" | Out-File -Append "$BasicLogFolder\Installed_Product.txt"
			ForEach($Registry in $Registries){
				If(($Registry.InstallSource -ne $Null -and $Registry.InstallSource -ne '') -and (Test-Path -Path $Registry.InstallSource)){
				   $Registry.InstallDate + "`t" + $Registry.Version + "`t" + $Registry.DisplayName | Out-File -Append "$BasicLogFolder\Installed_Product.txt"
				}
			}
		}
		# Group policy
		LogInfo "[$LogPrefix] Obtaining group policy"
		$Commands = @(
			"gpresult /h $BasicLogFolder\Policy_gpresult.html"
			"gpresult /z | Out-File $BasicLogFolder\Policy_gpresult-z.txt"
			"Secedit.exe /export /cfg $BasicLogFolder\Policy_secedit.txt"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True
	}
	#Policy keys
	$PoliciesKeys = @(
		'HKCU:Software\Policies'
		'HKLM:Software\Policies'
		'HKCU:Software\Microsoft\Windows\CurrentVersion\Policies'
		'HKLM:Software\Microsoft\Windows\CurrentVersion\Policies'
	)
	FwExportRegToOneFile $LogPrefix $PoliciesKeys "$BasicLogFolder\_Reg_Policy.txt"

	# Eventlog
	$EventLogs = Get-WinEvent -ListLog * -ErrorAction Ignore
	LogInfo ("[$LogPrefix] Exporting " + $EventLogs.Count + " event logs")
	ForEach($EventLog in $EventLogs){
		if ($FullBasic){	#we# issue#405
			$tmpStr = $EventLog.LogName.Replace('/','-')
			$EventLogName = ($tmpStr.Replace(' ','-') + '.evtx')
			wevtutil epl $EventLog.LogName "$EventLogFolder\$EventLogName" 2>&1 | Out-Null
		}
	}
	# Proxy
	$Commands = @(
		"REG EXPORT `"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings`" $BasicLogFolder\_Reg_HKCU_Internet_Settings.txt",
		"netsh winhttp show proxy 2>> $global:ErrorLogFile | Out-File -Append $BasicLogFolder\WinHTTP_Proxy.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$True -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-basic-setup-info{
	param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[switch]$FullBasic		# select -FullBasic to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($FullBasic){ $B_mode="Full" }else{$B_mode="Basic"}
	$LogPrefix = $B_mode + "Log-Setup"

	#------ Setup ------#
	LogInfo ("[$LogPrefix] Copying setup files")
	$ServicingFiles = @(
		"C:\Windows\INF\Setupapi.*"
		"C:\Windows\Logs\CBS\*.Log"
		"C:\Windows\Logs\DISM\*"
		"C:\Windows\logs\DPX\setupact.log"
		"C:\Windows\logs\CBS\CheckSUR.log"
		"C:\Windows\SoftwareDistribution\ReportingEvents.log"
		"C:\Windows\servicing\Sessions.xml"
		"C:\Windows\servicing\Sessions\*.*"
		"C:\Windows\winsxs\reboot.xml"
		"C:\Windows\Setup\State\State.ini"
		"C:\Windows\Panther\setup*.log"
		"C:\Windows\system32\sysprep\Unattend.xml"
	)
	if ($FullBasic) {
		$ServicingFiles += @(	
			"C:\Windows\winsxs\pending.xml"
			"C:\Windows\winsxs\pending.xml.bad"
			"C:\Windows\winsxs\poqexec.log"
			"C:\Windows\system32\driverstore\drvindex.dat"
			"C:\Windows\system32\driverstore\INFCACHE.1"
			"C:\Windows\system32\driverstore\infpub.dat"
			"C:\Windows\system32\driverstore\infstor.dat"
			"C:\Windows\system32\driverstore\infstrng.dat"
		)
	}
	$CopyCmds = @()
	ForEach($ServicingFile in $ServicingFiles){
		If(Test-Path -Path $ServicingFile){
			$CopyCmd = "Copy-Item $ServicingFile $SetupLogFolder -ErrorAction SilentlyContinue"
			$CopyCmds += $CopyCmd
		}
	}
	If(Test-Path -Path "C:\Windows\system32\sysprep\Panther"){
		$CopyCmds += "Copy-Item C:\Windows\system32\sysprep\Panther $SetupLogFolder\Panther -Recurse"
	}
	RunCommands $LogPrefix $CopyCmds -ThrowException:$False -ShowMessage:$True

	LogInfo ("[$LogPrefix] Exporting setup registry keys and getting package info")
	#reg save "HKLM\COMPONENTS" "$SetupLogFolder\COMPONENT.HIV"
	reg save "HKLM\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" "$SetupLogFolder\Component Based Servicing.HIV" 2>&1 | Out-Null
	FwExportRegToOneFile $LogPrefix "HKLM:System\CurrentControlSet\services\TrustedInstaller" "$BasicLogFolder\_Reg_TrustedInstaller.txt"
	FwExportRegToOneFile $LogPrefix "HKLM:Software\Microsoft\Windows\CurrentVersion\Setup\State" "$BasicLogFolder\_Reg_State.txt"
	dism /online /get-packages 2>&1| Out-File "$SetupLogFolder\dism-get-package.txt"
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-basic-networking-info{
	param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[switch]$FullBasic		# select -FullBasic to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($FullBasic){ $B_mode="Full" }else{$B_mode="Basic"}
	$LogPrefix = $B_mode + "Log-Net"
	#------- Networking --------#
	# TCP/IP
	LogInfo ("[$LogPrefix] Gathering networking info")
	$Commands = @(
		"ipconfig /all 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
		"ipconfig /displaydns 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
		"route print 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
		"netstat -nato 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
		"netstat -anob 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
		"netsh int tcp show global 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_offload.txt"
		"netsh int ipv4 show offload 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_offload.txt"
		"netstat -nato -p tcp 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_offload.txt"
		# SMB
		"Get-SmbMapping -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
		"Get-SmbClientConfiguration -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
		"Get-SmbClientNetworkInterface -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
		"Get-SmbConnection -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
		"Get-SmbMultichannelConnection -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
		"Get-SmbMultichannelConstraint -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Client_info.txt"
		"net config workstation 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Client_net_command.txt"
		"net statistics workstation 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Client_net_command.txt"
		"net use 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Client_net_command.txt"
		"net accounts 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Client_net_command.txt"
		"Get-SmbServerConfiguration -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
		"Get-SmbServerNetworkInterface -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
		"Get-SmbShare -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
		"net config server 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
		"net session 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
		"net files 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
		"net share 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
		# LBFO
		"Get-NetLbfoTeam -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetLbfo.txt"
		"Get-NetLbfoTeamMember -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetLbfo.txt"
		"Get-NetLbfoTeamNic -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetLbfo.txt"
		# NIC
		"Get-NetAdapter -IncludeHidden -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
		# COM/DCOM/RPC
		"netsh rpc show int 2>&1 | Out-File -Append $BasicLogFolder\Net_rpcinfo.txt"
		"netsh rpc show settings 2>&1 | Out-File -Append $BasicLogFolder\Net_rpcinfo.txt"
		"netsh rpc filter show filter 2>&1 | Out-File -Append $BasicLogFolder\Net_rpcinfo.txt"
	)
	if ($FullBasic) {
		$Commands += @(
			"arp -a 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
			"netstat -es 2>&1 | Out-File -Append $BasicLogFolder\Net_TCPIP_info.txt"
			"Get-NetIPAddress -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetIPInterface -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetIPConfiguration -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetIPv4Protocol -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetIPv6Protocol  -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetOffloadGlobalSetting -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetPrefixPolicy -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetRoute -IncludeAllCompartments -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetTCPConnection -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetTransportFilter -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetTCPSetting -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetUDPEndpoint -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			"Get-NetUDPSetting -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_TCPIP_pscmdlets.txt"
			# Firewall
			"Show-NetIPsecRule -PolicyStore ActiveStore -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
			"Get-NetIPsecMainModeSA -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
			"Get-NetIPsecQuickModeSA -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
			"Get-NetFirewallProfile -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_info_pscmdlets.txt"
			"Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_Firewall_Get-NetFirewallRule.txt"
			"netsh advfirewall show allprofiles 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show allprofiles state 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show currentprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show domainprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show global 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show privateprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show publicprofile 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"netsh advfirewall show store 2>&1 | Out-File -Append $BasicLogFolder\Net_Firewall_advfirewall.txt"
			"Copy-Item C:\Windows\System32\LogFiles\Firewall\pfirewall.log $BasicLogFolder\Net_Firewall_pfirewall.log -ErrorAction SilentlyContinue"
			# SMB
			"Get-SmbMultichannelConnection -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
			"Get-SmbMultichannelConstraint -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
			"Get-SmbOpenFile -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
			"Get-SmbSession -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
			"Get-SmbWitnessClient -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_SMB_Server_info.txt"
			#NIC
			"Get-NetAdapterAdvancedProperty -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterBinding -AllBindings -IncludeHidden -ErrorAction Stop | select Name, InterfaceDescription, DisplayName, ComponentID, Enabled | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterChecksumOffload -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterEncapsulatedPacketTaskOffload -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterHardwareInfo -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterIPsecOffload -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterLso -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterPowerManagement -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterQos -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterRdma -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterRsc -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterRss -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterSriov -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterSriovVf -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterStatistics -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterVmq -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterVmqQueue -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
			"Get-NetAdapterVPort -ErrorAction Stop | Out-File -Append $BasicLogFolder\Net_NetAdapterInfo.txt"
		)
	}
	If($IsServerSKU){
		#we: command not valid# $Commands += "net statistics server 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
	}Else{
		$Commands += "net statistics WorkStation 2>&1 | Out-File -Append $BasicLogFolder\Net_SMB_Server_net_command.txt"
	}
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	# TCPIP registry keys
	LogInfo ("[$LogPrefix] Gathering TCP/IP registries")
	$TCPIPKeys = @(
		"HKLM:Software\Policies\Microsoft\Windows\TCPIP"
		"HKLM:System\CurrentControlSet\services\TCPIP"
		"HKLM:System\CurrentControlSet\Services\Tcpip6"
		"HKLM:System\CurrentControlSet\Services\tcpipreg"
		"HKLM:System\CurrentControlSet\Services\iphlpsvc"
	)
	FwExportRegToOneFile $LogPrefix $TCPIPKeys "$BasicLogFolder\_Reg_Net_TCPIP.txt"

	if ($FullBasic) {
		# SMB
		LogInfo ("[$LogPrefix] Gathering SMB registry keys")
		$SMBKeys = @(
			"HKLM:System\CurrentControlSet\services\LanManWorkstation"
			"HKLM:System\CurrentControlSet\services\lmhosts"
			"HKLM:System\CurrentControlSet\services\MrxSmb"
			"HKLM:System\CurrentControlSet\services\MrxSmb10"
			"HKLM:System\CurrentControlSet\services\MrxSmb20"
			"HKLM:System\CurrentControlSet\services\MUP"
			"HKLM:System\CurrentControlSet\services\NetBIOS"
			"HKLM:System\CurrentControlSet\services\NetBT"
			"HKCU:Network"
			"HKLM:System\CurrentControlSet\Control\NetworkProvider"
			"HKLM:System\CurrentControlSet\services\Rdbss"
			#"HKLM:System\CurrentControlSet\Control\SMB"
		)
		FwExportRegToOneFile $LogPrefix $SMBKeys "$BasicLogFolder\_Reg_Net_SMB_Client.txt"

		$SMBServerKeys = @(
			"HKLM:System\CurrentControlSet\services\LanManServer"
			"HKLM:System\CurrentControlSet\services\SRV"
			"HKLM:System\CurrentControlSet\services\SRV2"
			"HKLM:System\CurrentControlSet\services\SRVNET"
		)
		FwExportRegToOneFile $LogPrefix $SMBServerKeys "$BasicLogFolder\_Reg_Net_SMB_Server.txt"
	}
	
	LogInfo ("[$LogPrefix] Gathering RPC registry keys")
	$RPCKeys = @(
		'HKLM:Software\Microsoft\Rpc'
		'HKLM:System\CurrentControlSet\Services\RpcEptMapper'
		'HKLM:System\CurrentControlSet\Services\RpcLocator'
		'HKLM:System\CurrentControlSet\Services\RpcSs'
	)
	FwExportRegToOneFile $LogPrefix $RPCKeys "$BasicLogFolder\_Reg_Net_RPC.txt"

	LogInfo ("[$LogPrefix] Exporting Ole registry")
	FwExportRegToOneFile $LogPrefix 'HKLM:Software\Microsoft\Ole' "$BasicLogFolder\_Reg_Net_Ole.txt"
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-basic-UEX-info{
	param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[switch]$FullBasic		# select -FullBasic to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($FullBasic){ $B_mode="Full" }else{$B_mode="Basic"}
	$LogPrefix = $B_mode + "Log-Ui"
	#------- UEX --------#
	LogInfo ("[$LogPrefix] Gathering UEX info")

	$Commands = @(
		"schtasks.exe /query /fo CSV /v | Out-File -Append $BasicLogFolder\schtasks_query.csv"
		"schtasks.exe /query /v | Out-File -Append $BasicLogFolder\schtasks_query.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True

	If($OperatingSystemInfo.OSVersion -eq 10){
		LogInfo ("[$LogPrefix] Gathering MDM info")
		If($OSBuild -le 14393){
			$MDMCmdLine = "MdmDiagnosticsTool.exe $BasicLogFolder\MdmDiagnosticsTool.xml | Out-Null"
		}Else{
			$MDMCmdLine = "MdmDiagnosticsTool.exe -out $BasicLogFolder\MDM  | Out-Null"
		}
		RunCommands $LogPrefix $MDMCmdLine -ThrowException:$False -ShowMessage:$True
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-basic-Storage-info{
	param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[switch]$FullBasic		# select -FullBasic to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($FullBasic){ $B_mode="Full" }else{$B_mode="Basic"}
	$LogPrefix = $B_mode + "Log-Sto"
	#------- Storage --------#
	LogInfo ("[$LogPrefix] Gathering Storage info")
	$Commands = @(
		"fltmc | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
		"fltmc Filters | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
		"fltmc Instances | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
		"fltmc Volumes | Out-File -Append $BasicLogFolder\Storage_fltmc.txt"
		"vssadmin list volumes | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
		"vssadmin list writers | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
		"vssadmin list providers | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
		"vssadmin list shadows | Out-File -Append $BasicLogFolder\Storage_VSSAdmin.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}
#end region --- FwBasicLog functions  & common helper functions

Function global:FwCollect_BasicLog{
	<#
	.SYNOPSIS
		The function collects basic logs, likely applicable for many different tracing scenarios
	.DESCRIPTION
		The function collects basic logs, likely applicable for many different tracing scenarios. 
		The list of logs is hardcoded.
	.NOTES
		Date:   19.04.2021, #we# 2021-12-05
	#>
	param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$False)]
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[switch]$Full			# select -Full to collect Full Basic data
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = 'Full-BasicLog'
	LogInfo "[$LogPrefix] .. running Full BasicLog"
	If([string]::IsNullOrEmpty($Stage)){
		$script:BasicSubFolder = "BasicLog$LogSuffix"
		#$BasicLogFolder = "$global:LogFolder\BasicLog$LogSuffix"
	}Else{
		$script:BasicSubFolder = "BasicLog$LogSuffix-$Stage"
		#$BasicLogFolder = "$global:LogFolder\BasicLog$LogSuffix-$Stage"
	}
	$BasicLogFolder = $global:LogFolder + "\" + $script:BasicSubFolder
	$EventLogFolder = "$BasicLogFolder\EventLogs"
	$SetupLogFolder = "$BasicLogFolder\DnD-Setup"
	Try{
		FwCreateLogFolder $BasicLogFolder
		FwCreateLogFolder $EventLogFolder
		FwCreateLogFolder $SetupLogFolder
	}Catch{
		LogError ("Unable to create log folder. " + $_.Exception.Message)
		Return
	}

	Try{
		$IsServerSKU = (Get-CimInstance -Class CIM_OperatingSystem -ErrorAction Stop).Caption -like "*Server*"
	}Catch{
		LogErrorFile ("Get-CimInstance for CIM_OperatingSystem failed.`n" + 'Command=' + $_.CategoryInfo.Activity + ' HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + ' Exception=' + $_.CategoryInfo.Reason + ' Message=' + $_.Exception.Message)
		$IsServerSKU = $False
	}

	FwGet-OSversion-Build
	FwGet-basic-system-info -FullBasic
	FWaddEvtLog @("System", "Application")	#we# issue#405
	FwGet-basic-setup-info -FullBasic
	FwGet-basic-networking-info -FullBasic
	FwGet-basic-UEX-info -FullBasic
	FwGet-basic-Storage-info -FullBasic
	FWgetRegList $global:TssPhase
	FWgetEvtLogList $global:TssPhase

	if ($FullBasic) {
		FwWaitForProcess $global:msinfo32NFO 300
		#LogInfo ("[BasicLog] msinfo32 completed.")
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwCollect_MiniBasicLog{
	param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$False)]
		[String]$Stage=$Null
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = 'Mini-BasicLog'
	LogDebug "[$LogPrefix] .. running Mini BasicLog"
	If([string]::IsNullOrEmpty($Stage)){
		$script:BasicSubFolder = "BasicLog_Mini$LogSuffix"
		#$BasicLogFolder = "$global:LogFolder\BasicLog_Mini$LogSuffix" 			#we# 
	}Else{
		$script:BasicSubFolder = "BasicLog_Mini$LogSuffix-$Stage"
		#$BasicLogFolder = "$global:LogFolder\BasicLog_Mini$LogSuffix-$Stage"	#we# 
	}
	$BasicLogFolder = $global:LogFolder + "\" + $script:BasicSubFolder
	$SetupLogFolder = "$BasicLogFolder\DnD-Setup"
	Try{
		FwCreateLogFolder $BasicLogFolder
		FwCreateLogFolder $SetupLogFolder
	}Catch{
		LogError ("Unable to create log folder. " + $_.Exception.Message)
		Return
	}

	FwGet-OSversion-Build
	FwGet-basic-system-info 
	FWaddEvtLog @("System", "Application") #we# issue#405
	FwGet-basic-setup-info
	FwGet-basic-networking-info
	FwGet-basic-UEX-info
	FwGet-basic-Storage-info
	FWgetRegList $global:TssPhase
	FWgetEvtLogList $global:TssPhase
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetHandle {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if (Test-Path $HandlePath) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] Collecting Handle output at $TssPhase"
		if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "Handle" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_Handle.txt"}
		$Commands = @(
			"handle.exe -a /AcceptEula | Out-File -Append $outFile"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
	}
}

function global:FwGetNetAdapter {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)] dump NetAdapter info with PowerShell commands at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "NetAdapter" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_NetAdapter.txt"}
	"Get-NetAdapter","Get-NetIPAddress","Get-NetIPConfiguration" | ForEach-Object { 
		$Commands = @("$_ | Out-File -Append $outFile"); RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False }
	#we# ToDo: 	if "!_HypHost!" equ "1" (  Get-VMNetworkAdapter * | fl | Out-file $global:LogFolder\$($LogPrefix)PsCommand_NetAdapter_!mode!.txt -Append -Encoding ascii )
	if ($global:InvocationLine -match "HypHost") { Get-VMNetworkAdapter * | fl | Out-file $global:LogFolder\$($LogPrefix)PsCommand_NetAdapter$TssPhase.txt -Append -Encoding ascii }
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwGetVMNetAdapter {
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	LogInfo "[$($MyInvocation.MyCommand.Name)]  dump VMNetworkAdapter info with PowerShell commands at $TssPhase"
	if ([string]::IsNullOrEmpty($Subfolder)) { $outFile = $PrefixTime + "VMNetworkAdapter" + $TssPhase + ".txt" } else { $outFile = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_VMNetworkAdapter.txt"}
	$Commands = @(
		"Get-NetAdapter -includehidden | Out-File -Append $outFile"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	if (Test-Path $env:windir\System32\virtmgmt.msc) {
		"=== PowerShell Get-VMNetworkAdapter -VMName * ft Name,VMName,IPAddresses,MacAddress,AdapterId,SwitchName,SwitchId,VMQueue,VmqUsage,Status -AutoSize Out-String -Width 4096" >> $outFile
		Get-VMNetworkAdapter -VMName * |ft Name,VMName,IPAddresses,MacAddress,AdapterId,SwitchName,SwitchId,VMQueue,VmqUsage,Status -AutoSize |Out-String -Width 4096 | Out-File -Append $outFile
	} else {LogInfo "[$($MyInvocation.MyCommand.Name)] [Info] This machine is not hosting Hyper-V VMs"}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwFileVersion {
	# return detailed VersionInfo, ex: C:\WINDOWS\system32\wbem\wbemcore.dll,10.0.17763.1999,20210608 20:32:26,Microsoft Corporation,Windows Management Instrumentation
	param(
	  [string] $FilePath
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "[FwFileVersion] Getting file version of $FilePath"
	if (Test-Path -Path $FilePath) {
		Try{
			$fileobj = Get-item $FilePath -ErrorAction Stop
			$filever = $fileobj.VersionInfo.FileMajorPart.ToString() + "." + $fileobj.VersionInfo.FileMinorPart.ToString() + "." + $fileobj.VersionInfo.FileBuildPart.ToString() + "." + $fileobj.VersionInfo.FilePrivatepart.ToString()
			$FilePath + "," + $filever + "," + $fileobj.CreationTime.ToString("yyyyMMdd HH:mm:ss") + "," + $fileobj.VersionInfo.CompanyName + "," + $fileobj.VersionInfo.FileDescription
		}Catch{
			# Do nothing
		}
	}Else{
		LogDebug ("[FwFileVersion] $FilePath not found.")
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportFileVerToCsv {
	# return detailed VersionInfo, ex: "C:\WINDOWS\SysWOW64\win32k.sys","10.0.17763.1 (WinBuild.160101.0800)","9/15/2018 9:13:04 AM","320000","Microsoft Corporation","Full/Desktop Multi-User Win32 Driver"
	param(
		[string] $WindirSubFolder,
		[string[]] $FileExts,			# List of one or more file extensions
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if ([string]::IsNullOrEmpty($Subfolder)) { $PrefixOut = $prefixCn } else { $PrefixOut = $global:LogFolder + "\" + $Subfolder + "\" + $Env:Computername + "_"}
	ForEach($FileExt in $FileExts){
		LogDebug "[FwExportFileVerToCsv] Getting file version of $Env:Windir\$WindirSubFolder\*.$FileExt"
		Get-ChildItem -Path ($Env:Windir + "\" + $WindirSubFolder) -Filter *.$FileExt -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
			[pscustomobject]@{
				Name = $_.FullName;
				Version = $_.VersionInfo.FileVersion;
				DateModified = $_.LastWriteTime;
				Length = $_.length;
				CompanyName = $_.VersionInfo.CompanyName;
				FileDescription = $_.VersionInfo.FileDescription;
			}
		} | export-csv -notypeinformation -path "$($PrefixOut + "FileVersions_" + $WindirSubFolder + "_" + $FileExt + ".csv")"
		LogInfoFile "[FwExportFileVerToCsv] ... finished for $WindirSubFolder\*.$FileExt"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

# This function disables quick edit mode. If the mode is enabled, 
#  console output would hang when key input or strings are selected. 
# So disable the quick edit mode during running script and re-enable it after script is finished.
$QuickEditCode=@"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Runtime.InteropServices;


public static class DisableConsoleQuickEdit
{

	const uint ENABLE_QUICK_EDIT = 0x0040;

	// STD_INPUT_HANDLE (DWORD): -10 is the standard input device.
	const int STD_INPUT_HANDLE = -10;

	[DllImport("kernel32.dll", SetLastError = true)]
	static extern IntPtr GetStdHandle(int nStdHandle);

	[DllImport("kernel32.dll")]
	static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

	[DllImport("kernel32.dll")]
	static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

	public static bool SetQuickEdit(bool SetEnabled)
	{

		IntPtr consoleHandle = GetStdHandle(STD_INPUT_HANDLE);

		// get current console mode
		uint consoleMode;
		if (!GetConsoleMode(consoleHandle, out consoleMode))
		{
			// ERROR: Unable to get console mode.
			return false;
		}

		// Clear the quick edit bit in the mode flags
		if (SetEnabled)
		{
			consoleMode &= ~ENABLE_QUICK_EDIT;
		}
		else
		{
			consoleMode |= ENABLE_QUICK_EDIT;
		}

		// set the new mode
		if (!SetConsoleMode(consoleHandle, consoleMode))
		{
			// ERROR: Unable to set console mode
			return false;
		}

		return true;
	}
}
"@
Try{
	$QuickEditMode = add-type -TypeDefinition $QuickEditCode -Language CSharp -ErrorAction Stop
	# Keep disabled when DebugMode for better debugging.
	If(!$DebugMode.IsPresent){
		$fQuickEditCodeExist = $True
	}
}Catch{
	$fQuickEditCodeExist = $False
}

$FindServicePIDCode=@'
using System;
using System.ServiceProcess;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;

namespace MSDATA {
  public static class FindService {

	public static void Main(){
	  //Console.WriteLine("Hello world!");
	}

	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
	public struct SERVICE_STATUS_PROCESS {
	  public int serviceType;
	  public int currentState;
	  public int controlsAccepted;
	  public int win32ExitCode;
	  public int serviceSpecificExitCode;
	  public int checkPoint;
	  public int waitHint;
	  public int processID;
	  public int serviceFlags;
	}

	[DllImport("advapi32.dll")]
	public static extern bool QueryServiceStatusEx(IntPtr serviceHandle, int infoLevel, IntPtr buffer, int bufferSize, out int bytesNeeded);

	public static int FindServicePid(string SvcName) {
	  //Console.WriteLine("Hello world!");
	  ServiceController sc = new ServiceController(SvcName);
	  if (sc == null) {
		return -1;
	  }
				  
	  IntPtr zero = IntPtr.Zero;
	  int SC_STATUS_PROCESS_INFO = 0;
	  int ERROR_INSUFFICIENT_BUFFER = 0;

	  Int32 dwBytesNeeded;
	  System.IntPtr hs = sc.ServiceHandle.DangerousGetHandle();

	  // Call once to figure the size of the output buffer.
	  QueryServiceStatusEx(hs, SC_STATUS_PROCESS_INFO, zero, 0, out dwBytesNeeded);
	  if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER) {
		// Allocate required buffer and call again.
		zero = Marshal.AllocHGlobal((int)dwBytesNeeded);

		if (QueryServiceStatusEx(hs, SC_STATUS_PROCESS_INFO, zero, dwBytesNeeded, out dwBytesNeeded)) {
		  SERVICE_STATUS_PROCESS ssp = (SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(zero, typeof(SERVICE_STATUS_PROCESS));
		  return (int)ssp.processID;
		}
	  }
	  return -1;
	}
  }
}
'@

Try{
	$FindServiceObject = 'MSDATA.FindService' -as [type]
	If($FindServiceObject -eq $Null){
		If($Host.Version.Major -ge 7){
			add-type -TypeDefinition $FindServicePIDCode -Language CSharp -ReferencedAssemblies 'System.ServiceProcess.ServiceController','netstandard','System.ComponentModel.Primitives' -ErrorAction Stop
		}Else{
			add-type -TypeDefinition $FindServicePIDCode -Language CSharp -ReferencedAssemblies 'System.ServiceProcess' -ErrorAction Stop
		}
	}
}Catch [System.InvalidOperationException]{
	#LogInfo "InvalidOperationException happened in Add-Type for FindServicePID but this is ignorable and continue."
}Catch{
	$_
	LogInfo "Unable to add C# code for finding service PID" "Magenta"
}

Function global:FindServicePid {
	Param(
		[String]$SvcName
	)

	Try{
		$pidsvc = [MSDATA.FindService]::FindServicePid($SvcName)
		LogInfo "[FindServicePid] Found PID for $SvcName(PID:$pidsvc)."
		Return $pidsvc
	}Catch{
		LogException "Error happened in FindServicePid()." $_ $fLogFileOnly
	}

	# Fall back to WMI way.
	LogInfo "[FindServicePid] Searching PID for $SvcName using WMI."
	$Service = Get-CimInstance -Class win32_service -ErrorAction Ignore | Where-Object {$_.Name -eq $SvcName}
	If($Service -eq $Null){
		LogError "Unable to find PID for $SvcName. Check if the service is running."
		Return $null
	}Else{
		Return $Service.ProcessID
	}
}

$UserDumpCode=@'
using System;
using System.Runtime.InteropServices;

namespace MSDATA
{
	public static class UserDump
	{
		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessID);
		[DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
		public static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

		private enum MINIDUMP_TYPE
		{
			MiniDumpNormal = 0x00000000,
			MiniDumpWithDataSegs = 0x00000001,
			MiniDumpWithFullMemory = 0x00000002,
			MiniDumpWithHandleData = 0x00000004,
			MiniDumpFilterMemory = 0x00000008,
			MiniDumpScanMemory = 0x00000010,
			MiniDumpWithUnloadedModules = 0x00000020,
			MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
			MiniDumpFilterModulePaths = 0x00000080,
			MiniDumpWithProcessThreadData = 0x00000100,
			MiniDumpWithPrivateReadWriteMemory = 0x00000200,
			MiniDumpWithoutOptionalData = 0x00000400,
			MiniDumpWithFullMemoryInfo = 0x00000800,
			MiniDumpWithThreadInfo = 0x00001000,
			MiniDumpWithCodeSegs = 0x00002000
		};

		public static bool GenerateUserDump(uint ProcessID, string dumpFileName)
		{
			System.IO.FileStream fileStream = System.IO.File.OpenWrite(dumpFileName);

			if (fileStream == null)
			{
				return false;
			}

			// 0x1F0FFF = PROCESS_ALL_ACCESS
			IntPtr ProcessHandle = OpenProcess(0x1F0FFF, false, ProcessID);

			if(ProcessHandle == null)
			{
				return false;
			}

			MINIDUMP_TYPE Flags =
				MINIDUMP_TYPE.MiniDumpWithFullMemory |
				MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo |
				MINIDUMP_TYPE.MiniDumpWithHandleData |
				MINIDUMP_TYPE.MiniDumpWithUnloadedModules |
				MINIDUMP_TYPE.MiniDumpWithThreadInfo;

			bool Result = MiniDumpWriteDump(ProcessHandle,
								 ProcessID,
								 fileStream.SafeFileHandle,
								 (uint)Flags,
								 IntPtr.Zero,
								 IntPtr.Zero,
								 IntPtr.Zero);

			fileStream.Close();
			return Result;
		}
	}
}
'@
Try{
	$UserDumpObject = 'MSDATA.UserDump' -as [type]
	If($UserDumpObject -eq $Null){
		add-type -TypeDefinition $UserDumpCode -Language CSharp
	}
}Catch{
	LogInfoFile "Unable to add C# code for collecting user dump."
}

Function global:FwCaptureUserDump{
	Param(
		[String] $Name,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $DumpFolder,
		[Bool] $IsService = $False,
		[long] $ProcPID
	)
	EnterFunc $MyInvocation.MyCommand.Name

	if (-not $global:ProcDump) {	#we# skip section if $global:ProcDump has een built at Start phase
		$global:ProcDump = "Procdump.exe"
		$ProcDumpCommand = Get-Command "Procdump.exe" -ErrorAction Ignore
	  if ($ProcDumpCommand -ne $Null) {
		  # For -Start, retrieve ProcDumpInterval from BoundParameters[] or config.cfg. For -Stop, $ProcDumpInterval are set in ReadParameterFromAutoLogReg().
		  If(!$Stop.IsPresent){
			  #$ProcDumpInterval = $global:BoundParameters['ProcDumpInterval']
			  If(!([string]::IsNullOrEmpty($global:BoundParameters['ProcDumpInterval']))){
					$ProcDumpInterval = $global:BoundParameters['ProcDumpInterval']
					LogDebug "[ProcDump] set ProcDumpInterval $global:ProcDumpInterval by CMDline"
			  }elseif (!([string]::IsNullOrEmpty($global:ProcDumpInterval))){
					LogDebug "[ProcDump] set ProcDumpInterval $global:ProcDumpInterval by config.cfg"
			  }else{
					LogDebug "[ProcDump] set default ProcDumpInterval $global:ProcDumpInterval by in FwCaptureUserDump"
			  }
			  LogDebug "[FwCaptureUserDump] ProcDumpInterval (N:sec): $global:ProcDumpInterval -global $global:ProcDumpInterval" "cyan"
		  }
		  If(($global:ProcDumpInterval -ne $Null) -or ($ProcDumpInterval -ne $Null)){
			  $Token = $ProcDumpInterval -split ":"
			  If($Token.Count -ne 2){
				  LogWarn "Invalid ProcDumpInterval($ProcDumpInterval) was passed."
			  }Else{
				  $script:NumDumps = $Token[0]
				  $script:DmpIntervalInSec = $Token[1]
				  $IntervalOption = "-s $script:DmpIntervalInSec -n $script:NumDumps"
				  LogInfoFile "[FwCaptureUserDump] [$global:TssPhase] ProcDump Interval in seconds: $script:DmpIntervalInSec - Number of dumps: $script:NumDumps - ProcDumpOption: $ProcDumpOption"
			  }
		  }
		  $global:ProcDump = "Procdump.exe $IntervalOption -accepteula -ma"
	  } else {
		$global:ProcDump = "Missing"
		LogWarn ("The ProcDump tool is not available'.")
	  }
	}

	if ($ProcPID) {
		$IsService = $false
		$ProcessObject = Get-Process -Id $ProcPID -ErrorAction Ignore
		If($ProcessObject -eq $Null){
			LogError "Unable to find the process with PID $ProcPID"
			Return
		}
	} else {
		If($IsService){
			Try{
				$PIDSvc = FindServicePid $Name
				If(-not $PIDSvc) {
					LogWarn "Cannot find the PID for the process running the service $Name. The service may not be running or the name could be incorrect."
					Return
				}
				$ProcessObject = Get-Process -Id $PIDSvc -ErrorAction Stop
			}Catch{
				LogError "An error happened during getting PID for `'$Name`' service."
				Return
			}
		}Else{
			Try{
				$Name = $Name -replace "\.exe",""
				$ProcessObject = Get-Process -Name $Name -ErrorAction Stop
			}Catch{
				LogError "The process $Name.exe is not running."
				Return
			}
		}
	}

	ForEach($Proc in $ProcessObject){
		If($IsService){
			$DumpFileName = "$DumpFolder\$($Proc.ProcessName).exe_$($Name)$global:TssPhase.dmp"
			$Message = "[UserDump] [$global:TssPhase] Capturing $script:NumDumps user dump(s) for $($Proc.ProcessName) ($Name) service in intervals of $script:DmpIntervalInSec seconds at $ProcDumpOption"
		}Else{
			$DumpFileName = "$DumpFolder\$($Proc.ProcessName).exe_$($Proc.Id)$global:TssPhase.dmp"
			$Message = "[UserDump] [$global:TssPhase] Capturing $script:NumDumps user dump(s) for $($Proc.ProcessName).exe ($($Proc.Id)) in intervals of $script:DmpIntervalInSec seconds at $ProcDumpOption"
		}
		LogInfo $Message

		if ($global:ProcDump -ne "Missing") {
			$Command = "$global:ProcDump $($Proc.ID) `"$DumpFileName`""
			RunCommands "UserDump" $Command -ThrowException:$False -ShowMessage:$True
		} else {
			$Result = [MSDATA.UserDump]::GenerateUserDump($Proc.ID, $DumpFileName)
			If(!$Result){
				If($IsService){
					LogError ("Failed to capture process dump for $($Name) service")
				}Else{
					LogError ("Failed to capture process dump for $($Proc.ProcessName)")
				}
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExecWMIQuery {
	[OutputType([Object])]
	param(
		[string] $NameSpace,
		[string] $Query
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo ("[ExecWMIQuery] Executing query " + $Query)
	Try{
		if ($PSVersionTable.psversion.ToString() -ge "3.0") {
			$Obj = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Stop
		} else {
			$Obj = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Stop
		}
	}Catch{
		LogException ("An error happened during running $Query") $_ $fLogFileOnly
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $Obj
}

Function global:FwGetCertStore{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$Store
	)
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		LogInfo ("[Cert] Getting Cert:\LocalMachine\$Store")
		$certlist = Get-ChildItem ("Cert:\LocalMachine\$Store") -ErrorAction Stop
	}Catch{
		LogError ("An error happened during retriving $Store")
		Return
	}
	
	ForEach($cert in $certlist) {
		$EKU = ""
		ForEach($item in $cert.EnhancedKeyUsageList){
			if ($item.FriendlyName) {
				$EKU += $item.FriendlyName + " / "
			} else {
				$EKU += $item.ObjectId + " / "
			}
		}
		$row = $Global:tbcert.NewRow()
		
		ForEach($ext in $cert.Extensions){
			if ($ext.oid.value -eq "2.5.29.14") {
				$row.SubjectKeyIdentifier = $ext.SubjectKeyIdentifier.ToLower()
			}
			if (($ext.oid.value -eq "2.5.29.35") -or ($ext.oid.value -eq "2.5.29.1")) { 
				$asn = New-Object Security.Cryptography.AsnEncodedData ($ext.oid,$ext.RawData)
				$aki = $asn.Format($true).ToString().Replace(" ","")
				$aki = (($aki -split '\n')[0]).Replace("KeyID=","").Trim()
				$row.AuthorityKeyIdentifier = $aki
			}
		}
		if($EKU){
			$EKU = $eku.Substring(0, $eku.Length-3)
		}
		$row.Store = $store
		$row.Thumbprint = $cert.Thumbprint.ToLower()
		$row.Subject = $cert.Subject
		$row.Issuer = $cert.Issuer
		$row.NotAfter = $cert.NotAfter
		$row.EnhancedKeyUsage = $EKU
		$row.SerialNumber = $cert.SerialNumber.ToLower()
		$Global:tbcert.Rows.Add($row)
	}
	EndFunc $MyInvocation.MyCommand.Name
}

function global:FwInvokeUnicodeTool($ToolString) {
	# Switch output encoding to unicode and then back to the default for tools
	# that output to the command line as unicode.
	$oldEncoding = [console]::OutputEncoding
	[console]::OutputEncoding = [Text.Encoding]::Unicode
	iex $ToolString
	[console]::OutputEncoding = $oldEncoding
}

Function global:FwCleanUpandExit{
	CleanUpandExit
}

Function global:FwPlaySound{
	If($OSBuild -ge 9600 -and $global:ParameterArray -notcontains 'noSound'){
		LogDebug "Playing sound."
		rundll32.exe cmdext.dll,MessageBeepStub
	}
}

Function global:FwTest-TCPport{ # original name: Test-PSOnePort
  <#
      .SYNOPSIS
      Tests a network port on a remote computer

      .DESCRIPTION
      Tests whether a port on a remote computer is responding.

      .EXAMPLE
      FwTest-TCPport -ComputerName 127.0.0.1 -Port 4000 -Timeout 1000 
      Tests whether port 4000 on the local computer is responding, 
      and waits a maximum of 1000 milliseconds

      .EXAMPLE
      FwTest-TCPport -ComputerName 127.0.0.1 -Port 4000 -Timeout 1000 -Count 30 -Delay 2000
      Tests 30 times whether port 4000 on the local computer is responding, 
      and waits a maximum of 1000 milliseconds inbetween each test

      .EXAMPLE
      FwTest-TCPport -ComputerName 127.0.0.1 -Port 4000 -Timeout 1000 -Count 0 -Delay 2000 -ExitOnSuccess
      Continuously tests whether port 4000 on the local computer is responding, 
      waits a maximum of 1000 milliseconds inbetween each test, 
      and exits as soon as the port is responding

      .LINK
      https://powershell.one/tricks/network/porttest
  #>
  param
  (
    [Parameter(Mandatory=$True)]
    [string]$ComputerName,
    # port number to test
    [Parameter(Mandatory=$True)]
    [int]$Port,
    # timeout in milliseconds
    [int]$Timeout = 500,
    # number of tries. A value of 0 indicates countinuous testing
    [int][ValidateRange(0,1000)]
    $Count = 1,
    # delay (in milliseconds) inbetween continuous tests
    $Delay = 2000,
    # when enabled, function returns as soon as port is available
    [Switch]$ExitOnSuccess
  )
  EnterFunc $MyInvocation.MyCommand.Name
  $ok = $false
  $c = 0
  $isOnline = $false
  $continuous = $Count -eq 0 -or $Count -gt 1
  try
  {
    do
    {
      $c++
      if ($c -gt $Count -and !$continuous) { 
        # count exceeded
        break
      }
      $start = Get-Date
      $tcpobject = [system.Net.Sockets.TcpClient]::new()
      $connect = $tcpobject.BeginConnect($computername,$port,$null,$null) 
      $wait = $connect.AsyncWaitHandle.WaitOne($timeout,$false) 
      if(!$wait) { 
        # no response from port
        $tcpobject.Close()
        $tcpobject.Dispose()
        Write-Verbose "Port $Port is not responding..."
        if ($continuous) { Write-Host '.' -NoNewline }
      } else { 
        try { 
          # port is reachable
          if ($continuous) { Write-Host '!' -NoNewline }
          [void]$tcpobject.EndConnect($connect)
          $tcpobject.Close()
          $tcpobject.Dispose()
          $isOnline = $true
          if ($ExitOnSuccess)
          {
            $ok = $true
            $delay = 0
          }
        }
        catch { 
          # access to port restricted
          throw "You do not have permission to contact port $Port."
        } 
      } 
      $stop = Get-Date
      $timeUsed = ($stop - $start).TotalMilliseconds
      $currentDelay = $Delay - $timeUsed
      if ($currentDelay -gt 100)
      {
        Start-Sleep -Milliseconds $currentDelay
      }
    } until ($ok)
  }
  finally
  {
    # dispose objects to free memory
    if ($tcpobject)
    {
      $tcpobject.Close()
      $tcpobject.Dispose()
    }
  }
  if ($continuous) { Write-Host }
  EndFunc ($MyInvocation.MyCommand.Name + "($isOnline)")
  return $isOnline
}

Function global:FwTestConnWebSite{
	# Purpose: check internet connectivity to WebSite
	# Results: True = machine has internet connectivity, False = no internet connectivity
		#_#$checkConn = Test-NetConnection -ComputerName $WebSite -CommonTCPPort HTTP -InformationLevel "Quiet"
	param
	(
		[string]$WebSite = "cesdiagtools.blob.core.windows.net"
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$checkConn =$False
	if ($WebSite) {
		try {
			$checkConn = FwTest-TCPport -ComputerName $WebSite -Port 80 -Timeout 900 
			}
        catch { LogError "[FwTestConnWebSite] WebSite to test is: $WebSite - checkConn: $checkConn"}
	} else { LogError "[FwTestConnWebSite] WebSite to test is: NULL "}
	EndFunc ($MyInvocation.MyCommand.Name + "($checkConn)")
	return $checkConn
}

Function global:FwAuditPolSet {
	param
	(
		[Parameter(Mandatory=$True)]
		[string]$AuditComponent,		# i.e. "Firewall"
		[Parameter(Mandatory=$True)]
		[string[]]$AuditSettingsList	# Example: @('"Filtering Platform Packet Drop","Filtering Platform Connection"') # for GUIDS see adtapi.h
	)
	EnterFunc $MyInvocation.MyCommand.Name
	#Note1: use /r to get a csv-formatted table: AuditPol /get /category:* /r | ConvertFrom-Csv | Format-Table 'Policy Target',Subcategory,'Inclusion Setting'
	#Note2: auditing categories are localized. On non-English systems the command using "names" fails, so lets use GUIDs in $AuditSettingsList
	LogInfofile "[$($MyInvocation.MyCommand.Name)] Backup current AuditPol settings to $PrefixCn`AuditPol_backup.csv"
	$Commands = @("AuditPol /backup /file:$PrefixCn`AuditPol_backup.csv")
	LogInfo "[$($MyInvocation.MyCommand.Name)] Enabling $AuditComponent related Events in Security Eventlog via AuditPol.exe"
	$Commands += @(
		"AuditPol.exe /get /category:* | Out-File -Append $global:LogFolder\$($LogPrefix)AuditPol$TssPhase.txt"
		"AuditPol.exe /set /SubCategory:$AuditSettingsList  /success:enable /failure:enable"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}
Function global:FwAuditPolUnSet {
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] Restoring original AuditPol settings from $PrefixCn`AuditPol_backup.csv"
	$Commands = @(
		"AuditPol.exe /restore /file:$PrefixCn`AuditPol_backup.csv"
		"AuditPol.exe /get /category:* | Out-File -Append $global:LogFolder\$($LogPrefix)AuditPol$TssPhase.txt"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwCopyMemoryDump {
	param
	(
		[Int]$DaysBack = 0
	)	
	EnterFunc "$($MyInvocation.MyCommand.Name) - DaysBack=$DaysBack"
	$SystemDumpFileName = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\CrashControl" -ErrorAction Ignore).DumpFile
	If($Null -eq $SystemDumpFileName){
		LogInfo "[FwCopyMemoryDump] `'DumpFile`' does not exist in `'HKLM:\System\CurrentControlSet\Control\CrashControl`'."
		Return
	}

	If(!(Test-Path -Path $SystemDumpFileName)){
		LogInfo "[FwCopyMemoryDump] `'$SystemDumpFileName`' does not exist."
		Return
	}

	$DumpFile = Get-Item $SystemDumpFileName
	If($DaysBack -ne 0){
		$TimeSpan = (Get-Date) - ($DumpFile.LastWriteTime)  # Current time - LastWriteTime
		LogDebug "DumpFile=$SystemDumpFileName TimeSpanDays=$($TimeSpan.Days) DaysBack=$DaysBack"
		If($TimeSpan.Days -gt $DaysBack){
			LogInfo "[FwCopyMemoryDump] Found `'$SystemDumpFileName`' but the last write time of the file is more than $DaysBack days ago($($TimeSpan.Days)). Skipping copying the file."
			Return
		}
	}

	$DumpFileSize = ($DumpFile.Length / 1GB).ToString("0.0")
	$Answer = FwRead-Host-YN -Message "Found memory dump($SystemDumpFileName with $($DumpFileSize)GB). Do you want to copy it to log folder? (timeout=10s)" -Choices "yn" -Timeout 10 -Default 'y'
	If($Answer){
		Try{
			LogInfo "Copying $SystemDumpFileName to $global:LogFolder"
			Copy-Item $SystemDumpFileName $global:LogFolder -ErrorAction Stop
		}Catch{
			LogError "Failed to copy memory.dmp. See $global:ErrorLogFile for detail."
			LogExceptionFile "Failed to copy memory.dmp to log folder." $_
		}
	} else { LogInfoFile "=== User declined to copy Memory.dmp to log folder ==="}
	EndFunc $MyInvocation.MyCommand.Name
}

#endregion common functions used by POD module

#region script functions

#region Common utilities
[void][System.Reflection.Assembly]::Load('System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
[void][System.Reflection.Assembly]::Load('System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')

function global:ShowEULAPopup($mode)
{
	$EULA = New-Object -TypeName System.Windows.Forms.Form
	$richTextBox1 = New-Object System.Windows.Forms.RichTextBox
	$btnAcknowledge = New-Object System.Windows.Forms.Button
	$btnCancel = New-Object System.Windows.Forms.Button

	$EULA.SuspendLayout()
	$EULA.Name = "EULA"
	$EULA.Text = "Microsoft Diagnostic Tools End User License Agreement"

	$richTextBox1.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
	$richTextBox1.Location = New-Object System.Drawing.Point(12,12)
	$richTextBox1.Name = "richTextBox1"
	$richTextBox1.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
	$richTextBox1.Size = New-Object System.Drawing.Size(776, 397)
	$richTextBox1.TabIndex = 0
	$richTextBox1.ReadOnly=$True
	$richTextBox1.Add_LinkClicked({Start-Process -FilePath $_.LinkText})
	$richTextBox1.Rtf = @"
{\rtf1\ansi\ansicpg1252\deff0\nouicompat{\fonttbl{\f0\fswiss\fprq2\fcharset0 Segoe UI;}{\f1\fnil\fcharset0 Calibri;}{\f2\fnil\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue255;}
{\*\generator Riched20 10.0.19041}{\*\mmathPr\mdispDef1\mwrapIndent1440 }\viewkind4\uc1 
\pard\widctlpar\f0\fs19\lang1033 MICROSOFT SOFTWARE LICENSE TERMS\par
Microsoft Diagnostic Scripts and Utilities\par
\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}These license terms are an agreement between you and Microsoft Corporation (or one of its affiliates). IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE RIGHTS BELOW. BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.\par
{\pict{\*\picprop}\wmetafile8\picw26\pich26\picwgoal32000\pichgoal15 
0100090000035000000000002700000000000400000003010800050000000b0200000000050000
000c0202000200030000001e000400000007010400040000000701040027000000410b2000cc00
010001000000000001000100000000002800000001000000010000000100010000000000000000
000000000000000000000000000000000000000000ffffff00000000ff040000002701ffff0300
00000000
}\par
\pard 
{\pntext\f0 1.\tab}{\*\pn\pnlvlbody\pnf0\pnindent0\pnstart1\pndec{\pntxta.}}
\fi-360\li360 INSTALLATION AND USE RIGHTS. Subject to the terms and restrictions set forth in this license, Microsoft Corporation (\ldblquote Microsoft\rdblquote ) grants you (\ldblquote Customer\rdblquote  or \ldblquote you\rdblquote ) a non-exclusive, non-assignable, fully paid-up license to use and reproduce the script or utility provided under this license (the "Software"), solely for Customer\rquote s internal business purposes, to help Microsoft troubleshoot issues with one or more Microsoft products, provided that such license to the Software does not include any rights to other Microsoft technologies (such as products or services). \ldblquote Use\rdblquote  means to copy, install, execute, access, display, run or otherwise interact with the Software. \par
\pard\widctlpar\par
\pard\widctlpar\li360 You may not sublicense the Software or any use of it through distribution, network access, or otherwise. Microsoft reserves all other rights not expressly granted herein, whether by implication, estoppel or otherwise. You may not reverse engineer, decompile or disassemble the Software, or otherwise attempt to derive the source code for the Software, except and to the extent required by third party licensing terms governing use of certain open source components that may be included in the Software, or remove, minimize, block, or modify any notices of Microsoft or its suppliers in the Software. Neither you nor your representatives may use the Software provided hereunder: (i) in a way prohibited by law, regulation, governmental order or decree; (ii) to violate the rights of others; (iii) to try to gain unauthorized access to or disrupt any service, device, data, account or network; (iv) to distribute spam or malware; (v) in a way that could harm Microsoft\rquote s IT systems or impair anyone else\rquote s use of them; (vi) in any application or situation where use of the Software could lead to the death or serious bodily injury of any person, or to physical or environmental damage; or (vii) to assist, encourage or enable anyone to do any of the above.\par
\par
\pard\widctlpar\fi-360\li360 2.\tab DATA. Customer owns all rights to data that it may elect to share with Microsoft through using the Software. You can learn more about data collection and use in the help documentation and the privacy statement at {{\field{\*\fldinst{HYPERLINK https://aka.ms/privacy }}{\fldrslt{https://aka.ms/privacy\ul0\cf0}}}}\f0\fs19 . Your use of the Software operates as your consent to these practices.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 3.\tab FEEDBACK. If you give feedback about the Software to Microsoft, you grant to Microsoft, without charge, the right to use, share and commercialize your feedback in any way and for any purpose.\~ You will not provide any feedback that is subject to a license that would require Microsoft to license its software or documentation to third parties due to Microsoft including your feedback in such software or documentation. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 4.\tab EXPORT RESTRICTIONS. Customer must comply with all domestic and international export laws and regulations that apply to the Software, which include restrictions on destinations, end users, and end use. For further information on export restrictions, visit {{\field{\*\fldinst{HYPERLINK https://aka.ms/exporting }}{\fldrslt{https://aka.ms/exporting\ul0\cf0}}}}\f0\fs19 .\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 5.\tab REPRESENTATIONS AND WARRANTIES. Customer will comply with all applicable laws under this agreement, including in the delivery and use of all data. Customer or a designee agreeing to these terms on behalf of an entity represents and warrants that it (i) has the full power and authority to enter into and perform its obligations under this agreement, (ii) has full power and authority to bind its affiliates or organization to the terms of this agreement, and (iii) will secure the permission of the other party prior to providing any source code in a manner that would subject the other party\rquote s intellectual property to any other license terms or require the other party to distribute source code to any of its technologies.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360\qj 6.\tab DISCLAIMER OF WARRANTY. THE SOFTWARE IS PROVIDED \ldblquote AS IS,\rdblquote  WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL MICROSOFT OR ITS LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\par
\pard\widctlpar\qj\par
\pard\widctlpar\fi-360\li360\qj 7.\tab LIMITATION ON AND EXCLUSION OF DAMAGES. IF YOU HAVE ANY BASIS FOR RECOVERING DAMAGES DESPITE THE PRECEDING DISCLAIMER OF WARRANTY, YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT, OR INCIDENTAL DAMAGES. This limitation applies to (i) anything related to the Software, services, content (including code) on third party Internet sites, or third party applications; and (ii) claims for breach of contract, warranty, guarantee, or condition; strict liability, negligence, or other tort; or any other claim; in each case to the extent permitted by applicable law. It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your state, province, or country may not allow the exclusion or limitation of incidental, consequential, or other damages.\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 8.\tab BINDING ARBITRATION AND CLASS ACTION WAIVER. This section applies if you live in (or, if a business, your principal place of business is in) the United States.  If you and Microsoft have a dispute, you and Microsoft agree to try for 60 days to resolve it informally. If you and Microsoft can\rquote t, you and Microsoft agree to binding individual arbitration before the American Arbitration Association under the Federal Arbitration Act (\ldblquote FAA\rdblquote ), and not to sue in court in front of a judge or jury. Instead, a neutral arbitrator will decide. Class action lawsuits, class-wide arbitrations, private attorney-general actions, and any other proceeding where someone acts in a representative capacity are not allowed; nor is combining individual proceedings without the consent of all parties. The complete Arbitration Agreement contains more terms and is at {{\field{\*\fldinst{HYPERLINK https://aka.ms/arb-agreement-4 }}{\fldrslt{https://aka.ms/arb-agreement-4\ul0\cf0}}}}\f0\fs19 . You and Microsoft agree to these terms. \par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 9.\tab LAW AND VENUE. If U.S. federal jurisdiction exists, you and Microsoft consent to exclusive jurisdiction and venue in the federal court in King County, Washington for all disputes heard in court (excluding arbitration). If not, you and Microsoft consent to exclusive jurisdiction and venue in the Superior Court of King County, Washington for all disputes heard in court (excluding arbitration).\par
\pard\widctlpar\par
\pard\widctlpar\fi-360\li360 10.\tab ENTIRE AGREEMENT. This agreement, and any other terms Microsoft may provide for supplements, updates, or third-party applications, is the entire agreement for the software.\par
\pard\sa200\sl276\slmult1\f1\fs22\lang9\par
\pard\f2\fs17\lang2057\par
}
"@
	$richTextBox1.BackColor = [System.Drawing.Color]::White
	$btnAcknowledge.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
	$btnAcknowledge.Location = New-Object System.Drawing.Point(544, 415)
	$btnAcknowledge.Name = "btnAcknowledge";
	$btnAcknowledge.Size = New-Object System.Drawing.Size(119, 23)
	$btnAcknowledge.TabIndex = 1
	$btnAcknowledge.Text = "Accept"
	$btnAcknowledge.UseVisualStyleBackColor = $True
	$btnAcknowledge.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::Yes})

	$btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
	$btnCancel.Location = New-Object System.Drawing.Point(669, 415)
	$btnCancel.Name = "btnCancel"
	$btnCancel.Size = New-Object System.Drawing.Size(119, 23)
	$btnCancel.TabIndex = 2
	if($mode -ne 0)
	{
		$btnCancel.Text = "Close"
	}
	else
	{
		$btnCancel.Text = "Decline"
	}
	$btnCancel.UseVisualStyleBackColor = $True
	$btnCancel.Add_Click({$EULA.DialogResult=[System.Windows.Forms.DialogResult]::No})

	$EULA.AutoScaleDimensions = New-Object System.Drawing.SizeF(6.0, 13.0)
	$EULA.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
	$EULA.ClientSize = New-Object System.Drawing.Size(800, 450)
	$EULA.Controls.Add($btnCancel)
	$EULA.Controls.Add($richTextBox1)
	if($mode -ne 0)
	{
		$EULA.AcceptButton=$btnCancel
	}
	else
	{
		$EULA.Controls.Add($btnAcknowledge)
		$EULA.AcceptButton=$btnAcknowledge
		$EULA.CancelButton=$btnCancel
	}
	$EULA.ResumeLayout($false)
	$EULA.Size = New-Object System.Drawing.Size(800, 650)

	Return ($EULA.ShowDialog())
}

function global:ShowEULAIfNeeded($toolName, $mode)
{
	$eulaRegPath = "HKCU:Software\Microsoft\CESDiagnosticTools"
	$eulaAccepted = "No"
	$eulaValue = $toolName + " EULA Accepted"
	if(Test-Path $eulaRegPath)
	{
		$eulaRegKey = Get-Item $eulaRegPath
		$eulaAccepted = $eulaRegKey.GetValue($eulaValue, "No")
	}
	else
	{
		$eulaRegKey = New-Item $eulaRegPath
	}
	if($mode -eq 2) # silent accept
	{
		$eulaAccepted = "Yes"
	   		$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
	}
	else
	{
		if($eulaAccepted -eq "No")
		{
			$eulaAccepted = ShowEULAPopup($mode)
			if($eulaAccepted -eq [System.Windows.Forms.DialogResult]::Yes)
			{
					$eulaAccepted = "Yes"
					$ignore = New-ItemProperty -Path $eulaRegPath -Name $eulaValue -Value $eulaAccepted -PropertyType String -Force
			}
		}
	}
	return $eulaAccepted
}

Function InsertArrayIntoArray($Array, $insertAfter, $valueToInsert){  
	$index = 0
	$insertPoint = -1

	#find the index of value before insertion
	#ryhayash: IndexOf is not case sensitive. So change logic to get index.
	#$insertPoint = $Array.IndexOf($insertAfter)
	If($insertAfter -is [int]){
		$insertPoint = $insertAfter
	}Else{
		ForEach($Element in $Array){
			If($Element -eq $insertAfter){
				$insertPoint = $index
			}
			$index++
		}
	}

	If($insertPoint -lt 0){
		LogDebug "[$valueToInsert] Unable to find insert point for $insertAfter(InsertPoint=$insertPoint). Adding the parameter to the head of the array." "Red"
	}Else{
		LogDebug "[$valueToInsert] InsertPoint=$insertPoint($insertAfter)"
	}

	#split the array into two parts
	#slice into a new array
	$newArray = @()
	If($insertPoint -eq 0){
		$secondHalf = $Array
		foreach ($insert in $valueToInsert){
			$newArray+=$insert
		}
	}Else{
		$firstHalf = $Array[0..$insertPoint]
		$secondHalf = $Array[($insertPoint +1)..$Array.Length]
		foreach ($first in $firsthalf){
			$newArray+=$first
		}
	}
	If($insertPoint -ne 0){
		foreach ($insert in $valueToInsert){
			$newArray+=$insert
		}
	}
	foreach ($second in $secondHalf){
		$newArray+=$second
	}

	return $newArray
	#returning this new array means you can assign it over the old array
}

Function RemoveItemFromArray($Array, $Item){
	EnterFunc $MyInvocation.MyCommand.Name
	$newArray = @()

	ForEach($Element in $Array){
		If($Element -ne $Item){
			$newArray += $Element
		}Else{
			LogDebug "Removing $Item."
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
	return $newArray
}

Function SearchTTTracer{
	[OutputType([String])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$TTDFullPath = $Null
	$fFound = $False
	
	# First, seach path specified with '-TTDPath'
	$TTDPath = $global:BoundParameters['TTDPath']
	If(![string]::IsNullOrEmpty($TTDPath)){
		$TTDFullPath = Join-Path -Path $TTDPath "TTTracer.exe"
		If(!(Test-Path -path $TTDFullPath)){
			
			# Seach a bit more as TTDPath might have been specified with upper folder.
			$TTTracers = Get-ChildItem $TTDPath 'TTTracer.exe' -Recurse -ErrorAction Ignore
		
			If($Global:ProcArch -eq 'x64'){
			   $PathWithArch = ".*(amd64|x64)\\.*TTTracer.exe"
			}Else{
			   $PathWithArch = ".*x86\\.*TTTracer.exe"
			}
			
			ForEach($TTTracer in $TTTracers){
				If($TTTracer.FullName -like "*downlevel*" -or $TTTracer.FullName -like "*wow64*"){
					LogDebug "Skipping $($TTTracer.FullName)"
					Continue
				}
				If($TTTracer.FullName -match $PathWithArch){
					LogDebug "Use $($TTTracer.FullName)"
					$TTDFullPath = $TTTracer.FullName
					$Script:UsePartnerTTD = $True
					$fFound = $True
					Break
				}Else{
					LogDebug "Skipping $($TTTracer.FullName)"
					Continue
				}
			}
		}Else{
			$Script:UsePartnerTTD = $True
			$fFound = $True
		}
	}Else{ # Search TTD shipped with AutoLog. If not exist, try to search built-in TTD.
		If($Global:ProcArch -eq 'x64'){
			If($global:OSVersion.Build -le 9600){
				$TTDFullPath = Join-Path -Path ".\BINx64\downlevel" "TTTracer.exe"
			}Else{
				$TTDFullPath = Join-Path -Path ".\BINx64" "TTTracer.exe"  # !!! the relative path might need to be updated once partner package is included in AutoLog and actual TTD path is determined.
			}
		}ElseIf($Global:ProcArch -eq 'x86'){
			If($global:OSVersion.Build -le 9600){
				$TTDFullPath = Join-Path -Path ".\BINx86\downlevel" "TTTracer.exe"
			}Else{
				$TTDFullPath = Join-Path -Path ".\BINx86" "TTTracer.exe"
			}
		}
		If(Test-Path -path $TTDFullPath){
			$Script:UsePartnerTTD = $True
			$fFound = $True
		}Else{ # Search built-in TTD
			$BuiltInTTDPath = "C:\Windows\System32\TTTracer.exe"
			If(Test-Path -path $BuiltInTTDPath){
				$TTDFullPath = $BuiltInTTDPath
				$Script:UsePartnerTTD = $False
				$fFound = $True
			}Else{
				$fFound = $False
			}
		}
	}
	If(!$fFound){
		$TTDFullPath = $Null
	}
	LogDebug "TTD path = $TTDFullPath"
	EndFunc ($MyInvocation.MyCommand.Name + "($TTDFullPath)")
	Return $TTDFullPath
}

Function Close-Transcript{
	param(
	[Parameter(Mandatory=$False)]
	[switch]$ShowMsg=$False
	)
	Try{
		if ($ShowMsg) { LogInfo "[$($MyInvocation.MyCommand.Name)] Stopping transcript" }
		Stop-Transcript -ErrorAction Ignore | Out-Null
	}Catch{
		$Error.RemoveAt(0)
	}
}

Function CleanUpandExit{
	$CallStack = Get-PSCallStack
	$CallerInfo = $CallStack[1]
	If($CallerInfo.FunctionName -eq '<ScriptBlock>'){
		 $FuncName = 'Main'
	}Else{
		$FuncName = $CallerInfo.FunctionName
	}
	EnterFunc ("$($MyInvocation.MyCommand.Name)" + "(Caller - $($FuncName):$($CallerInfo.ScriptLineNumber))")

	# Removing temporary files and registried used in this script.
	If($TempCommandErrorFile -ne $Null -and (Test-Path -Path $TempCommandErrorFile)){
		Remove-Item $TempCommandErrorFile -Force | Out-Null
	}

	# Delete outstanding job
	$AutoLogJob = Get-Job -Name "AutoLog-*"
	If($AutoLogJob -ne $Null){
		$AutoLogJob | Remove-Job
	}

	# Restoring DisableRegistryTools to original value. We do this if original value is other than 0(regedit is disabled by administrator).
	If((IsStart) -or $Stop.IsPresent -or !([string]::IsNullOrEmpty($CollectLog)) -or !([string]::IsNullOrEmpty($StartDiag))){
		If($global:OriginalDisableRegistryTools -gt 0){
			LogInfo "Restoring `'DisableRegistryTools`' to $global:OriginalDisableRegistryTools"
			ToggleRegToolsVal $global:OriginalDisableRegistryTools
		}
	}

	# Restore Quick Edit mode
	If($fQuickEditCodeExist){
		[DisableConsoleQuickEdit]::SetQuickEdit($False) | Out-Null
	}

	# Stop TSS Clock if running
	If($Stop.IsPresent -or ((IsStart) -and !($StartNoWait.IsPresent))){
		StopAutoLogClock
	}

	# Stop console logging.
	Close-Transcript
	If($global:LogFolder -ne $Null -and ($Error.Count -ne 0 -and (Test-Path -Path $global:LogFolder))){
		$Error | Out-File -FilePath $global:ErrorVariableFile
	}
	EndFunc $MyInvocation.MyCommand.Name
	LogDebug "Exiting script..."
	Exit
}

Function ToggleRegToolsVal($TmpVal){
	EnterFunc $MyInvocation.MyCommand.Name
	$DisableRegistryTools = (Get-ItemProperty -ErrorAction Ignore -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System).DisableRegistryTools
	LogDebug "DisableRegistryTools is setting to $TmpVal from $DisableRegistryTools"
	Set-ItemProperty -ErrorAction Ignore -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableRegistryTools -Value $TmpVal
	EndFunc $MyInvocation.MyCommand.Name
}

Function GetETWSessionByLogman(){
	[OutputType([String[]])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name

	$ETWSessionList = logman -ets | Out-String
	$SessionCount = 0
	$RunningSessionList = @()
	$LineNumber = 0

	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$LineNumber++
		# Skip first 3 lines
		If($LineNumber -le 3){
			Continue
		}
		$TraceSessionName = ($Line -Split '\s+')[0]
		$TraceType = ($Line -Split '\s+')[1]
		# Skip line with null string, like '----*' and if first string is space(' ').
		If($TraceSessionName -eq ''){
			Continue
		}ElseIf($TraceSessionName -like '----*'){
			Continue
		}ElseIf($TraceSessionName.Substring(0,1) -eq ' '){
			Continue
		}

		# Also skip line that does not have 2nd token.
		If([string]::IsNullOrEmpty($TraceType)){
			Continue
		}
		$SessionCount++
		$RunningSessionList += $TraceSessionName
	}
	LogDebug "Returning $($RunningSessionList.Count) sessions."
	EndFunc $MyInvocation.MyCommand.Name
	Return $RunningSessionList
}

Function ConvertScenarioTraceNametoTraceName{
	[OutputType([String])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ScenarioTraceName
	)

	If(!($ScenarioTraceName.ToLower().Contains('scenario'))){
		Return $Null
	}

	$TraceName = $ScenarioTraceName -replace ".*Scenario_",""  # AutoLog_NET_BITSScenario_NET_BITSTrace => NET_BITSTrace
	$TraceName = $TraceName -replace "Trace$",""		  # NET_BITSTrace => NET_BITS
	LogDebug "Returning with $TraceName"
	Return $TraceName
}

Function HasScenarioCommandTypeTrace{
	[OutputType([Bool])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ScenarioName
	)
	
	# Load all properties with log type and create an array for the list of commands
	$CommandProperties = Get-Variable "*Property" -ValueOnly -ErrorAction Ignore | Where-Object {$_.LogType -eq "Command"}
	$Commandlist = @()
	ForEach($CommandProperty in $CommandProperties){
		$Commandlist += $CommandProperty.Name
	}
	$CommandList += 'NetshScenario'

	# See if the scenario has a trace with command type(WPR, Netsh, Perf, etc).
	$ScenarioDefinition = "$ScenarioName" + "_ETWTracingSwitchesStatus"
	$TracesInScenario = Get-Variable $ScenarioDefinition -ValueOnly -ErrorAction Ignore
	ForEach($Key in $TracesInScenario.Keys){
		$Command = ($Key -split ' ')[0]
		If($CommandList -contains $Command){
			LogDebug "$ScenarioName has $Command command."
			Return $True
		}
	}
	Return $False
}

Function IsStart{
	[OutputType([Bool])]

	$CallStack = Get-PSCallStack
	$CallerInfo = $CallStack[1]
	If($CallerInfo.FunctionName -eq '<ScriptBlock>'){
		 $FuncName = 'Main'
	}Else{
		$FuncName = $CallerInfo.FunctionName
	}
	EnterFunc ("$($MyInvocation.MyCommand.Name)" + "(Caller - $($FuncName):$($CallerInfo.ScriptLineNumber))")

	If($global:ParameterArray -eq $Null -or $global:ParameterArray.Count -eq 0){
		LogError "IsStart() was called but ParameterArray is not initialized yet."
		Return $False
	}

	$fStart = $False
	Switch($global:ParameterArray[0]){
		'start'{
			$fStart = $True
		}
		'StartAutoLogger'{
			$fStart = $True
		}
		'StartDiag'{}
		'stop'{}
		'RemoveAutoLogger'{}
		'set'{}
		'unset'{}
		'help'{}
		'TraceInfo'{}
		'Find'{}
		'FindGUID'{}
		'status'{}
		'CollectLog'{}
		'List'{}
		'ListSupportedCommands'{}
		'ListSupportedDiag'{}
		'ListSupportedLog'{}
		'ListSupportedNetshScenario'{}
		'ListSupportedNoOptions'{}
		'ListSupportedPerfCounter'{}
		'ListSupportedScenarioTrace'{}
		'ListSupportedSDP'{}
		'ListSupportedTrace'{}
		'ListSupportedWPRScenario'{}
		'ListSupportedXperfProfile'{}
		'Version'{}
		'update'{}
		'SDP'{}
		'Xray'{}
		default{
			$fStart = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fStart)")
	Return $fStart
}

Function IsTraceOrDataCollection{
	[OutputType([Bool])]
	$CallStack = Get-PSCallStack
	$CallerInfo = $CallStack[1]
	If($CallerInfo.FunctionName -eq '<ScriptBlock>'){
		 $FuncName = 'Main'
	}Else{
		$FuncName = $CallerInfo.FunctionName
	}
	EnterFunc ("$($MyInvocation.MyCommand.Name)" + "(Caller - $($FuncName):$($CallerInfo.ScriptLineNumber))")

	$Result = $False
	If($Null -eq $global:BoundParameters -or $global:BoundParameters.Count -eq 0){
		LogWarn "BoundParameters[] is not initialized yet."
		Return $False
	}

	$DataCollectionParameters = @(
		'Start',
		'StartAutoLogger',
		'StartDiag'
		'StartNoWait'
		'Stop'
		'CollectLog'
		'CollectEventLog'
		'SDP'
		'Xray'
		'RemoveAutoLogger'
	)
	ForEach($key in $global:BoundParameters.Keys){
		If($key -in $DataCollectionParameters){
			$Result = $True
			Break 
		}
	}
	LogDebug "Returning with $Result"
	EndFunc ($MyInvocation.MyCommand.Name + "($Result)")
	Return $Result
}

Function IsServerCore{
	[OutputType([Bool])]
	param()
	EnterFunc $MyInvocation.MyCommand.Name
	$IsServerCore = $False
	If(!(Test-Path -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Server")){
		Return $IsServerCore  # Early return as this is Client SKU.
	}

	$ServerCore = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels" -ErrorAction Ignore).ServerCore
	If($ServerCore -ne $Null -and $ServerCore -eq 1){
		$IsServerCore = $True
	}

	# Issue#374 - PSR report is not recorded on DC
	$ServerGuiShell = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels" -ErrorAction Ignore)."Server-Gui-Shell"
	If($ServerGuiShell -ne $Null -and $ServerGuiShell -eq 1){
		$IsServerCore = $False
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($IsServerCore)")
	Return $IsServerCore
}

Function SaveToAutoLogReg{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegValue,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object]$RegData
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If(!(Test-Path $global:AutoLogParamRegKey)){
		LogInfo "Saving all parameters to $global:AutoLogParamRegKey"
		RunCommands "SaveToAutoLogReg" "New-Item -Path `"$global:AutoLogParamRegKey`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
	}

	$AutoLogReg = Get-ItemProperty -Path  $global:AutoLogParamRegKey
	Switch ($RegData.GetType()){
		'int'{
			$PropertyType = "DWord"
		}
		'string[]'{
			$RegData = $RegData -join ','
			$PropertyType = "String"
		}
		'System.Object[]'{
			$RegData = $RegData -join ','
			$PropertyType = "String"
		}
		default{
			$PropertyType = "String"
		}
	}

	LogInfoFile "Saving $RegValue($RegData) type=$($RegData.GetType()) to $($global:AutoLogParamRegKey)"
	LogDebug "Saving -Name $RegValue -Value $RegData"
	If($AutoLogReg.$RegValue -ne $Null){ # Overwrite the value
		Set-ItemProperty -Path $global:AutoLogParamRegKey -Name $RegValue -Value $RegData
	}Else{
		New-ItemProperty -Path $global:AutoLogParamRegKey -Name $RegValue -Value $RegData -PropertyType $PropertyType | Out-Null
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwRead-Host-YN{
	<#
	.SYNOPSIS
	 Displays message and reads user input (y or n) from console.
	.DESCRIPTION
	 Reads input from console using choice.exe if script runs on PowerShell or command prompt. In case of ISE, use Read-Host to read user input as ISE does not support interactive command(choice.exe).
	.EXAMPLE
	 1) FwRead-Host-YN -Message "Test messages" # Ask yes/no question without timeout
	 2) FwRead-Host-YN -Message "Test messages" -Timeout 10				 # Ask yes/no question with 10 second timeout
	 3) FwRead-Host-YN -Message "Test messages" -Choices "y"				# Request to input 'y' without timeout
	 4) FwRead-Host-YN -Message "Test messages" -Choices "yn"			   # Same as 1). Ask yes/no question without timeout
	 5) FwRead-Host-YN -Message "Test messages" -Choices "yn" -Timeout 10   # Same as 2). Ask yes/no question with 10 second timeout
	.PARAMETER Message
	 Mandatory option. String message that is displayed.
	.PARAMETER Choices
	 Optional parameter. Currently only 'yn' or 'y' is supported(default is 'yn'). For 'yn', user will be asked yes/no question. For 'y', requests user to input only 'y'.
	.PARAMETER Timeout
	 Optional parameter. Time out value in seconds. By default, there is no timeout and wait for user input permanently.
	 NOTE: This works only if script runs on PowerShell or command prompt. In case of ISE, -Timeout is simply ignored and does not work as ISE does not support choice.exe and Read-Host that does not have timeout feature is used.
	#>
	[OutputType([Bool])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message,
		[ValidateNotNullOrEmpty()]
		[ValidateSet("y","yn")] # Currently only 'y' and 'yn' are supported.
		[String]$Choices="yn",
		[Int]$TimeOut=0,
		[String]$Default="y"
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$Answer = $True
	If($global:IsISE){ # In case of ISE, use Read-Host
		If($Choices -eq "yn"){
			$Message = $Message + " [Y/N]"
		}ElseIf($Choices -eq "y"){
			$Message = $Message + " [Y]"
		}
		$Input = Read-Host $Message
		If(![String]::IsNullOrEmpty($Input) -and $Input.Substring(0,1) -eq 'n'){
			$Answer = $False
		}ElseIf([String]::IsNullOrEmpty($Input)){
			LogInfo "RETURN key entered. Take it as 'yes'."
		}
	}Else{
		$Argument = "/C $Choices /M `"$Message`""
		If($TimeOut -gt 0){
			$Argument = $Argument + " /T $TimeOut /D " + $Default
		}
		$Proc = Start-Process -FilePath "Choice" -ArgumentList $Argument -PassThru -Wait -NoNewWindow
		If($Proc.ExitCode -eq 2) { # 'n' case
			$Answer = $False
			#LogInfoFile "[User provided answer:] $Answer"
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($Answer)")
	Return $Answer
}

Function global:FwDisplayPopUp{
	<#
	.SYNOPSIS
	  Displays a notification popup window for N seconds
	.DESCRIPTION
	  Function will display a PopUp window with [OK] button for duration of N seconds with title "AutoLog PowerShell ..." and closes after N seconds, then AutoLog script continues and requests input from user
	.EXAMPLE
	  FwDisplayPopUp 5 "[Topic is DFS]"
	#>
	Param(
		[parameter(Mandatory=$false)]
		[int]$Timer = 30,	# default time to display PopUp
		[parameter(Mandatory=$false)]
		[String]$Topic
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$newobject = New-Object -ComObject Wscript.Shell
	#ToDo: place window .TopMost = $true
	$PopUpWin = $newobject.popup("$Topic - Click OK and then Please answer TSS question ",$Timer ," AutoLog PowerShell window has a question for you! ($Timer sec display) ",0)
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwWaitForProcess{
	<#
	.SYNOPSIS
	  Wait for a background process to complete and terminate process if Timeout (in seconds) expired
	.DESCRIPTION
	  Wait for a background process to complete and terminate process if Timeout (in seconds) expired
	  i.e. msinfo32.exe is a background process 
	  FwWaitForProcess expects 2 parameters:
	   P1 is process object that had been started i.e. with "$myNotepad = Start-Process -FilePath 'notepad' -PassThru"
	   P2 is the timeout in seconds 
	.EXAMPLE
	  FwWaitForProcess $myNotepad 60
	#>
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object]$ProcObj,		# background process
		[parameter(Mandatory=$true)]
		[int]$pTimeout			# timeout in seconds
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($ProcObj -ne $Null){
		$TargetProc = Get-Process -Id $ProcObj.Id -ErrorAction SilentlyContinue
		If($TargetProc -ne $Null){
			Try{
				Loginfo "[FwWaitForProcess] Waiting $pTimeout seconds for $($ProcObj.Name) with ID $($ProcObj.Id) to be completed."
				Wait-Process -id $ProcObj.Id -Timeout $pTimeout -ErrorAction Stop
			}Catch{
				Loginfo "[FwWaitForProcess] $($ProcObj.Name) is running more than $pTimeout seconds, so stopping the process." "Magenta"
				$TargetProc.kill()
			}
		}
	}else{ LogInfoFile "[FwWaitForProcess] missing parameter for process object"}
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion common functions used by POD module

Function DisplayDataUploadRequestInError{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Message
	)
	$CallStack = Get-PSCallStack
	$CallerInfo = $CallStack[1]
	If($CallerInfo.FunctionName -eq '<ScriptBlock>'){
		 $FuncName = 'Main'
	}Else{
		$FuncName = $CallerInfo.FunctionName
	}
	EnterFunc ("$($MyInvocation.MyCommand.Name)" + "(Caller - $($FuncName):$($CallerInfo.ScriptLineNumber))")
	LogInfo "ERROR: $Message" "Red"
	LogInfo "==> Please send below log files to our upload site." "Cyan"
	LogInfo "    - All log files in $global:LogFolder" "Yellow"
	LogInfo "    - $global:TranscriptLogFile" "Yellow"
	LogInfo "    - $global:ErrorLogFile" "Yellow"
	EndFunc $MyInvocation.MyCommand.Name
}

Function IsLiteMode{
	[OutputType([Bool])]
	$NumExecutable = (Get-ChildItem "$global:ScriptFolder\BIN\" -Name "*.exe" -ErrorAction Ignore).count 
	$NumExecutable += (Get-ChildItem "$global:ScriptFolder\BINx86\" -Name "*.exe" -ErrorAction Ignore).count
	$NumExecutable += (Get-ChildItem "$global:ScriptFolder\BINx64\" -Name "*.exe" -ErrorAction Ignore).count
	LogDebug "The number of executables in \BIN*\ folders is $NumExecutable"
	#LogInfo "The number of executables in \BIN*\ folders is $NumExecutable"
	#_#If($NumExecutable -lt 20){
	If($NumExecutable -lt 30){
		Return $True
	}Else{
		Return $False
	}
}

Function IsRegCommandAvailable{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$Result = $False
	$ApplicationInfo = Get-Command reg -ErrorAction Ignore
	If($Null -ne $ApplicationInfo){
		$CompanyName = $ApplicationInfo.FileVersionInfo.CompanyName
		If($CompanyName -like "*Microsoft*"){
			Reg.exe query HKLM | Out-Null
			If($LASTEXITCODE -eq 0){
				$Result = $True
			}
		}
	}
	EndFunc "$($MyInvocation.MyCommand.Name) returning with $Result"
	Return $Result
}

#endregion Common utilities

#region FW Core functions
Function CreateETWTraceProperties{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[Object]]$TraceDefinitionArray
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If($TraceDefinitionArray.Count -eq 0 -or $TraceDefinitionArray -eq $Null){
		Throw '$TraceDefinitionList is null.'
	}

	# Normal case
	Try{
		LogDebug ('Adding traces to PropertyArray')
		ForEach($TraceDefinition in $TraceDefinitionArray)
		{
			$TraceName = $TraceDefinition.Name + 'Trace'
			If([string]::IsNullOrEmpty($TraceDefinition.MultipleETLFiles)){
				$TraceDefinition.MultipleETLFiles = 'no'
			}
			$TraceProperty = @{
				Name = $TraceDefinition.Name
				TraceName = $ScriptPrefix + '_' + $TraceDefinition.Name + 'Trace'
				LogType = 'ETW'
				CommandName = 'logman.exe'
				Providers = $TraceDefinition.Provider  # this is the good moment to report duplicate guids in err log
				LogFileName = "`"$global:LogFolder\$LogPrefix$TraceName.etl`""
				StartOption = $Null
				StopOption = $Null
				PreStartFunc = $TraceDefinition.Name + 'PreStart'
				StartFunc = $Null
				StopFunc = $Null
				PostStopFunc = $TraceDefinition.Name + 'PostStop'
				DiagFunc = 'Run' + $TraceDefinition.Name + 'Diag'
				DetectionFunc = $Null
				AutoLogger =  @{
					AutoLoggerEnabled = $False
					AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\$TraceName-AutoLogger.etl`""
					AutoLoggerSessionName = $AutoLoggerPrefix + $ScriptPrefix + '_' + $TraceName
					AutoLoggerStartOption = $Null
					AutoLoggerStopOption = $Null
					AutoLoggerKey = $AutoLoggerBaseKey + $ScriptPrefix + '_' + $TraceName
				}
				Wait = $Null
				SupportedOSVersion = $Null # Any OSes
				Status = $TraceStatus.Success
				MultipleETLFiles = $TraceDefinition.MultipleETLFiles
				StartPriority = $StartPriority.ETW
				StopPriority = $StopPriority.ETW
				WindowStyle = $Null
			}
			#LogDebug ($TraceProperty.Name)
			$script:ETWPropertyList.Add($TraceProperty)  
		}
	}Catch{
		Throw ('An error happened during creating property for ' + $TraceDefinition.Name)
	}

	If($script:ETWPropertyList.Count -eq 0){
		Throw ('Failed to create ETWPropertyList. ETWPropertyList.Count is 0. Maybe bad entry in $TraceDefinitionList caused this.')
	}
	LogDebug ('Returning ' + $script:ETWPropertyList.Count  + ' properties.')
	EndFunc $MyInvocation.MyCommand.Name
}

Function AddTraceToAutoLog{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$TraceName
	)
	EnterFunc ($MyInvocation.MyCommand.Name + ' with ' + $TraceName)

	If($TraceName -like "*Scenario_*"){ # Scenario case
		$Token = $TraceName -split ("Scenario_")
		$TraceObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq $Token[1]}
		If($TraceObject -ne $Null){
			LogDebug "Creating a trace name for $TraceName"
			$TraceObject = CreateTraceObjectforScenarioTrace ($TraceName + 'Trace')
			If($TraceObject -ne $Null){
				LogDebug "New object for scnario trace $TraceName was created."
			}Else{
				LogError "Failed to create trace object for $TraceName"
			}
		}
	}Else{ # Normal case
		$TraceObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq $TraceName}
	}
	if($TraceName -ne "Debug"){ #Debug is switch
		if($TraceObject -eq $Null){
			Throw 'Trace ' + $TraceName + ' is not registered in trace catalog.'
		}

		# Version check
		If($TraceObject.SupportedOSVersion -ne $Null){
			If(!(FwIsSupportedOSVersion $TraceObject.SupportedOSVersion)){
				$ErrorMessage = $TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupportedOSVersion.OS + ' Build ' + $TraceObject.SupportedOSVersion.Build + '].'
				LogError $ErrorMessage
				CleanUpandExit # Early return as non supported option is specified.
			}
		}

		# Duplication check
		$tmpObject = $AutoLog | Where-Object{$_.TraceName -eq $TraceObject.TraceName}
		If($tmpObject -ne $Null){
			LogInfo "ERROR: Tried to start trace for $($TraceObject.TraceName) twice. Usually this happens when a scenario trace and a normal trace that is contained in the scenario are started at the same time. Please check what traces are contained in the scenario with below command." "Red"
			LogInfo "=> .\$ScriptName -TraceInfo <ScenarioName>" "Yellow"
			CleanUpandExit
		}
		LogDebug "Adding $($TraceObject.TraceName) to trace list"
		$AutoLog.Add($TraceObject)
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return
}

Function DumpCollection{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object[]]$Collection
	)
	EnterFunc $MyInvocation.MyCommand.Name

	LogDebug '--------------------------------------------------'
	ForEach($TraceObject in $Collection){
	   LogDebug ('Name              : ' + $TraceObject.Name)
	   LogDebug ('TraceName         : ' + $TraceObject.TraceName)
	   LogDebug ('LogType           : ' + $TraceObject.LogType)
	   LogDebug ('CommandName       : ' + $TraceObject.CommandName)
	   If($TraceObject.Providers -eq $Null){
		   $ProviderProp = ''
	   }Else{
		   $ProviderProp = $TraceObject.Providers[0] + '...  --> ' + $TraceObject.Providers.Count + ' providers'
	   }
	   LogDebug ('Providers         : ' + $ProviderProp)
	   LogDebug ('LogFileName       : ' + $TraceObject.LogFileName)
	   LogDebug ('StartOption       : ' + $TraceObject.StartOption)
	   LogDebug ('StopOption        : ' + $TraceObject.StopOption)
	   LogDebug ('PreStartFunc      : ' + $TraceObject.PreStartFunc)
	   LogDebug ('StartFunc         : ' + $TraceObject.StartFunc)
	   LogDebug ('StopFunc          : ' + $TraceObject.StopFunc)
	   LogDebug ('PostStopFunc      : ' + $TraceObject.PostStopFunc)
	   LogDebug ('DetectionFunc     : ' + $TraceObject.DetectionFunc)
	   LogDebug ('AutoLogger        : ' + $TraceObject.AutoLogger)
	   If($TraceObject.AutoLogger -ne $Null){
		   LogDebug (' - AutoLoggerEnabled     : ' + $TraceObject.AutoLogger.AutoLoggerEnabled)
		   LogDebug (' - AutoLoggerLogFileName : ' + $TraceObject.AutoLogger.AutoLoggerLogFileName)
		   LogDebug (' - AutoLoggerSessionName : ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
		   LogDebug (' - AutoLoggerStartOption : ' + $TraceObject.AutoLogger.AutoLoggerStartOption)
		   LogDebug (' - AutoLoggerStopOption  : ' + $TraceObject.AutoLogger.AutoLoggerStopOption)
		   LogDebug (' - AutoLoggerKey         : ' + $TraceObject.AutoLogger.AutoLoggerKey)
	   }
	   LogDebug ('Wait              : ' + $TraceObject.Wait)
	   If($TraceObject.SupportedOSVersion -ne $Null){
		   $OSver = $TraceObject.SupportedOSVersion.OS
		   $Build = $TraceObject.SupportedOSVersion.Build
		   $OSVersionStr = 'Windows ' + $OSver + ' Build ' + $Build
	   }Else{
			$OSVersionStr = ''
	   }
	   LogDebug ('SupportedOSVersion: ' + $OSVersionStr)
	   LogDebug ('Status            : ' + $TraceObject.Status)
	   LogDebug ('MultipleETLFiles  : ' + $TraceObject.MultipleETLFiles)
	   LogDebug ('StartPriority     : ' + $TraceObject.StartPriority)
	   LogDebug ('StopPriority      : ' + $TraceObject.StopPriority)
	   LogDebug ('WindowStyle       : ' + $TraceObject.WindowStyle)
	   LogDebug ('--------------------------------------------------')
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DumpTraceObject{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object[]]$Collection
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($Collection -eq $Null){
		LogError "Passed trace object list is null."
		return
	}
	ForEach($TraceObject in $Collection){
		If($Collection.Count -gt 1){
			Write-Host '--------------------------------------------------'
		}
		Write-Host "Name             : $($TraceObject.Name)"
		Write-Host "TraceName        : $($TraceObject.TraceName)"
		Write-Host "LogType          : $($TraceObject.LogType)"
		Write-Host "CommandName      : $($TraceObject.CommandName)"
		Write-Host "Provider         :"
		If($TraceObject.Providers -eq $Null){
			Write-Host "   => No provider"
		}Else{
			ForEach($Provider in $TraceObject.Providers){
				Write-Host "   $Provider"
			}
		}
		Write-Host "LogFileName      : $($TraceObject.LogFileName)"
		Write-Host "StartOption      : $($TraceObject.StartOption)"
		Write-Host "StopOption       : $($TraceObject.StopOption)"
		Write-Host "PreStartFunc     : $($TraceObject.PreStartFunc)"
		Write-Host "StartFunc        : $($TraceObject.StartFunc)"
		Write-Host "StopFunc         : $($TraceObject.StopFunc)"
		Write-Host "PostStopFunc     : $($TraceObject.PostStopFunc)"
		Write-Host "DetectionFunc    : $($TraceObject.DetectionFunc)"
		Write-Host "AutoLogger       :"
		If($TraceObject.AutoLogger -ne $Null){
			Write-Host "  - AutoLoggerEnabled     : $($TraceObject.AutoLogger.AutoLoggerEnabled)"
			Write-Host "  - AutoLoggerLogFileName : $($TraceObject.AutoLogger.AutoLoggerLogFileName)"
			Write-Host "  - AutoLoggerSessionName : $($TraceObject.AutoLogger.AutoLoggerSessionName)"
			Write-Host "  - AutoLoggerStartOption : $($TraceObject.AutoLogger.AutoLoggerStartOption)"
			Write-Host "  - AutoLoggerStopOption  : $($TraceObject.AutoLogger.AutoLoggerStopOption)"
			Write-Host "  - AutoLoggerKey         : $($TraceObject.AutoLogger.AutoLoggerKey)"
		}
		Write-Host "Wait            : $($TraceObject.Wait)"
		If($TraceObject.SupportedOSVersion -ne $Null){
			$OSver = $TraceObject.SupportedOSVersion.OS
			$Build = $TraceObject.SupportedOSVersion.Build
			$OSVersionStr = 'Windows ' + $OSver + ' Build ' + $Build
		}Else{
			 $OSVersionStr = ''
		}
		Write-Host "SupportedOSVersion: $($OSVersionStr)"
		Write-Host "Status            : $($TraceObject.Status)"
		Write-Host "MultipleETLFiles  : $($TraceObject.MultipleETLFiles)"
		Write-Host "StartPriority     : $($TraceObject.StartPriority)"
		Write-Host "StopPriority      : $($TraceObject.StopPriority)"
		Write-Host "WindowStyle       : $($TraceObject.WindowStyle)"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function InspectProperty{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Hashtable]$Property
	)
	#EnterFunc $MyInvocation.MyCommand.Name
	# Name
	If($Property.Name -eq $Null -or $Property.Name -eq ''){
		Throw 'ERROR: Object name is null.'
	}

	# TraceName
	If($Property.TraceName -eq $Null -or $Property.TraceName -eq ''){
		Throw 'ERROR: TraceName is null.'
	}

	# LogType
	ForEach($LogType in $script:LogTypes){
		If($Property.LogType -eq $LogType){
			$fResult = $True
			Break
		} 
	}
	If(!$fResult){
		Throw 'ERROR: unknown log type: ' + $Property.LogType
	}

	Switch($Property.LogType){
		# ETW must have:
		#   - providers
		#   - AutoLogger
		#   - AutoLoggerLogFileName/AutoLoggerSessionName
		'ETW' {
			If($Property.Providers -eq $Null){
				Throw 'ERROR: Log type is ' + $Property.LogType + ' but there are no providers.'
			}
			If($Property.AutoLogger -eq $Null){
				Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLogger is no set.'
			}Else{
				If($Property.AutoLogger.AutoLoggerLogFileName -eq $Null){
					Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerLogFileName is not specified in this property.'
				}
				If($Property.AutoLogger.AutoLoggerSessionName -eq $Null){
					Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerSessionName is not specified in this property.'
				}
			}
		}
		# Command must have:
		#   - CommandName
		#   - StartOption/StopOption
		#   - If AutoLogger is supported:
		#	   - must have AutoLoggerLogFileName/AutoLoggerStartOption/AutoLoggerStopOption
		'Command' {
			If($Property.CommandName -eq $Null){
				Throw 'ERROR: Log type is ' + $Property.LogType + " but 'CommandName' is not specified in this property."
			}
			If($Property.LogType -eq 'Command' -and ($Property.StartOption -eq $Null -or $Property.StopOption -eq $Null)){
				Throw 'ERROR: Log type is ' + $Property.LogType + ' but StartOption/StopOption is not specified in this property.'
			}
			If([string]::IsNullOrEmpty($Property.StopTimeOutInSec)){
				Throw "ERROR: Command type property must have StopTimeOutInSec but it is null"
			}
			If($Property.AutoLogger -ne $Null){
				If($Property.AutoLogger.AutoLoggerLogFileName -eq $Null){
					Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerLogFileName is not specified in this property.'
				}
				If($Property.AutoLogger.AutoLoggerStartOption -eq $Null){
					Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerStartOption is not specified in this property.'
				}
				If($Property.AutoLogger.AutoLoggerStopOption -eq $Null){
					Throw 'ERROR: Log type is ' + $Property.LogType + ' but AutoLoggerStopOption is not specified in this property.'
				}
			}
		}
		'Custom' {
			If($Property.StartFunc -ne $Null){
				Try{
					Get-Command $Property.StartFunc -ErrorAction Stop | Out-Null
				}Catch{
					Throw 'ERROR: ' + $Property.StartFunc + ' is not implemented in this script.'
				}
			}
			If($Property.StopFunc -ne $Null){
				Try{
					Get-Command $Property.StopFunc -ErrorAction Stop | Out-Null
				}Catch{
					Throw 'ERROR: ' + $Property.StopFunc + ' is not implemented in this script.'
				}
			}
			If($Property.DetectionFunc -ne $Null){
				Try{
					Get-Command $Property.DetectionFunc -ErrorAction Stop | Out-Null
				}Catch{
					Throw 'ERROR: ' + $Property.DetectionFunc + ' is not implemented in this script.'
				}
			}

			If($Property.Status -eq $Null){
				Throw('ERROR: Status is not initialized.')
			}
			# No additonal tests needed for Custom object
			Return
		}
	}

	# LogFileName
	If($Property.LogFileName -eq $Null){
		Throw 'ERROR: LogFileName must be specified.'
	}

	If($Property.Status -eq $Null){
		Throw('ERROR: Status is not initialized.')
	}
	#EndFunc $MyInvocation.MyCommand.Name	
}

Function ValidateCollection{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object[]]$Collection
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$ErrorCount=0

	ForEach($TraceObject in $Collection){
		# Name
		If($TraceObject.Name -eq $Null -or $TraceObject.Name -eq '')
		{
			Throw "[$($TraceObject.Name)] ERROR: Name is null."
			$ErrorCount++
		}
		# LogType
		$fValidLogType = $False
		ForEach($LogType in $LogTypes){
			If($TraceObject.LogType -eq $LogType){
				$fValidLogType = $True
				Break
			} 
		}
		If(!$fValidLogType){
			Throw "[$($TraceObject.Name)] ERROR: unknown log type: $($TraceObject.LogType)"
		}

		# LogFileName/Providers/AutoLogger/AutoLoggerLogFileName/AutoLoggerSessionName
		# => These may be null in some cases. We don't check them.

		# Command
		If($TraceObject.LogType -eq 'Command' -and $TraceObject.CommandName -eq $Null){
			Throw "[$($TraceObject.Name)] ERROR: Log type is Commad but 'CommandName' is not specified in this TraceObject."
		}
	}

	# For custom object
	If($TraceObject.StartFunc -ne $Null){
		Try{
			Get-Command $TraceObject.StartFunc -ErrorAction Stop | Out-Null
		}Catch{
			Throw "[$($TraceObject.Name)] ERROR: $($TraceObject.StartFunc) is not implemented in this script."
		}
	}
	If($TraceObject.StopFunc -ne $Null){
		Try{
			Get-Command $TraceObject.StopFunc -ErrorAction Stop | Out-Null
		}Catch{
			Throw "[$($TraceObject.Name)] ERROR: $($TraceObject.StopFunc) is not implemented in this script."
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function GetExistingTraceSession{
	[OutputType("System.Collections.Generic.List[PSObject]")]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name

	If($GlobalTraceCatalog.Count -eq 0){
		LogInfo 'No traces in GlobalTraceCatalog.' "Red"
		CleanUpandExit
	}

	Try{
		ValidateCollection $GlobalTraceCatalog
	}Catch{
		LogException "An exception happened in ValidateCollection" $_
		CleanUpandExit
	}

	$RunningTraces = New-Object 'System.Collections.Generic.List[PSObject]'
	$Script:RunningScenarioTraceList = New-Object 'System.Collections.Generic.List[PSObject]'
	$ETWSessionList = logman -ets | Out-String
	$CurrentSessinID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
	$Processes = Get-Process | Where-Object{$_.SessionID -eq $CurrentSessinID}

	ForEach($TraceObject in $GlobalTraceCatalog){
		Switch($TraceObject.LogType) {
			'ETW' {
				#LogDebug "Checking exist sessesion of $($TraceObject.TraceName)"

				ForEach($Line in ($ETWSessionList -split "`r`n")){
					$Token = $Line -Split '\s+'
					$TraceName = $Token[0] -replace ("Trace.*","Trace")
					If($TraceName -eq $TraceObject.TraceName){
						LogDebug "Found running trace session($TraceName)." "Yellow"
						$TraceObject.Status = $TraceStatus.Running
						$RunningTraces.Add($TraceObject)
						Break
					}ElseIf($TraceName -like ("*Scenario_" + $TraceObject.Name + "Trace*")){ # Scenario trace
						$NewTraceObject = CreateTraceObjectforScenarioTrace $TraceName
						If($NewTraceObject -ne $Null){
							LogDebug "Found running scenario trace session $($NewTraceObject.TraceName)" "Yellow"
							$NewTraceObject.Status = $TraceStatus.Running
							$RunningTraces.Add($NewTraceObject)
						}Else{
							LogError "Failed to create trace object for $TraceName"
						}
					}ElseIf($TraceName -like ("*Scenario_METL_$($TraceObject.Name)_*")){ # METL in Scenario trace
						$NewTraceObject = CreateTraceObjectforMultiETLTrace $TraceName
						If($NewTraceObject -ne $Null){
							LogDebug "Found running METL in scenario trace session $($NewTraceObject.TraceName)" "Yellow"
							$NewTraceObject.Status = $TraceStatus.Running
							$RunningTraces.Add($NewTraceObject)
						}Else{
							LogError "Failed to create trace object for $TraceName"
						}
					}
				}
			}
			'Command' {
				LogDebug ("[$($TraceObject.LogType)] Checking if $($TraceObject.Name) is enabled.")
				Switch($TraceObject.Name) {
					'WPR' {
						ForEach($Line in ($ETWSessionList -split "`r`n")){
							$Token = $Line -Split '\s+'
							If($Token[0] -eq 'WPR_initiated_WprApp_WPR' -or $Token[0] -eq 'WPR_initiated_WprApp_boottr_WPR'){
								LogDebug "Found existing $($TraceObject.Name) session." "Yellow"
								$TraceObject.Status = $TraceStatus.Running
								$RunningTraces.Add($TraceObject)
								Break
							}
						}
					}
					'Xperf' {
						# We use a log file for xperf to see if the xperf is actively running.
						$RegValue = Get-ItemProperty -Path  "$global:AutoLogParamRegKey" -ErrorAction Ignore
						$LogFolderInReg = $RegValue.LogFolder
						If(![String]::IsNullOrEmpty($LogFolderInReg)){
							$XperfFileName = "$LogFolderInReg\xperf.etl"
							If(Test-Path -Path $XperfFileName){
								LogDebug "Found existing $($TraceObject.Name) session." "Yellow"
								$TraceObject.Status = $TraceStatus.Running
								$RunningTraces.Add($TraceObject)
								Break
							}
						}
					}
					'Netsh' {
						$NetshSessionName = 'NetTrace'
						ForEach($Line in ($ETWSessionList -split "`r`n")){
							$Token = $Line -Split '\s+'							
							If($Token[0].Contains($NetshSessionName)){
								$TraceObject.Status = $TraceStatus.Running
								$RunningTraces.Add($TraceObject)
								LogDebug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
								Break
							}
						}
					}
					'Procmon' {
						$ProcmonProcess = Get-Process -name "Procmon*" -ErrorAction Ignore
						$FilterDriverList = fltmc | Out-String
						ForEach($Line in ($FilterDriverList -split "`r`n")){ # Get line
							# Split line by space and token[0] is driver name and token[1] is the number of instance.
							$Token = $Line -Split '\s+' 
							If([String]$Token[0] -like "Procmon*"){
								If($Token[1] -ne "0"){
									If((($ProcmonProcess -ne $Null) -and ($global:ParameterArray -contains 'Start' -or $Status.IsPresent -or $Stop.IsPresent)) -or $script:StopAutologger){
										LogDebug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
										$TraceObject.Status = $TraceStatus.Running
										$RunningTraces.Add($TraceObject)
										break
									}
								}
							}
						}
					}
					'PSR' {
						$PSRProcess = $Processes | Where-Object{$_.Name.ToLower() -eq 'psr'}
						If($PSRProcess.Count -ne 0){
							$TraceObject.Status = $TraceStatus.Running
							$RunningTraces.Add($TraceObject)
							LogDebug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
						}
					}
					'Video' {
						$VideoProcess = $Processes | Where-Object{$_.Name.ToLower() -eq 'recordercommandline'}
						If($VideoProcess.Count -ne 0){
							$TraceObject.Status = $TraceStatus.Running
							$RunningTraces.Add($TraceObject)
							LogDebug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
						}
					}
				}
			}
			'Perf' {
				LogDebug ("[$($TraceObject.LogType)] Checking if $($TraceObject.Name) is enabled.")
				$datacollectorset = new-object -COM Pla.DataCollectorSet
				Try{  
					$datacollectorset.Query($TraceObject.Name, $env:computername)
				}Catch{
					# If 'Perf' is not running, exception happens and this is actually not error. So just log it if -DebugMode.
					$Error.RemoveAt(0)
					LogDebug ('INFO: An Exception happened in Pla.DataCollectorSet.Query for ' + $TraceObject.Name)
					Break
				}
			
				#Status ReturnCodes: 0=stopped 1=running 2=compiling 3=queued (legacy OS) 4=unknown (usually AutoLogger)
				If($datacollectorset.Status -ne 1){
					LogDebug ('PerfMon status is ' + $datacollectorset.Status)
					Break
				}
				$TraceObject.Status = $TraceStatus.Running
				$RunningTraces.Add($TraceObject)
				LogDebug ('Found existing ' + $TraceObject.Name + ' session.')
			}
			'Custom' {
				LogDebug ("[$($TraceObject.LogType)] Checking if $($TraceObject.Name) is enabled.")
				If($TraceObject.DetectionFunc -ne $Null){
					$fResult = & $TraceObject.DetectionFunc
					If($fResult){
						$TraceObject.Status = $TraceStatus.Running
						$RunningTraces.Add($TraceObject)
						LogDebug ('Found existing ' + $TraceObject.Name + ' session.') "Yellow"
					}
				}Else{
					LogDebug ($TraceObject.Name + ' does not have detection function.')
				}
			}
			Default {
				LogInfo ('Unknown log name ' + $TraceObject.LogType) "Red"
			}
		}
	}

	$RunningMultiETLTraceList = GetRunningMultiETLTrace
	ForEach($RunningMultiETLTraceObject in $RunningMultiETLTraceList){
		LogDebug ('Found running multi elt file trace ' + $RunningMultiETLTraceObject.TraceName) "Yellow"
		$RunningTraces.Add($RunningMultiETLTraceObject)
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $RunningTraces
}

Function GetRunningMultiETLTrace{
	[OutputType("System.Collections.Generic.List[PSObject]")]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name

	$RunningMultiETLTraceList = New-Object 'System.Collections.Generic.List[PSObject]'
	$ETWSessionList = logman -ets | Out-String

	# To detect multi etl file trace, we check output of logman -ets again and if found the multi etl trace,
	# create trace object and add it to $RunningTraces
	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$Token = $Line -Split '\s+'
		If($Token[0] -like ($ScriptPrefix + '_METL_' + "*Trace")){

			# Create a new trace property and object
			$FullTraceName = $Token[0] -replace ("Trace.*","Trace")
			$TraceObject = CreateTraceObjectforMultiETLTrace $FullTraceName
			If($TraceObject -ne $Null){
				LogDebug "Trace object for $($TraceObject.TraceName) was created." "Yellow"
				$TraceObject.Status = $TraceStatus.Running
				$RunningMultiETLTraceList.Add($TraceObject)
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $RunningMultiETLTraceList
}

Function GetRunningScenarioTrace{
	[OutputType("System.Collections.Generic.List[PSObject]")]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name

	$RunningScenarioObjectList = New-Object 'System.Collections.Generic.List[PSObject]'
	$TraceListInScenario = New-Object 'System.Collections.Generic.List[PSObject]'
	$ETWSessionList = logman -ets | Out-String

	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$Token = $Line -Split '\s+'

		If($Token[0] -like ("*Scenario_*")){ # Scenario trace
			# Example: $ScenarioName="ADS_AUTH" $FullTraceName="AutoLog_ADS_AUTHScenario_ADS_XXXTrace" $TraceName=ADS_XXXTrace
			$ScenarioToken = $Token[0] -Split 'Scenario_' # AutoLog_ADS_AUTHScenario_ADS_XXXTrace => AutoLog_ADS_AUTH , ADS_XXXTrace
			$ScenarioName = $ScenarioToken[0] -replace (($ScriptPrefix + '_'),'') # AutoLog_ADS_AUTH => ADS_Auth
			$FullTraceName = $Token[0] -replace ("Trace.*","Trace") # AutoLog_ADS_AUTHScenario_ADS_XXXTraceXXX => AutoLog_ADS_AUTHScenario_ADS_XXXTrace
			If($ScenarioToken[1].contains("METL")){
				$Temp = $ScenarioToken[1] -Split '_'   
				$TraceName = ($Temp[1] + '_' + $Temp[2] + 'Trace') # METL_NET_AfdTcpBasic_NetIoBasicTrace => NET_AfdTcpBasicTrace
			}Else{
				$TraceName = $ScenarioToken[1] -replace ("Trace.*","Trace") # ADS_XXXTraceXXX => ADS_XXXTrace
			}
			LogDebug "TraceName = $TraceName(Original name=$FullTraceName)"
			$ScenarioObject = $RunningScenarioObjectList | Where-Object{$_.ScenarioName -eq $ScenarioName}
			If($ScenarioObject -eq $Null){
				$TraceListInScenario = New-Object 'System.Collections.Generic.List[PSObject]'
				$TraceObject = $GlobalTraceCatalog | Where-Object{$_.TraceName -like ("*" + $TraceName)}
				If($TraceObject -eq $Null){
					LogDebug "Searching " + $TraceName + " failed."
					continue
				}
				$NewTraceObject = $TraceObject.psobject.copy() # Create new object for scenario trace
				$NewTraceObject.TraceName = $FullTraceName
				LogDebug "Adding $($NewTraceObject.TraceName) to $ScenarioName"
				$TraceListInScenario.Add($NewTraceObject)
				$ScenarioProperty = @{
					ScenarioName = $ScenarioName
					TraceListInScenario = $TraceListInScenario
				}
				LogDebug "Creating object for $ScenarioName"
				$RunningScenarioObject = New-Object PSObject -Property $ScenarioProperty
				$RunningScenarioObjectList.Add($RunningScenarioObject)
			}Else{
				$TraceObject = $GlobalTraceCatalog | Where-Object{$_.TraceName -like ("*" + $TraceName)}
				If($TraceObject -eq $Null){
					LogDebug "Searching $($ScenarioToken[1]) failed."
				}
				$NewTraceObject = $TraceObject.psobject.copy() # Create new object for scenario trace
				$NewTraceObject.TraceName = $FullTraceName
				LogDebug "Adding $($NewTraceObject.TraceName) to $($ScenarioObject.ScenarioName)"
				$ScenarioObject.TraceListInScenario.Add($NewTraceObject)
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $RunningScenarioObjectList
}

Function GetEnabledAutoLoggerSession{
<#
.SYNOPSIS
Get all enabled AutoLogger traces

.DESCRIPTION
Process of detecting enabled AutoLogger settings:
1. Search registry keys that has our sign($Scriptprefix) from 'HKLM\System\CurrentControlSet\Control\WMI\AutoLogger'
2. Firstly we will see if the key name has '_.*Scenario_.*' to get enabled AutoLogger for scenario trace.
3. Scondly ,search with '_METL_.*' to get enabled AutoLogger for multiple etl file trace.
4. After that, search normal ETW trace with '$ScriptPrifix_' which is currently 'AutoLog_'.
5. In the step 2-4, we found all types of ETW traces enabled by this script. After that, we will find
   AutoLogger entries for other support tools like WPR, Netsh and Procmon.
6. Return list of trace object that is enabled for AutoLogger.

.OUTPUTS
List of trace object that is enabled for AutoLogger.
Type: System.Collections.Generic.List[PSObject]

.NOTES
This function does not throw exception. In case of error, this function returns $Null.
#>
	[OutputType("System.Collections.Generic.List[PSObject]")]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$EnabledAutoLoggerTraces = New-Object 'System.Collections.Generic.List[PSObject]'

	# Get enabled AutoLogger traces for normal ETW, scneario trace and multiple etl trace.
	Try{
		$AutoLoggerRegArray = Get-ChildItem -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\AutoLogger
	}Catch{
		LogException ("Exception happened when accessing to HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\AutoLogger") $_ $fLogFileOnly
		Return $Null
	}
	
	ForEach($AutoLoggerReg in $AutoLoggerRegArray){
		$TraceObject = $Null
		If(($AutoLoggerReg.PSChildName) -match ($ScriptPrifix + '_.*Scenario_.*')){
			# Scenario trace case
			$TraceObject = CreateTraceObjectforScenarioTrace $AutoLoggerReg.PSChildName
		}ElseIf(($AutoLoggerReg.PSChildName) -match ($ScriptPrifix + '_METL_.*')){
			# Multiple ETL file trace case or single trace with '!' provider format.
			$TraceObject = CreateTraceObjectforMultiETLTrace $AutoLoggerReg.PSChildName
		}ElseIf(($AutoLoggerReg.PSChildName).contains($ScriptPrifix + '_')){
			# Normal ETW case
			$TraceObject = $GlobalTraceCatalog | Where-Object{$_.TraceName -eq $AutoLoggerReg.PSChildName}
			If($TraceObject.AutoLogger.AutoLoggerKey -ne $Null){
				$RegValue = $Null
				$RegValue = Get-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction Ignore
				If($RegValue -eq $Null){
					LogDebug ($TraceObject.Name + " does not have AutoLogger start registry(" + $TraceObject.AutoLogger.AutoLoggerKey + "\Start)") 
					Continue
				}
			}Else{
				Continue
			}
		}

		If($TraceObject -ne $Null){
			# Update AutoLoggerEnabled
			Try{
				$RegStartValue = Get-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction Stop
			}Catch{
				# We cannot use stream as this function returns object. So this is error but just logs with debugmode.
				LogDebug ($TraceObject.Name + " does not have AutoLogger start registry(" + $TraceObject.AutoLogger.AutoLoggerKey + "\Start)") 
				Continue
			}
			If($RegStartValue.Start -eq 1){
				$TraceObject.AutoLogger.AutoLoggerEnabled = $True
			}Else{
				$TraceObject.AutoLogger.AutoLoggerEnabled = $False
			}
			
			# Upadate AutoLoggerLogFileName
			If(!$StartAutoLogger.IsPresent){
				Try{
					$RegFileNameValue = Get-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'FileName' -ErrorAction Stop
				}Catch{
					# We cannot use stream as this function returns object. So this is error but just logs with debugmode.
					LogDebug ($TraceObject.TraceName + " does not have FileName registry") 
				}
				If($RegFileNameValue.FileName -ne $Null){
					$TraceObject.AutoLogger.AutoLoggerLogFileName = $RegFileNameValue.FileName
				}
			}

			If($TraceObject.AutoLogger.AutoLoggerEnabled){
				LogDebug ("AutoLogger for $($TraceObject.AutoLogger.AutoLoggerSessionName) is enabled.") "Yellow"
				$EnabledAutoLoggerTraces.Add($TraceObject)
				Continue
			}
		}
	}

	# Search AutoLogger entries for other all support tools(ex WPR, Netsh and Procmon).
	$CommandTraces = $GlobalTraceCatalog | Where-Object {$_.LogType -ne 'ETW'}
	ForEach($TraceObject in $CommandTraces){
		
		# This object does not support AutoLogger.
		If($TraceObject.AutoLogger -eq $Null){
			#LogDebug ('Skipping ' + $TraceObject.Name + ' as this does not support AutoLogger.')
			Continue
		}
		# This has AutoLogger but it is not enabled.
		If(!(Test-Path -Path $TraceObject.AutoLogger.AutoLoggerKey)){
			LogDebug ('Skipping ' + $TraceObject.Name + ' as AutoLogger is not enabled.')
			Continue
		}
	
		# Check start value.
		$RegValue = $Null
		$RegValue = Get-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction Ignore
		If($RegValue -eq $Null){
			# We cannot use stream as this function returns object. So this is error but just logs with debugmode.
			LogDebug ($TraceObject.Name + " does not have AutoLogger start registry(" + $TraceObject.AutoLogger.AutoLoggerKey + "\Start)") 
			Continue
		}
	
		# Now this object has start value so check it.
		# Procmon is tricky and if it is 0 or 3, which means BootLogging enabled.
		If($TraceObject.Name -eq 'Procmon' -and ($RegValue.Start -eq 3 -or $RegValue.Start -eq 0)){
			LogDebug ('AutoLogger for ' + $TraceObject.Name + ' is enabled.') "Yellow"
			$TraceObject.AutoLogger.AutoLoggerEnabled = $True
			$EnabledAutoLoggerTraces.Add($TraceObject)
			Continue
		}
	
		If($RegValue.Start -eq 1){
			LogDebug ('AutoLogger for ' + $TraceObject.Name + ' is enabled.') "Yellow"
			$TraceObject.AutoLogger.AutoLoggerEnabled = $True
			$EnabledAutoLoggerTraces.Add($TraceObject)
		}Else{
			$TraceObject.AutoLogger.AutoLoggerEnabled = $False
		}
	}

	# Show found traces in case of debugmode.
	If($DebugMode.IsPresent){
		LogDebug ("===============	 ENABLED AutoLogger TRACE	 ===============")
		ForEach($TraceObject in $EnabledAutoLoggerTraces){
			LogDebug ("  - " + $TraceObject.AutoLogger.AutoLoggerSessionName)
		}
		LogDebug ("===============================================================")
		If($EnabledAutoLoggerTraces.Count -ne 0){
			DumpCollection $EnabledAutoLoggerTraces
		}
		#Read-Host ("[DBG - hit ENTER to continue] [End of GetEnabledAutoLoggerSession] ==>")
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $EnabledAutoLoggerTraces
}

Function CreateTraceObjectforScenarioTrace{
	[OutputType([Object])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ScenarioTraceName
	)
	EnterFunc "$($MyInvocation.MyCommand.Name) with $ScenarioTraceName"
	If(!($ScenarioTraceName.contains('Scenario_'))){
		LogDebug "$ScenarioTraceName is not a scenario trace" "Yellow"
		Return $Null
	}
	$tmpTraceName = $ScenarioTraceName -replace (".*Scenario_","") # AutoLog_testScenario_DEV_TEST1Trace => DEV_TEST1Trace
	$TraceName = $tmpTraceName -replace ("Trace","") # DEV_TEST1Trace => DEV_TEST1
	If($TraceName.Contains("METL")){ 
		$TraceName = $TraceName -replace ("METL_","") # METL_DEV_TEST2_CertCli => # DEV_TEST2_CertCli
		$Token = $TraceName -split ('_')
		$TraceName = $Token[0] + '_' + $Token[1]
	}
	$TraceObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq $TraceName}
	If($TraceObject -ne $Null){
		$NewTraceObject = $TraceObject.psobject.copy() # Create new object for scenario trace
		$NewTraceObject.TraceName = $ScenarioTraceName
		$NewTraceObject.AutoLogger = $Null
		$NewTraceObject.AutoLogger = @{
			AutoLoggerEnabled  = $False
			AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\$($NewTraceObject.TraceName)-AutoLogger.etl`""
			AutoLoggerSessionName = $AutoLoggerPrefix + $NewTraceObject.TraceName
			AutoLoggerStartOption = $Null
			AutoLoggerStopOption = $Null
			AutoLoggerKey = $AutoLoggerBaseKey + $NewTraceObject.TraceName
		}
		LogDebug "Trace object for $($NewTraceObject.TraceName) was created."
	}Else{
		LogError "Unable to find $TraceName from global trace catalog"
		Return $Null
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $NewTraceObject
}

Function CreateTraceObjectforMultiETLTrace{
	[OutputType([Object])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$MultiETLTraceName
	)
	EnterFunc "$($MyInvocation.MyCommand.Name) with $MultiETLTraceName"
	If(!($MultiETLTraceName.contains('_METL_'))){
		LogDebug "$MultiETLTraceName is not a METL trace" "Yellow"
		Return $Null
	}

	# Convert METL name to original normal trace name in order to retrieve trace object from global catalog later.
	$TraceName = $Null
	$tmpTraceName = $MultiETLTraceName -replace ".*METL_","AutoLog_" # AutoLog_METL_NET_TEST3_CertCliTrace => AutoLog_NET_TEST3_CertCliTrace
	$Token = $tmpTraceName -split "_"
	For($i=0; $i -lt $Token.Length-1; $i++){
		If($i -ne 0){
			$TraceName = $TraceName + '_'
		}
		$TraceName = $TraceName + $Token[$i]  # AutoLog_NET_TEST3_CertCliTrace => AutoLog_NET_TEST3
	}
	$TraceName = $TraceName + 'Trace'  # AutoLog_NET_TEST3 => AutoLog_NET_TEST3Trace(Original trace name)

	# Get trace object for METL from catalog
	$TraceObject = $GlobalTraceCatalog | Where-Object{$TraceName -eq $_.TraceName}
	If($TraceObject -ne $Null){
		If($TraceObject.Count -ne $Null -and $TraceObject.Length -gt 1){
			LogError "$($TraceObject.Length) trace names are found in Global catalog.(Found trace names: $($TraceObject.TraceName)"
			Return $Null
		}
		# Original trace object taken from catalog is different from METL trace. So copy it and modify properties to create object for METL
		$NewTraceObject = $TraceObject.psobject.copy() # Create new object for METL trace
		$NewTraceObject.TraceName = $MultiETLTraceName
		$NewTraceObject.MultipleETLFiles = 'yes'
		# Inner object for AutoLogger is not copied. Hence create new one and set it to the new trace object.
		$NewTraceObject.AutoLogger = $Null
		$NewTraceObject.AutoLogger = @{
			AutoLoggerEnabled  = $False
			AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\$($NewTraceObject.TraceName)-AutoLogger.etl`""
			AutoLoggerSessionName = $AutoLoggerPrefix + $NewTraceObject.TraceName
			AutoLoggerStartOption = $Null
			AutoLoggerStopOption = $Null
			AutoLoggerKey = $AutoLoggerBaseKey + $NewTraceObject.TraceName
		}
		LogDebug "Trace object for $($NewTraceObject.TraceName) was created."
	}Else{
		LogError "Unable to find $TraceName from global trace catalog(METL name: $MultiETLTraceName)"
		Return $Null
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $NewTraceObject
}

Function ConvertToLocalPerfCounterName{
	[OutputType([Array])]
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String[]]$PerfCounterList
	)
	EnterFunc $MyInvocation.MyCommand.Name

	if (!(FwTestRegistryValue "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Perflib\009" "Counter")) {
		LogWarn "English Reg. 'Counter' not found."}
	else {
		$EnglishCounterName = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Perflib\009" -name 'Counter' | Select-Object -ExpandProperty counter
	}
	if (!(FwTestRegistryValue "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage" "Counter")) {
		LogWarn "Localized Reg. 'Counter' not found."}
	else {
		$LocalCounterName = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage" -name 'Counter' | Select-Object -ExpandProperty counter
	}
	
	$LoopCount = 0
	$PerfHashList = @{}
	ForEach($CounterData in @($EnglishCounterName,$LocalCounterName)){
		$CounterDataHash = @{}
		$i = 0
		# Creating hashtable that has counter id and counter name
		ForEach($line in ($CounterData -split "`r`n")){
			If($i -eq 0){
				$id = $line
				$i++
			}ElseIf($i -eq 1){
				$CounterName = $line
				# Issue#385 - '-Perfmon ALL' fails on Win11 in ConvertToLocalPerfCounterName
				If(!$CounterDataHash.ContainsKey($id)){
					#LogDebug ("Adding $id($CounterName)")
					$CounterDataHash.Add($id,$CounterName)
					$i = 0
				}
			}
		}

		If($LoopCount -eq 0){
			$PerfHashList.add("en-US",$CounterDataHash)
		}ElseIf($LoopCount -eq 1){
			$PerfHashList.add("Local",$CounterDataHash)
		}
		$LoopCount++
	}
	
	$EnlishCounterHash = $PerfHashList["en-US"]
	$LocalCounterHash = $PerfHashList["Local"]
	
	$LocalizedCounterSetNameArray = @()

	ForEach($EnglishCounterName in $PerfCounterList){
		$IsNonInstanceType = $False
		# Case for # Case for '<CounterName>(*)\*'
		If($EnglishCounterName.contains("(*)\*")){ 
			$EnglishCounterName = $EnglishCounterName -replace '^\\','' # Remove first '\'.
			$EnglishCounterName = $EnglishCounterName -replace '\(\*\)\\\*',''
		# Case for '<CounterName>\*'
		}ElseIf($EnglishCounterName.contains("\*")){
			$EnglishCounterName = $EnglishCounterName -replace '^\\','' # Remove first '\'.
			$EnglishCounterName = $EnglishCounterName -replace '\\\*',''
			$IsNonInstanceType = $True
		}Else{
			LogWarn ("Invalid counter set name($EnglishCounterName) is passed.")
			Continue
		}
	
		# Now search counter id conrresponding to the counter name and get localized counter name using the id.
		Foreach ($CounterID in $EnlishCounterHash.Keys){
			$EnglishCounterNameInRegistry = $EnlishCounterHash[$CounterID]
			If($EnglishCounterName -eq $EnglishCounterNameInRegistry){
				If($Null -ne $LocalCounterHash[$CounterID]){
					# Converting to localized counter name using counter id.
					#LogDebug ("Adding " + $LocalCounterHash[$CounterID] + " to counter array")
					If($IsNonInstanceType){
						$LocalizedCounterSetNameArray += "\" + $LocalCounterHash[$CounterID] + "\*"
					}Else{
						$LocalizedCounterSetNameArray += "\" + $LocalCounterHash[$CounterID] + "(*)\*"
					}
				}Else{
					# This case, we don't have local counter(this might be a bug) and simply set english counter name to local counter array.
					LogDebug ("Adding English name of " + $EnglishCounterNameInRegistry + " to counter array")
					If($IsNonInstanceType){
						$LocalizedCounterSetNameArray += "\" + $EnlishCounterHash[$CounterID] + "\*"
					}Else{
						$LocalizedCounterSetNameArray += "\" + $EnlishCounterHash[$CounterID] + "(*)\*"
					}
				}
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $LocalizedCounterSetNameArray
}

Function RunPreparation{
	EnterFunc $MyInvocation.MyCommand.Name

	If($global:ParameterArray -notcontains 'Stop'){

		# For -Netsh and -NetshScenario
		If($global:ParameterArray -Contains 'netsh' -or $global:ParameterArray -Contains 'netshscenario'){
			If(!($global:ParameterArray -Contains 'noNetsh')){
				LogDebug "Running dummy netsh"
				$DummyNetshFile = "$env:temp\packetcapture_dummy.etl"
				$Commands = @(
					"netsh trace start capture=yes scenario=NetConnection capturetype=physical traceFile=$DummyNetshFile correlation=no $Script:NetshTraceReport maxSize=1 fileMode=circular overwrite=yes",
					"netsh trace stop"
				)
				RunCommands "netsh" $Commands -ThrowException:$False -ShowMessage:$False
				$DummyNetshFileFull = (Get-Item -LiteralPath $DummyNetshFile -ErrorAction Ignore).FullName 	#we# needed for short folder names like C:\Users\walte~1.abc\AppData\Local\Temp
				If(![String]::IsNullOrEmpty($DummyNetshFileFull)) {
					If(test-path -Path $DummyNetshFileFull){
						Remove-Item -Force -Path $DummyNetshFileFull -ErrorAction Ignore | Out-Null
					}
				}
				LogInfo "Setting up Netsh parameters."
				FixUpNetshProperty
			} else {
				LogInfoFile "skip Setting up Netsh, because of -noNetsh switch"
			}
		}
	}

	# Fiddler
	If($global:ParameterArray -Contains 'Fiddler'){
		FixUpFiddlerProperty
	}

	# For -Procmon, fix up property to find path for Procmon.exe
	If($global:ParameterArray -Contains 'Procmon'){
		If($global:ParameterArray -notcontains 'noProcmon'){
			FixUpProcmonProperty
		} else {
			LogInfoFile "skip Setting up Procmon, because of -noProcmon switch"
		}
	}

	<# 
	Autual process starts here:
	1. CreateETWTraceProperties creates trace properties for ETW trace automatically based on $TraceDefinitionList.
	2. Created trace properties are added to $GlobalPropertyList which has all properties including other traces like WRP and Netsh.
	3. Create trace objects based on $GlobalPropertyList 
	4. Created TraceObjects are added to $GlobalTraceCatalog
	5. Check argmuents and pick up TraceObjects specified in command line parameter and add them to $AutoLog(Generic.List)
	6. StartTraces() starts all traces in $AutoLog(not $GlobalTraceCatalog). 
	#>
	
	# Creating properties for ETW trace and add them to ETWPropertyList
	Try{
		LogDebug ('Creating properties for ETW and adding them to GlobalPropertyList.')
		CreateETWTraceProperties $TraceDefinitionList  # This will add created property to $script:ETWPropertyList
	}Catch{
		LogException ("An exception happened in CreateETWTraceProperties.") $_
		CleanUpandExit # Trace peroperty has invalid value and this is critical. So exits here.
	}

	ForEach($RequestedTraceName in $global:ParameterArray){   #milantodo this is where we need handle new params
		If($TraceSwitches.Contains($RequestedTraceName)){  #TraceSwitches correspond to scenarios
			 $ETWTrace = $TraceDefinitionList | Where-Object {$_.Name -eq $RequestedTraceName}
			If($ETWTrace -eq $Null){
				LogInfo ($RequestedTraceName + ' is not registered in our trace list.') "Red"
				CleanUpandExit
			}
			Continue 
		}
	}

	# Creating all properties and add them to $GlobalPropertyList
	LogDebug ("Adding $($script:ETWPropertyList.count) ETW properties and $($CommandPropertyList.Count) command properties to GlobalTraceCatalog.")
	$AllProperties = $script:ETWPropertyList + $CommandPropertyList
	ForEach($TraceProperty in $AllProperties){
		Try{
			InspectProperty $TraceProperty
		}Catch{
			LogInfo ('ERROR: an error happens during inspecting property for ' + $TraceProperty.Name) "Red"
			Write-Host ($_.Exception.Message) -ForegroundColor Red
			Write-Host ('---------- Error propery ----------')
			$TraceProperty | ft
			Write-Host ('-----------------------------------')
			CleanUpandExit # This is critical and exiting.
		}
		# Creating TraceObject from TraceProperty and add it to GlobalTraceCatalog.
		$TraceObject = New-Object PSObject -Property $TraceProperty
		$GlobalTraceCatalog.Add($TraceObject)
	}

	LogDebug ('Setting $fPreparationCompleted to true.')
	$script:fPreparationCompleted = $True

	#If($DebugMode.IsPresent){
	#	LogDebug ("======================	 GLOBAL TRACE CATALOG	 =======================")
	#	ForEach($TraceObject in $GlobalTraceCatalog){
	#		LogDebug ("Name: " + $TraceObject.Name + " TraceName: " + $TraceObject.TraceName)
	#	}
	#	LogDebug ("===========================================================================")
	#}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StartTraces{
	EnterFunc $MyInvocation.MyCommand.Name
	$global:TssPhase = "_Start_"
	
	# Run pre-start function for scenario trace and start TSS Clock.
	If($Scenario.Count -ne 0){
		ForEach($ScenarioName in $Scenario){
			RunFunction ($ScenarioName + 'ScenarioPreStart')
		}
		# Issue#334 - Clock should start on each Scenario
		StartAutoLogClock
	}

	# List used for multi etl file trace
	$CreatedMETLTraceList = New-Object 'System.Collections.Generic.List[PSObject]'
	$RemoveTraceList = New-Object 'System.Collections.Generic.List[PSObject]'

	ForEach($TraceObject in $AutoLog)
	{
		# Run pre-start function for a component.
		$ComponentPreStartFunc = $TraceObject.Name + 'PreStart'
		Try{
			RunFunction $ComponentPreStartFunc -ThrowException:$True
		}Catch{
			LogWarn "[$($TraceObject.Name)] Error happens in pre-start function($ComponentPreStartFunc). Skipping this trace."
			LogException ("An error happened in " + $ComponentPreStartFunc) $_ $fLogFileOnly
			$TraceObject.Status = $TraceStatus.ErrorInStart
			Continue
		}

		Switch($TraceObject.LogType){
			'ETW' {
				If($StartAutoLogger.IsPresent){
					$TraceName = $TraceObject.AutoLogger.AutoLoggerSessionName
				}Else{	
					$TraceName = $TraceObject.TraceName
				}
				LogDebug "Enter [ETW] section in StartTraces. Starting $TraceName"

				if($TraceObject.MultipleETLFiles -eq 'yes')
				{
					#add code for multiple etl files
					LogDebug "[$($TraceObject.Name)] Enter multiple file condition"
					$RemoveTraceList.Add($TraceObject)
					$i=0
					ForEach($Provider in $TraceObject.Providers){
						#get etl file namd and guid from Provider
						if ($Provider -like "*!*")
						{
							$temp = $Provider.Split('!')
							$SingleTraceGUID = $temp[0] # Trace GUID
							$ETLName = $temp[1] # etl name
							If(![string]::IsNullOrEmpty($Scenario)){
								$TraceName = $ScriptPrefix + '_' + $Scenario + 'Scenario_METL_' + $TraceObject.Name + '_' + $ETLName + 'Trace'
							}Else{
								$TraceName = $ScriptPrefix + '_METL_' + $TraceObject.Name + '_' + $ETLName + 'Trace'
							}
							If($StartAutoLogger.IsPresent){
								If(![string]::IsNullOrEmpty($Scenario)){
									$SingleTraceName = $AutoLoggerPrefix + $ScriptPrefix + '_' + $Scenario + 'Scenario_METL_' + $TraceObject.Name + '_' + $ETLName + 'Trace'
								}Else{
									$SingleTraceName = $AutoLoggerPrefix + $ScriptPrefix + '_METL_' + $TraceObject.Name + '_' + $ETLName + 'Trace'
								}
							}Else{
								$SingleTraceName = $TraceName
							}
							#support for custom flags in etl
							$SingleTraceFlags = $temp[2] # Trace flag
							if ([string]::IsNullOrEmpty($SingleTraceFlags))
							{
								$SingleTraceFlags = "0xffffffffffffffff"
							}
							$SingleTraceLevel  = $temp[3] # Trace level
							if ([string]::IsNullOrEmpty($SingleTraceLevel))
							{
								$SingleTraceLevel = "0xff"
							}
							LogDebug "ETLMode=$Script:ETLmode | GUID=$SingleTraceGUID | TraceName=$SingleTraceName | TraceFlag=$SingleTraceFlags | TraceLevel=$SingleTraceLevel"

							$CreatedMETLTraceObject = $CreatedMETLTraceList | Where-Object{$_.TraceName -eq $TraceName}
							If($CreatedMETLTraceObject -eq $Null){
								$ShouldCreate = $True

								# Create trace object and add it to AutoLog
								$METLTraceObject = CreateTraceObjectforMultiETLTrace $TraceName
								If($METLTraceObject -ne $Null){
									LogDebug "Adding $($METLTraceObject.TraceName) to CreatedMETLTraceList"
									$CreatedMETLTraceList.Add($METLTraceObject)
								}Else{
									Throw "Failed to create trace object for $TraceName"
								}
							}Else{
								$ShouldCreate = $False
							}

							#If($DebugMode.IsPresent){
							#	Read-Host ("[DBG - hit ENTER to continue] [before starting logman create for multifile mode] ==>")
							#}
							If($StartAutoLogger.IsPresent){
								$AutoLoggerFileName = $SingleTraceName -replace ('autosession\\','')
								$etlLogPath= ($TraceObject.LogFileName).Substring(0, ($TraceObject.LogFileName).LastIndexOf("\")+1) + $LogPrefix + $AutoLoggerFileName + '-AutoLogger.etl"'
							}Else{
								$etlLogPath= ($TraceObject.LogFileName).Substring(0, ($TraceObject.LogFileName).LastIndexOf("\")+1) + $LogPrefix + $SingleTraceName + '.etl"'
							}

							Write-Progress -Activity ('Adding ' + $SingleTraceGUID + ' ' + $SingleTraceName + ' to ' + $TraceName) -Status 'Progress:' -PercentComplete ($i/$TraceObject.Providers.count*100)

							if ($Script:ETLmode -eq "circular")
							{
								Start-Sleep -Milliseconds 200
								If($ShouldCreate){
									RunCommands "ETW" "logman create trace $SingleTraceName -ow -o $($etlLogPath) -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -nb 16 16 -bs 1024 -mode $Script:ETLmode -f bincirc -max $Script:ETLMaxSize -ets" -ThrowException:$True -ShowMessage:$True -ShowError:$True
								}Else{
									RunCommands "ETW" "logman update trace $SingleTraceName -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -ets" -ThrowException:$False -ShowMessage:$False -ShowError:$True
								}
							}
							elseif($Script:ETLmode -eq "newfile")
							{
								$a = "`"$($etlLogPath.Substring(1, $etlLogPath.Length-6))_%d.etl`""
								Start-Sleep -Milliseconds 200
								If($ShouldCreate){
									RunCommands "ETW" "logman create trace $SingleTraceName -ow -o $a -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -nb 16 16 -bs 1024 -mode $Script:ETLmode -max $Script:ETLMaxSize -ets" -ThrowException:$True -ShowMessage:$True -ShowError:$True
								}Else{
									RunCommands "ETW" "logman update trace $SingleTraceName -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -ets" -ThrowException:$True -ShowMessage:$False -ShowError:$True
								}
							}
							else
							{
								# we should never get here
								Throw ("Invalid ETLOptions! ETLMode must contain either circular or newfile")
							}
							$i++
						}
					}
					Write-Progress -Activity 'Updating providers' -Status 'Progress:' -Completed
				}
				#elseif ([string]::IsNullOrEmpty($TraceObject.Providers)) #milanmil210527
				#{
				#	 Write-Progress -Activity 'ETW tracing is not configured for this data collection' -Status 'Progress:' -Completed
				#}  #milanmil210527

				else # case for normal trace 
				{
					LogDebug ("ETLMode=$Script:ETLmode  | LogFileName=" + $TraceObject.LogFileName)

					# This throws an exception and will be handled in main
					if ($Script:ETLmode -eq "circular")
					{
						Start-Sleep -Milliseconds 200
						RunCommands "ETW" "logman create trace $TraceName -ow -o $($TraceObject.LogFileName) -mode $Script:ETLmode -bs 64 -f bincirc -max $Script:ETLMaxSize -ft 60 -ets" -ThrowException:$True -ShowMessage:$True -ShowError:$True
					}
					elseif($Script:ETLmode -eq "newfile")
					{
						$a = "`"$(($TraceObject.LogFileName).Substring(1, ($TraceObject.LogFileName).Length-6))_%d.etl`""
						Start-Sleep -Milliseconds 200
						RunCommands "ETW" "logman create trace $TraceName -ow -o $a -mode $Script:ETLmode -bs 64 -max $Script:ETLMaxSize -ft 60 -ets" -ThrowException:$True -ShowMessage:$True -ShowError:$True
					}
					else
					{
					# we should never get here
					   Throw ("Invalid ETLOptions! ETLMode must contain either circular or newfile")
					}

					# Adding all providers to the trace session
					$i=0
					ForEach($Provider in $TraceObject.Providers){

						if ($Provider -like "*!*")
						{ # Single etl file + multi flags/levels
							$temp = $Provider.Split('!')
							$SingleTraceGUID = $temp[0]
							$SingleTraceName = $temp[1]  # this will be ignored in this run as we trace all in a same file, however it is mandatory in case custom flags is required
							If($StartAutoLogger.IsPresent){
								If(![string]::IsNullOrEmpty($Scenario)){
									$SingleTraceName = $AutoLoggerPrefix + $ScriptPrefix + '_' + $Scenario + 'Scenario_METL_' + $TraceObject.Name + '_' + $temp[1] + 'Trace'
								}Else{
									$SingleTraceName = $AutoLoggerPrefix + $ScriptPrefix + '_METL_' + $TraceObject.Name + '_' + $temp[1] + 'Trace'
								}
							}Else{
								If(![string]::IsNullOrEmpty($Scenario)){
									$SingleTraceName = $ScriptPrefix + '_' + $Scenario + 'Scenario_METL_' + $TraceObject.Name + '_' + $temp[1] + 'Trace'
								}Else{
									$SingleTraceName = $ScriptPrefix + '_METL_' + $TraceObject.Name + '_' + $temp[1] + 'Trace'
								}
							}
							#support for custom flags in etl
							$SingleTraceFlags = $temp[2]
							if ([string]::IsNullOrEmpty($SingleTraceFlags))
							{
								$SingleTraceFlags = "0xffffffffffffffff"
							}
							$SingleTraceLevel = $temp[3]
							if ([string]::IsNullOrEmpty($SingleTraceLevel))
							{
								$SingleTraceLevel = "0xff"
							}
							LogDebug ("ETLMode=$Script:ETLmode | GUID=$SingleTraceGUID | TraceName=$SingleTraceName | TraceFlag=$SingleTraceFlags | TraceLevel=$SingleTraceLevel")
							$etlLogPath= ($TraceObject.LogFileName).Substring(0, ($TraceObject.LogFileName).LastIndexOf("\")+1) + $LogPrefix + $SingleTraceName + '.etl"'  
							Write-Progress -Activity ('Adding ' + $SingleTraceGUID + ' to ' + $TraceName) -Status 'Progress:' -PercentComplete ($i/$TraceObject.Providers.count*100)
							RunCommands "ETW" "logman update trace $TraceName -p `"$SingleTraceGUID`" $SingleTraceFlags $SingleTraceLevel -ets" -ThrowException:$False -ShowMessage:$False
							# logman update trace command is same for circular and newfile modes
						}
						else
						{ # Normal case
						$SingleTraceFlags = "0xffffffffffffffff"
						$SingleTraceLevel = "0xff"
						Write-Progress -Activity ('Adding ' + $Provider + ' to ' + $TraceName) -Status 'Progress:' -PercentComplete ($i/$TraceObject.Providers.count*100)
						RunCommands "ETW" "logman update trace $TraceName -p `"$Provider`" $SingleTraceFlags $SingleTraceLevel -ets" -ThrowException:$False -ShowMessage:$False
						}
						$i++
					}
					Write-Progress -Activity 'Updating providers' -Status 'Progress:' -Completed
				} 

				# If AutoLogger, update 'FileMax' and log folder
				If($StartAutoLogger.IsPresent -and $TraceObject.AutoLogger -ne $Null){
					If($TraceObject.MultipleETLFiles -eq 'yes'){
						$AutoLoggerTraceOjects = $CreatedMETLTraceList
					}Else{ # MultipleETLFiles='no'
						$AutoLoggerTraceOjects = $TraceObject
					}
					ForEach($AutoLoggerTraceOject in $AutoLoggerTraceOjects){
						LogDebug "Updating AutoLogger log path and FileMax for $($AutoLoggerTraceOject.TraceName)"
						If(Test-Path -Path $AutoLoggerTraceOject.AutoLogger.AutoLoggerKey){
							# Set maximum number of instances of the log file to 5
							Try{
								New-ItemProperty -Path $AutoLoggerTraceOject.AutoLogger.AutoLoggerKey -Name 'FileMax' -PropertyType DWord -Value 5 -force -ErrorAction SilentlyContinue | Out-Null
							}Catch{
								LogWarn "Unable to update $($AutoLoggerTraceOject.AutoLogger.AutoLoggerKey)"
							}
						}Else{
							LogDebug "WARNING: $($AutoLoggerTraceOject.AutoLogger.AutoLoggerKey) does not exist."
						}

						Try{
							If($Script:ETLmode -eq "newfile"){
								# For future use.

								#$a = "`"$(($AutoLoggerTraceOject.AutoLogger.AutoLoggerLogFileName).Substring(1, $($AutoLoggerTraceOject.AutoLogger.AutoLoggerLogFileName).Length-6))_%d.etl`""
								#Start-Sleep -Milliseconds 200
								#LogInfo "Updating log file to $a"
								#RunCommands "ETW" "logman update trace $($AutoLoggerTraceOject.AutoLogger.AutoLoggerSessionName) -o $a" -ThrowException:$False -ShowMessage:$True
							}Else{ # Normal(circular) case
								LogInfo "Updating log file to $($AutoLoggerTraceOject.AutoLogger.AutoLoggerLogFileName)"
								RunCommands "ETW" "logman update trace $($AutoLoggerTraceOject.AutoLogger.AutoLoggerSessionName) -o $($AutoLoggerTraceOject.AutoLogger.AutoLoggerLogFileName)" -ThrowException:$False -ShowMessage:$True
							}
						}Catch{
							LogWarn "Warning: unable to update logfolder for AutoLogger. Trace will continue with default location where this script is run."
						}
						$AutoLoggerTraceOject.Status = $TraceStatus.Started
					}
				}
				If($TraceObject.MultipleETLFiles -eq 'no'){
					$TraceObject.Status = $TraceStatus.Started
				}
			}
			'Perf' {
				LogDebug ('Enter [Perf] section in StartTraces. Starting ' + $TraceObject.TraceName)
				Try{
					StartPerfLog  $TraceObject  # This may throw an exception.
				}Catch{
					$TraceObject.Status = $TraceStatus.ErrorInStart
					$ErrorMessage = 'An exception happened during starting Performance Monitor log.'
					LogException $ErrorMessage $_
					Throw ($ErrorMessage)
				}
				$TraceObject.Status = $TraceStatus.Started
			}
			'Command' {
				LogDebug ('Enter [Command] section in StartTraces. Start processing ' + $TraceObject.TraceName)

				# Supported version check
				If($TraceObject.SupportedOSVersion -ne $Null){
					If(!(FwIsSupportedOSVersion $TraceObject.SupportedOSVersion)){
						LogWarn ($TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupportedOSVersion.OS + ' Build ' + $TraceObject.SupportedOSVersion.Build + '] Skipping this trace.')
						$TraceObject.Status = $TraceStatus.NotSupported
						Break # This is not critical and continue another traces.
					}
				}

				# Check if the command exists.
				$CommName = Get-Command $TraceObject.CommandName -ErrorAction SilentlyContinue	#we# check if command exists, before testing Path, i.e. if psr.exe was removed from system
				#we# If(!(Test-Path -Path (Get-Command $TraceObject.CommandName).Path)){
				If($CommName){
					If(!(Test-Path -Path $CommName.Path)){
						LogWarn ('Warning: ' + $TraceObject.CommandName + ' not found. Skipping ' + $TraceObject.Name)
						$TraceObject.Status = $TraceStatus.ErrorInStart
						Break
					}
				}

				# Normal case.
				If(!$StartAutoLogger.IsPresent){ 
					LogInfo "[$($TraceObject.Name)] Running $($TraceObject.CommandName) $($TraceObject.Startoption) (Wait=$($TraceObject.Wait))"
					If($TraceObject.Wait){
						$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.Startoption -RedirectStandardOutput $env:temp\StartProcess-output.txt -RedirectStandardError $env:temp\StartProcess-err.txt -PassThru -Wait
						If($Proccess.ExitCode -ne 0){
							Get-Content $env:temp\StartProcess-output.txt
							Get-Content $env:temp\StartProcess-err.txt
							Remove-Item $env:temp\StartProcess*
							$TraceObject.Status = $TraceStatus.ErrorInStart
							$ErrorMessage = ('An error happened in ' + $TraceObject.CommandName + ' (Error=0x' + [Convert]::ToString($Proccess.ExitCode,16) + ')')
							LogError $ErrorMessage
							Throw ($ErrorMessage)
						}
					}Else{
						If($TraceObject.WindowStyle -eq 'Minimized'){ # For trace with window minimized.
							$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.Startoption -WindowStyle Minimized
						}Else{
							$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.Startoption
						}
					}
					$TraceObject.Status = $TraceStatus.Started
				# AutoLogger case.
				}Else{ 
					# WPR -BootTrace does not support RS1 or earlier.
					If($TraceObject.Name -eq 'WPR'){
						LogDebug ('Enter [WPR] Current OS build=' + $OSBuild + ' WPR supported build=' + $WPRBootTraceSupportedVersion.Build)
						If($OSBuild -lt $WPRBootTraceSupportedVersion.Build){
							$TraceObject.Status = $TraceStatus.NotSupported
							Throw ($TraceObject.Name + ' -BootTrace is not supported on this OS. Supported Version is Windows ' + $WPRBootTraceSupportedVersion.OS  + ' Build ' + $WPRBootTraceSupportedVersion.Build + ' or later.')
						}
					}

					If($TraceObject.Name -eq 'Netsh'){
						LogDebug ('Enter [Netsh] Checking if there is running session.')
						$NetshSessionName = 'NetTrace'
						ForEach($Line in ($ETWSessionList -split "`r`n")){
							$Token = $Line -Split '\s+'
							If($Token[0].Contains($NetshSessionName)){
								$TraceObject.Status = $TraceStatus.ErrorInStart
								Throw ($TraceObject.Name + ' is already running.')
							}
						}
					}

					LogInfo ('[' + $TraceObject.Name + '] Running ' + $TraceObject.CommandName + ' ' + $TraceObject.AutoLogger.AutoLoggerStartOption)
					If($TraceObject.Wait){
						$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.AutoLogger.AutoLoggerStartOption -RedirectStandardOutput $env:temp\StartProcess-output.txt -RedirectStandardError $env:temp\StartProcess-err.txt -PassThru -Wait
						If($Proccess.ExitCode -ne 0){
							$TraceObject.Status = $TraceStatus.ErrorInStart
							Get-Content $env:temp\StartProcess-output.txt
							Get-Content $env:temp\StartProcess-err.txt
							Remove-Item $env:temp\StartProcess*
							$ErrorMessage = ('An error happened in ' + $TraceObject.CommandName + ' (Error=0x' + [Convert]::ToString($Proccess.ExitCode,16) + ')')
							LogError $ErrorMessage
							Throw ($ErrorMessage)
						}
					}Else{
						$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.AutoLogger.AutoLoggerStartOption
						# Unfortunately we don't know if it starts without error as the process is stared as background process.
					}
					$TraceObject.Status = $TraceStatus.Started
				}
			}
			'Custom' {
				LogDebug ('Enter [Custom] section in StartTraces. Start processing ' + $TraceObject.TraceName)
				# Supported version check
				If($TraceObject.SupportedOSVersion -ne $Null){
					If(!(FwIsSupportedOSVersion $TraceObject.SupportedOSVersion)){
						$ErrorMessage = $TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupportedOSVersion.OS + ' Build ' + $TraceObject.SupportedOSVersion.Build + '].'
						LogError $ErrorMessage
						$TraceObject.Status = $TraceStatus.NotSupported
						Throw ($ErrorMessage) 
					}
				}
				# Check if the trace has pre-start function. If so, just call it.
				Try{
					RunFunction $TraceObject.StartFunc -ThrowException:$True
				}Catch{
					$TraceObject.Status = $TraceStatus.ErrorInStart
					Throw "[$($TraceObject.StartFunc)] ERROR: $($_.Exception.Message)"
				}
				$TraceObject.Status = $TraceStatus.Started
			}
			Default {
				$TraceObject.Status = $TraceStatus.ErrorInStart
				LogError ('Unknown log type ' + $TraceObject.LogType)
			}
		}
		# Run post-start function for a component.
		$ComponentPostStartFunc = $TraceObject.Name + 'PostStart'
		Try{
			RunFunction $ComponentPostStartFunc -ThrowException:$True
		}Catch{
			LogWarn "[$($TraceObject.Name)] Error happens in pre-start function($ComponentPostStartFunc). Skipping this trace."
			LogException ("An error happened in " + $ComponentPostStartFunc) $_ $fLogFileOnly
			Continue
		}
	}

	If($CreatedMETLTraceList.Count -ne 0){
		ForEach($METLTraceObject in $CreatedMETLTraceList){
			LogDebug "Adding $($METLTraceObject.TraceName) to AutoLog" Yellow
			$AutoLog.Add($METLTraceObject)
		}
	}
	If($RemoveTraceList.Count -ne 0){
		ForEach($RemoveTraceObject in $RemoveTraceList){
			LogDebug "Removing $($RemoveTraceObject.TraceName) from AutoLog" Yellow
			$AutoLog.Remove($RemoveTraceObject) | Out-Null
		}
	}

	# Run pre-start function for scenario trace. #we# moved here
	ForEach($ScenarioName in $Scenario){
		RunFunction ($ScenarioName + 'ScenarioPostStart')
	}

	# Call common START task
	# Run collection of RegKey and Eventlogs before repro, defined by POD calls to FWaddRegItem and FWaddEvtLog _Start_
	if ($global:RegKeysModules.count -gt 0) { FWgetRegList $global:TssPhase }
	if ($global:EvtLogNames.count -gt 0) { FWgetEvtLogList $global:TssPhase }
	#$Script:RunningScenarioObjectList = GetRunningScenarioTrace
	If(($Scenario.Count -ne 0) -and [string]::IsNullOrEmpty($CommonTask)){
		ForEach($ScenarioName in $Scenario){
			$ScenarioTraceSetName = "$($ScenarioName)_ETWTracingSwitchesStatus"
			$Scenario_ETWTracingSwitchesStatus = Get-Variable $ScenarioTraceSetName -ValueOnly -ErrorAction Ignore
			ForEach($Key in $Scenario_ETWTracingSwitchesStatus.Keys){
				$Token = $Null
				$ValueName = $Null
				If($Key.contains('CommonTask')){
					$Token = $Key -split ' '
					LogDebug "Setting `'$($Token[1])`' to TaskType"
					$TaskType = $Token[1]
					Switch($TaskType){
						'Full'{
							RunFunction "FwCollect_BasicLog" -Stage "Before-Repro" -ThrowException:$False
						}
						'Mini'{
							RunFunction "FwCollect_MiniBasicLog" -Stage "Before-Repro" -ThrowException:$False
						}
						Default {
							$PODCommonStartFunc = $TaskType + "_Start_Common_Tasks"
							RunFunction $PODCommonStartFunc -ThrowException:$False
						}
					}
				}
			}
		}
	}ElseIf(![string]::IsNullOrEmpty($CommonTask)){ # -Start/-StartAutoLogger + -CommonTask without scenario case
		Switch($CommonTask){
			'Full'{
				RunFunction "FwCollect_BasicLog" -Stage  "Before-Repro" -ThrowException:$False
			}
			'Mini'{
				RunFunction "FwCollect_MiniBasicLog" -Stage "Before-Repro" -ThrowException:$False
			}
			Default {
				$PODCommonStartFunc = $CommonTask + "_Start_Common_Tasks"
				RunFunction $PODCommonStartFunc -ThrowException:$False
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function RemoveAutoLogger{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")
	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation
		}Catch{
			LogException "[RemoveAutoLogger] An exception happened in RunPreparation." $_
			CleanUpandExit
		}
	}

	$Count=0
	$EnabledAutoLoggerSessions = GetEnabledAutoLoggerSession
	ForEach($TraceObject in $EnabledAutoLoggerSessions){

		If($TraceObject.AutoLogger -eq $Null -or !$TraceObject.AutoLogger.AutoLoggerEnabled){
			Continue
		}

		LogDebug ('Processing deleting AutoLogger setting for ' + $TraceObject.Name)
		Try{
			Switch($TraceObject.LogType){
				'ETW' {
					LogInfo ('[ETW] Deleting ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
					logman stop $TraceObject.Name -ets | Out-Null
					logman delete $TraceObject.AutoLogger.AutoLoggerSessionName | Out-Null
					If($LASTEXITCODE -ne 0){
						Throw('Error happens in logman delete ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
					}
				}
				'Command' {
					Switch($TraceObject.Name) {
						'WPR' {
							LogInfo ('[' + $TraceObject.Name + '] Canceling BootTrace.')
							wpr.exe -BootTrace -cancelboot
							 If($LASTEXITCODE -ne 0){
								 $ErrorMssage = 'Error happens in wpr.exe -BootTrace -cancelboot'
								 LogError$ErrorMssage 
								 Throw($ErrorMssage)
							 }
						}
						'Xperf' {
							LogInfo ('[' + $TraceObject.Name + '] Canceling BootTrace.')
							$XperfCommand = Get-Command $TraceObject.CommandName -ErrorAction Ignore
							If($XperfCommand -eq $Null){
								LogError "Unable to find $XperfPath"
								CleanUpandExit
							}
							$Command = "$($TraceObject.CommandName) -BootTrace off"
							RunCommands "Xperf" $Command -ThrowException:$True -ShowMessage:$True -ShowError:$True
						}
						'Netsh' {
							 netsh trace show status  | Out-Null
							 If($LASTEXITCODE -ne 0){
								 LogDebug ('[' + $MyInvocation.MyCommand.Name + '] Netsh is not running') 
								 Continue
							 }
							 LogInfo ('[' + $TraceObject.Name + '] Running ' + $TraceObject.CommandName + ' ' + $TraceObject.AutoLogger.AutoLoggerStopOption)
							 Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.AutoLogger.AutoLoggerStopOption -PassThru -wait | Out-Null
						}
						'Procmon' {
							If($script:fDonotDeleteProcmonReg){
								Break
							}
							LogInfo ('[Procmon] Deleting Procmon registry keys(' + $TraceObject.AutoLogger.AutoLoggerKey + '\Start and Type)')
							Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction SilentlyContinue
							Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Type' -ErrorAction SilentlyContinue
						}
					}
				}
			}
		}Catch{
			LogException ('An exception happens during deleting AutoLogger setting for ' + $TraceObject.Name) $_
			Continue
		}
		$Count++
	}

	If($Count -eq 0){
		LogInfo "No AutoLogger session was found."
	}

	# Unregister a purge task in task scheduler if it exists.
	UnRegisterPurgeTask

	# Remove script parameters in AutoLog registry as no longer needed.
	RemoveParameterFromAutoLogReg

	EndFunc $MyInvocation.MyCommand.Name
}

Function StartPerfLog{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object]$TraceObject
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ('Starting Performance Monitor log.')
	If($TraceObject.LogType -ne 'Perf' -or $TraceObject.Providers.Length -eq 0){
		$ErrorMessage = ('Invalid object(LogType:' + $TraceObject.LogType + ') was passed to StartPerfLog.')
		LogError $ErrorMessage
		Throw($ErrorMessage)
	}

	$PerfCounters = $Null
	ForEach($PerfCounter in $TraceObject.Providers){
		$PerfCounters += "`"" + $PerfCounter + "`""  + " "
	}
	
	If($TraceObject.Name -eq 'PerfMon'){
		$Interval = $Script:PerfMonInterval
	}ElseIf($TraceObject.Name -eq 'PerfMonLong'){
		$Interval = $Script:PerfMonLongInterval
	}

	$Perfcmd = "logman create counter " + $TraceObject.Name + " -o `"" + $TraceObject.LogFileName + "`" -si $Interval -c $PerfCounters" # | Out-Null"
	LogInfo "[$($TraceObject.Name)] Running $Perfcmd"
	Try{
		Invoke-Expression $Perfcmd -ErrorAction Stop | Out-Null
	}Catch{
		$ErrorMessage = ('An exception happened in logman create counter.')
		LogException ($ErrorMessage) $_ $fLogFileOnly
		Throw($ErrorMessage)
	}

	logman start $TraceObject.Name  | Out-Null
	If($LASTEXITCODE -ne 0){
		$ErrorMessage = ('An error happened during starting ' + $TraceObject.Name + '(Error=' + [Convert]::ToString($LASTEXITCODE,16) + ')')
		LogError $ErrorMessage
		Throw($ErrorMessage)
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CompressLogIfNeededAndShow{
	EnterFunc $MyInvocation.MyCommand.Name
	# Fix(#224)
	if (!($global:ParameterArray -contains 'noZip') -and !($global:ParameterArray -contains 'noCab')) {  # skip compressing results if -noZip or -noCab

		If(!$global:BoundParameters.ContainsKey('Discard')){
			# 1. In case of scenario trace, create Zip file suffix using the scenario name.
			If($Script:RunningScenarioObjectList.Count -ne 0){
				$script:LogZipFileSuffixScn = $Script:RunningScenarioObjectList.ScenarioName
				$script:LogZipFileSuffix = $script:LogZipFileSuffixScn
			}ElseIf(![String]::IsNullOrEmpty($Scenario)){ # Case for -StartNoWait + no trace in scenario
				$Token = $Scenario -split ','
				ForEach($ScenarioName in $Token){
					$script:LogZipFileSuffix = $ScenarioName + '_'
				}
				$script:LogZipFileSuffix = $script:LogZipFileSuffix  -replace "_$",""
			}

			# 2. In case of -AddDescription, ask user to input brief description and set it to $Description
			If($global:ParameterArray -Contains 'AddDescription' -and !($global:ParameterArray -Contains 'noAsk')){
				While($True){
					Write-Host ""
					LogInfo "Enter a brief description of the issue (Press Enter when done)"
					Write-Host "Example:"
					Write-Host "  - Good"
					Write-Host "  - Error case"
					Write-Host "  - Failing Repro"
					Write-Host '=> Special characters/symbols(#<>*_/\{}$+%`|=@\") are not allowed to use.'
					FwPlaySound
					$Description = Read-Host "Description"
					If($Description.Length -gt 40 -or $Description.Length -eq 0){
						LogInfo "Enter problem description within 40 characters"
					}ElseIf($Description -match '[#<>\*_\/\\\{\}\$\?\+%`\|=@"]'){
						LogInfo "Below symbols are not allowed. Please enter the description again." 
						LogInfo '=> Illegal characters/symbols: #<>*_/\{}$+%`|=@\"' "Yellow"
					}Else{
						Break
					}
				}
				# Replace space(' ') with dash('-')
				$Description = $Description -replace (' ','-')
			}

			$LongZipFileName = (Split-Path $global:LogFolder -Leaf) + ".zip"

			# -Scenario case. Append scenario name.
			If(![string]::IsNullOrEmpty($script:LogZipFileSuffix)){ 
				$LongZipFileName = $LongZipFileName -Replace(".zip", "$script:LogZipFileSuffix.zip")
			# -CollectLog case. Append collected log component name.
			}ElseIf($global:ParameterArray -contains 'CollectLog'){
				$LogNames = $CollectLog -replace (",","-")
				$CollectLogDescription = "Log"
				ForEach($ComponentName in $CollectLog){
					$CollectLogDescription = $CollectLogDescription + '-' + $ComponentName
				}
				$LongZipFileName = $LongZipFileName -Replace(".zip", "$CollectLogDescription.zip")
			}

			# -Xray case. Append xray_INFO or xray_ISSUES-FOUND
			If($global:ParameterArray -Contains 'xray'){
				$XrayInfoFile =  Get-ChildItem $global:LogFolder "xray_INFO*" -Recurse
				$XrayIssueFoundFile = Get-ChildItem $global:LogFolder "xray_ISSUES-FOUND*" -Recurse
				If($XrayInfoFile.Count -ne 0){
					$XrayDescription = "_xray_INFO"
				}
				If($XrayIssueFoundFile.Count -ne 0){
					$XrayDescription = "_xray_ISSUES-FOUND"
				}
				LogDebug "XrayInfoFile count = $($XrayInfoFile.Count) $XrayIssueFoundFile count = $($XrayIssueFoundFile.Count)"
				$LongZipFileName = $LongZipFileName -Replace(".zip", "$XrayDescription.zip")
			}

			# -AddDescription case. Append brief description of the issue.
			If($global:ParameterArray -Contains 'AddDescription' -and !($global:ParameterArray -Contains 'noAsk')){
				$LongZipFileName = $LongZipFileName -Replace(".zip", "-$Description.zip")
			}

			# 3. Create a full path of zip file
			$zipDestinationPath = (Split-Path $global:LogFolder -Parent) + "\" + $LongZipFileName
			LogDebug "LogZipFileSuffix = $script:LogZipFileSuffix"
			LogDebug "zipDestinationPath = $zipDestinationPath"

			# 4. If the created file path already exists(this could happen -stop without -AddDescription), rename the existing file.
			If(Test-Path $zipDestinationPath){
				# Case where destination zip file already exists.
				$DateSuffix = "$(Get-Date -f yyyy-MM-dd.HHmm.ss)"  
				$BackupZipPath = $zipDestinationPath -replace (".zip", "$DateSuffix.zip")
				LogInfo "Moving $zipDestinationPath to $BackupZipPath"
				Move-Item $zipDestinationPath $BackupZipPath -ErrorAction SilentlyContinue
			}
		}
		Write-Host ""

		# 5. Before compressing log folder, close transcript.
		$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
		LogInfoFile "=========== End of AutoLog Data collection: $TimeUTC UTC ==========="
		Close-Transcript -ShowMsg

		# 6. Records all errors in $Error variable.
		If($Error.Count -ne 0){
			$Error | Out-File -FilePath $global:ErrorVariableFile
		}

		If(!$global:BoundParameters.ContainsKey('Discard')){
			# 7. Finally, compress log folder here.
			If(!$Script:StopInError){
				$ZipFileName = [System.IO.Path]::GetFileName($zipDestinationPath)
				LogInfo "[$($MyInvocation.MyCommand.Name)] Compressing $global:LogFolder folder(zip=$ZipFileName). This might take a while."
				Start-Sleep -s 5 #give some time for logging to complete before starting zip
				Try{
					Add-Type -Assembly 'System.IO.Compression.FileSystem'
					[System.IO.Compression.ZipFile]::CreateFromDirectory($global:LogFolder, $zipDestinationPath)
				}Catch{
					$ErrorMessage = 'An exception happened during compressing log folder' + "`n" + $_.Exception.Message
					LogWarn $ErrorMessage
					LogInfo "[$MyInvocation.MyCommand.Name] Please compress $global:LogFolder manually and send it to MS workspace upload site."
					LogException $ErrorMessage $_ $fLogFileOnly
					Return # Return here to prevent the deletion of source folder that is performed later.
				}
			}Else{
				LogInfo "[$MyInvocation.MyCommand.Name] Skipping compressing folder as an error happened in stop."
			}

			# 8. In case of Remoting, copy zip file to file share.
			If((IsStart) -and $global:IsRemoting -and $global:BoundParameters.ContainsKey('RemoteLogFolder')){
				$RemoteLogFolder = $global:BoundParameters['RemoteLogFolder']
				LogInfo "[$MyInvocation.MyCommand.Name] Copying $zipDestinationPath to $RemoteLogFolder"
				Try{
					Copy-Item $zipDestinationPath $RemoteLogFolder
				}Catch{
					LogError "Failed to copy $zipDestinationPath to $RemoteLogFolder"
				}
				$zipFileName = [System.IO.Path]::GetFileName($zipDestinationPath)
				$RemoteZiplogFileName = $RemoteLogFolder + "\" + $zipFileName
				If(Test-Path $RemoteZiplogFileName){
					Write-Host "==> Please send all zip files in $RemoteLogFolder to our upload site." -ForegroundColor Cyan
					$IsCopyToRemoteShareSucceeded = $True
				}Else{
					LogInfo "==> Please send $zipDestinationPath to our upload site." -ForegroundColor Cyan
				}
			}ElseIf($Script:StopInError){
				LogWarn "ERROR(s) happened during stopping traces."
				LogInfo "==> Please send below log files to our upload site." "Cyan"
				LogInfo "	- All log files in $global:LogFolder"
				LogInfo "	- $global:TranscriptLogFile"
				LogInfo "	- $global:ErrorLogFile"
			}Else{
				LogInfo "[$($MyInvocation.MyCommand.Name)] Please send $zipDestinationPath to our MS upload site."
			}
		}
		# 9. Delete original log folder to save free space.
		If(!$Script:StopInError){
			LogDebug "Deleting $global:LogFolder"
			Try{
				Remove-Item $global:LogFolder -Recurse -Force -ErrorAction Stop | Out-Null
			}Catch{
				LogInfo "Please remove $global:LogFolder manually"
				$ErrorMessage = 'An exception happened during removing log folder' + "`n" + $_.Exception.Message
				LogException $ErrorMessage $_ $fLogFileOnly
			}
		}
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe (Split-Path $global:LogFolder -parent) }
	}Else{
		If(!$global:BoundParameters.ContainsKey('Discard')){
			LogInfo "Logs were stored in $global:LogFolder"
			LogInfo "Please compress $global:LogFolder manually and send it to MS workspace upload site." "Cyan"
		}
		$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
		LogInfoFile "=========== End of AutoLog Data collection: $TimeUTC UTC ==========="
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe $global:LogFolder }
	}

	# 10. In case of remoting, also display remote share folder.
	If($IsCopyToRemoteShareSucceeded){
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe $RemoteLogFolder }
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ShowTraceResult{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[PSObject]]$TraceObjectList,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('Start','Stop')]
		[String]$FlagString,
		[Parameter(Mandatory=$True)]
		[Bool]$fAutoLogger
	)
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Flag=$FlagString, fAutoLogger=$fAutoLogger"
	If($FlagString -eq 'Start'){
		$Status = $TraceStatus.Started
		If($fAutoLogger){
			$Message = 'Following AutoLogger session(s) were enabled:'
		}Else{
			$Message = 'Following trace(s) are started:'
		}
	}ElseIf($FlagString -eq 'Stop'){
		$Status = $TraceStatus.Stopped
		$Message = 'Following trace(s) are successfully stopped:'
	}

	Write-Host ""
	Write-Host '********** RESULT **********'
	$TraceObjects = $TraceObjectList | Where-Object{$_.Status -eq $Status}
	If($TraceObjects -ne $Null){
		Write-Host ($Message)
		ForEach($TraceObject in $TraceObjects){
			If(!$fAutoLogger){
				Write-Host ('	- ' + $TraceObject.TraceName)
			}Else{
				Write-Host ('	- ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
			}
		}
	}Else{
		If($FlagString -eq 'Start'){
			Write-Host ('No traces are started.')
		}ElseIf($FlagString -eq 'Stop'){
			Write-Host ('No traces are stopped.')
		}
	}

	$ErrorTraces = $TraceObjectList | Where-Object{$_.Status -ne $Status -and $_.Status -ne $TraceStatus.NoStopFunction -and $_.Status -ne $TraceStatus.NotSupported}
	If($ErrorTraces -ne $Null){
		$Script:StopInError = $True # This will be used in CompressLogIfNeededAndShow()
		LogInfo ('[Error] The following trace(s) failed:')
		ForEach($TraceObject in $ErrorTraces){
			$StatusString = ($TraceStatus.GetEnumerator() | Where-Object {$_.Value -eq $TraceObject.Status}).Key
			If(!$fAutoLogger){
				Write-Host ('	- ' + $TraceObject.TraceName + "($StatusString)") -ForegroundColor Red
			}Else{
				Write-Host ('	- ' + $TraceObject.AutoLogger.AutoLoggerSessionName + "($StatusString)") -ForegroundColor Red
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function RunSetWer{
	EnterFunc $MyInvocation.MyCommand.Name
	$WERRegKey = "HKLM:Software\Microsoft\Windows\Windows Error Reporting\LocalDumps"
	FwPlaySound
	$DumpFolder = Read-Host -Prompt "Enter dump folder name"
	If(!(Test-Path -Path $DumpFolder -PathType Container)){
		Try{
			LogInfo ("Creating $DumpFolder.")
			New-Item $DumpFolder -ItemType Directory -ErrorAction Stop | Out-Null
		}Catch{
			LogException ("Unable to create $DumpFolder") $_
			CleanUpandExit
		}
	}

	If(!(Test-Path -Path $WERRegKey)){
		Try{
			LogInfo ("Creating $WERRegKey.")
			New-Item $WERRegKey -ErrorAction Stop | Out-Null
		}Catch{
			LogException ("Unable to create $WERRegKey") $_
			CleanUpandExit
		}
	}

	Try{
		LogInfo ("Setting `'DumpType`' to `'2`'.")
		Set-ItemProperty -Path $WERRegKey -Name 'DumpType' -value 2 -Type DWord -ErrorAction Stop | Out-Null
		LogInfo ("Setting `'DumpFolder`' to `'$DumpFolder`'")
		Set-ItemProperty -Path $WERRegKey -Name 'DumpFolder' -value $DumpFolder -Type ExpandString -ErrorAction Stop | Out-Null
	}Catch{
		LogException ("Unable to set DumpType or DumpFolder") $_
		CleanUpandExit
	}
	LogInfo ("WER (Windows Error Reporting) settings are set properly.")
	EndFunc $MyInvocation.MyCommand.Name
	CleanUpandExit
}

Function RunUnSetWer{
	EnterFunc $MyInvocation.MyCommand.Name
	$WERRegKey = "HKLM:Software\Microsoft\Windows\Windows Error Reporting\LocalDumps"
	If(Test-Path -Path $WERRegKey){
		Try{
			LogInfo ("Deleting $WERRegKey.")
			Remove-Item $WERRegKey -ErrorAction Stop | Out-Null
		}Catch{
			LogException ("Unable to delete $WERRegKey") $_
			CleanUpandExit
		}
	}Else{
			LogInfo ("INFO: `'$WERRegKey`' is already deleted.")
	}
	LogInfo ("Disabling WER (Windows Error Reporting) settings is completed.")
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessCollectLog{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("Started with -CollectLog $CollectLog")

	If([String]::IsNullOrEmpty($global:TssPhase)) { $global:TssPhase = "_Collect_" }
	
	LogInfoFile "======================== Start of Collect ========================"
	
	$RequestedLogs = $CollectLog -Split '\s+'

	If (("Basic" -notin ($RequestedLogs)) -and ("Full" -notin ($RequestedLogs))){
		CollectBasicLog
	}

	ForEach($RequestedLog in $RequestedLogs){

		If("Basic" -eq $RequestedLog){
			$global:RunningCollect = "Basic";
		}Else{
			$global:RunningCollect = "Full";
		}

		$ComponentLogCollectionFunc = 'Collect' + $RequestedLog + 'Log'
		$Commandobj = Get-Command $ComponentLogCollectionFunc -CommandType Function -ErrorAction Ignore # Ignore exception

		If($Commandobj -ne $Null){
			Try{
				LogInfo "[$($MyInvocation.MyCommand.Name)] Calling log collection function ($ComponentLogCollectionFunc)"
				& $ComponentLogCollectionFunc
			}Catch{
				LogWarn ("Exception happened in $ComponentLogCollectionFunc.")
				LogException ("An error happened in $ComponentLogCollectionFunc") $_ $fLogFileOnly
				Continue
			}
		}Else{
			Continue
		}
		LogInfoFile "======================== End of Collect =========================="
	}
	CompressLogIfNeededAndShow
	CleanUpandExit
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessHelp {
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		Write-Output "-Usage:"
		Write-Output "-----------------------------------------------------------------------------------------------------------------------------------------------------------"
		Write-Output ".\AutoLog.ps1 -CollectLog Basic                                       - Collect basic logs"
		Write-Output ".\AutoLog.ps1 -CollectLog Full                                        - Collect full additional logs"
		Write-Output ".\AutoLog.ps1 -CollectLog Wu                                          - Collect basic logs and Windows Update logs"
		Write-Output ".\AutoLog.ps1 -CollectLog Defender                                    - Collect basic logs and Defender logs"
		Write-Output ".\AutoLog.ps1 -CollectLog Defender -DefenderDurinMin <int in minutes> - Collect basic logs, Defender logs and Network traces for the specified duration"
		Write-Output "----------------------------------------------------------------------------------------------------------------------------------------------------------"
	}Catch{
		LogInfo "[$($MyInvocation.MyCommand.Name)] An exception happened in ProcessHelp"
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CheckParameterCompatibility{
	EnterFunc $MyInvocation.MyCommand.Name
	If($Netsh.IsPresent -and ($NetshScenario -ne $Null)){
		$Message = 'ERROR: Cannot specify -Netsh and -NetshScenario at the same time.'
		LogInfo ($Message) "Red"
		Throw $Message
	}

	If(($global:ParameterArray -contains 'WPR') -and ($global:ParameterArray -contains 'Xperf')){
		$Message = 'ERROR: Cannot specify -WPR and -Xperf at the same time.'
		LogInfo ($Message) "Red"
		Throw $Message
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function VersionInt($verString){
	EnterFunc $MyInvocation.MyCommand.Name
	$verSplit = $verString.Split([char]0x0a, [char]0x0d, '.')
	$vFull = 0; $i = 0; $vNum = 256 * 256 * 256
	while ($vNum -gt 0) { $vFull += [int] $verSplit[$i] * $vNum; $vNum = $vNum / 256; $i++ };
	EndFunc ($MyInvocation.MyCommand.Name + "($vFull)")
	return $vFull
}

Function CreateStartCommandforBatch{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[PSObject]]$TraceObjectList
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If($TraceObjectList -eq $Null){
		LogError"There is no trace in AutoLog."
		retrun
	}

	If($StartAutoLogger.IsPresent){
		$BatFileName = $StartAutoLoggerBatFileName
	}

	Try{
		$BatchFolder = Split-Path $BatFileName -Parent
		FwCreateLogFolder $BatchFolder
	}Catch{
		LogException("Unable to create $BatchFolder") $_
		CleanUpandExit
	}

	If(!$StartAutoLogger.IsPresent){
		If($LogFolderName -eq ""){
			$LogFolder = $LogFolder -replace ".*\Desktop","%USERPROFILE%\Desktop"
		}
		Write-Output("MD $LogFolder") | Out-File $BatFileName -Encoding ascii -Append
	}Else{
		Write-Output("MD $AutoLoggerLogFolder") | Out-File $BatFileName -Encoding ascii -Append
	}

	ForEach($TraceObject in $TraceObjectList){
		Switch($TraceObject.LogType){
			'ETW' {
				If($StartAutoLogger.IsPresent){
					$TraceName = $TraceObject.AutoLogger.AutoLoggerSessionName
				}Else{	
					$TraceName = $TraceObject.TraceName
				}
				$LogFileName = $TraceObject.LogFileName -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."

				If($LogFolderName -eq ""){
					$LogFileName = $LogFileName -replace ".*\Desktop","`"%USERPROFILE%\Desktop"
				}

				$Commandline = "logman create trace $TraceName -ow -o $LogFileName -mode Circular -bs 64 -f bincirc -max $Script:ETLMaxSize -ft 60 -ets"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
				
				ForEach($Provider in $TraceObject.Providers){
					$Commandline = "logman update trace $TraceName -p $Provider 0xffffffffffffffff 0xff -ets"
					LogInfo ("Adding `'$CommandLine`' to $BatFileName")
					Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
				}

				If($StartAutoLogger.IsPresent -and $TraceObject.AutoLogger -ne $Null){
					$Commandline = "logman update trace $TraceName -o $($TraceObject.AutoLogger.AutoLoggerLogFileName)"
					LogInfo ("Adding `'$CommandLine`' to $BatFileName")
					Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append

					$AutoLoggerKey = $TraceObject.AutoLogger.AutoLoggerKey -replace ":",""  # Convert "HKLM:" => "HKLM\"
					$Commandline = "REG ADD $AutoLoggerKey /V FileMax /T REG_DWORD /D 5 /F"
					LogInfo ("Adding `'$CommandLine`' to $BatFileName")
					Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
				}
			}
			'Perf' {
			   ForEach($PerfCounter in $TraceObject.Providers){
				   $AllCounters += "`"" + $PerfCounter + "`""  + " "
			   }
			   $LogFileName = $TraceObject.LogFileName -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."

			   If($LogFolderName -eq ""){
				   $LogFileName = $LogFileName -replace ".*\Desktop","%USERPROFILE%\Desktop"
			   }

			   If($global:ParameterArray -contains 'PerfmonLong'){
				   $PerflogInterval = $PerflogLongInterval
			   }

			   $Commandline = "logman create counter " + $TraceObject.Name + " -o `"" + $LogFileName + "`" -si $PerflogInterval -c $AllCounters"
			   LogInfo ("Adding `'$CommandLine`' to $BatFileName")
			   Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append

			   $Commandline = "logman start $($TraceObject.Name)"
			   LogInfo ("Adding `'$CommandLine`' to $BatFileName")
			   Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
			}
			'Command' {
				If(!$StartAutoLogger.IsPresent){
					$StartOptionWithoutSuffix = $($TraceObject.Startoption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."
				}Else{
					$StartOptionWithoutSuffix = $($TraceObject.AutoLogger.AutoLoggerStartOption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."
				}
				$CommandLine = "Start $($TraceObject.CommandName) $StartOptionWithoutSuffix"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
			}
			Default {
				LogWarn ("-CreateBatFile does not support command for $($TraceObject.TraceName)")
				Continue
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CreateStopCommandforBatch{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[PSObject]]$TraceObjectList
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If($StartAutoLogger.IsPresent){
		$BatFileName = $StopAutoLoggerBatFileName
	}Else{
		LogInfo ("Adding `'Pause`' to $BatFileName")
		Write-Output("") | Out-File $BatFileName -Encoding ascii -Append
		Write-Output("Pause") | Out-File $BatFileName -Encoding ascii -Append
		Write-Output("") | Out-File $BatFileName -Encoding ascii -Append
	}

	ForEach($TraceObject in $TraceObjectList){
		Switch($TraceObject.LogType){
			'ETW' {
				$CommandLine = "logman stop $($TraceObject.TraceName) -ets"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append

				If($StartAutoLogger.IsPresent){
					$CommandLine = "logman delete $($TraceObject.AutoLogger.AutoLoggerSessionName)"
					LogInfo ("Adding `'$CommandLine`' to $BatFileName")
					Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
				}
			}
			'Perf' {
				$CommandLine = "logman stop $($TraceObject.Name) & logman delete $($TraceObject.Name)"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
			}
			'Command' {
				If(!$StartAutoLogger.IsPresent){
					$StopOptionWithoutSuffix = $($TraceObject.StopOption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."

				}Else{
					$StopOptionWithoutSuffix = $($TraceObject.AutoLogger.AutoLoggerStopOption) -replace "-[0-9]+-[0-9]+-[0-9]+\.[0-9]+\.[0-9]+.","."
				}
				$CommandLine = "$($TraceObject.CommandName) $StopOptionWithoutSuffix"
				LogInfo ("Adding `'$CommandLine`' to $BatFileName")
				Write-Output($CommandLine) | Out-File $BatFileName -Encoding ascii -Append
			}
			Default {
				LogWarn ("-CreateBatFile does not support command for $($TraceObject.TraceName)")
				Continue
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpNetshProperty{
	EnterFunc $MyInvocation.MyCommand.Name
		
	# Issue#321
	# Adjust parameter in case of Server Core
	If($global:IsServerCore){
		LogInfo "AutoLog is running on Server Core and adjusting netsh parameters"
		# SrvCORE does not work with trace scenario=InternetClient_dbg etc. Hence, replace original scenario name with 'InternetServer'
		If($global:BoundParameters.ContainsKey('NetshScenario')){
			$ScenarioNames = $global:BoundParameters['NetshScenario']
			$global:BoundParameters.Remove('NetshScenario') | Out-Null
			$global:BoundParameters.Add('NetshScenario','InternetServer')
		}
		
		# Remove provider
		If($global:BoundParameters.ContainsKey('NetshOptions')){
			$NetshOptions = $global:BoundParameters['NetshOptions']
			[System.Collections.ArrayList]$Token = $NetshOptions -split ' '
			While($Token -match "provider=*"){
			   For($i=0;$i -lt $Token.Count;$i++){
				   If($Token[$i] -like "provider=*"){
					   $Token.Remove($Token[$i]) # Remove entry for 'Provider=XXX'
					   Break
				   }
				}
			}
			$AdjustedNetshOptions = $Token -join ' '
			$global:BoundParameters.Remove('NetshOptions') | Out-Null
			$global:BoundParameters.Add('NetshOptions',$AdjustedNetshOptions)
		}
	}

	# Initialize max log size for netsh with default value(2GB)
	$NetshMaxSize = 2048

	# Update max log size fo Netsh if NetshMaxSize is configured.
	If($global:BoundParameters.containskey('NetshMaxSize')){
		$NetshMaxSize = $global:BoundParameters['NetshMaxSize']
	}Else{
		# See if max size is configured from tss_config.cfg
		$MaxSizeFromConfig = $FwConfigParameters['_NetshMaxSize']
		If(![string]::IsNullOrEmpty($MaxSizeFromConfig)){
			LogDebug "Use NetshMaxSize($MaxSizeFromConfig) configured in tss_config.cfg"
			$NetshMaxSize = $MaxSizeFromConfig
		}
	}

	# Update $LogSizeInGB that is used in CalculateLogSize() later.
	LogDebug "NetshMaxSize=$NetshMaxSize MB"
	$LogSizeInGB.Netsh = $NetshMaxSize / 1024
	$LogSizeInGB.NetshScenario = ($NetshMaxSize / 1024) + 4

	# Compose a log file name for netsh and add it to 'traceFile='
	If($global:BoundParameters.containskey('NetshScenario')){
		$NetshScenarioArray = $global:BoundParameters['NetshScenario']
		# dbg/wpp scenarios:
		$SupportedNetshScenarios = Get-ChildItem 'HKLM:System\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs\WPPTrace\HelperClasses'
		# normal scenarios: #we# [waltere] added
		$SupportedNetshScenarios += Get-ChildItem 'HKLM:System\CurrentControlSet\Control\NetTrace\Scenarios'
		#$RequestedScenarios = $NetshScenario -Split ','
		$i=0
		ForEach($RequestedScenario in $NetshScenarioArray){
			$fFound=$False
			ForEach($SupportedNetshScenario in $SupportedNetshScenarios){
				If($RequestedScenario.ToLower() -eq $SupportedNetshScenario.PSChildName.ToLower()){
					$fFound=$True
					If($i -eq 0){
						$SenarioString = $SupportedNetshScenario.PSChildName
					}Else{
						$SenarioString = $SenarioString + ',' + $SupportedNetshScenario.PSChildName
					}
				}
			}
			If(!$fFound){
				LogInfo "ERROR: Unable to find scenario `"$RequestedScenario`" for -NetshScenario. Supported scenarios for -NetshScnario are:" "Red"
				ForEach($SupportedNetshScenario in $SupportedNetshScenarios){
					Write-Host ("  - " + $SupportedNetshScenario.PSChildName)
				}
				CleanUpandExit
			}
			$i++
		}

		LogInfo "Scenario string for NetshScenario is $SenarioString"
		$SenarioStringForLog = $SenarioString.Replace(",","-")
		$NetshScenarioLogFile = "$global:LogFolder\$($LogPrefix)packetcapture-$SenarioStringForLog.etl" #we#[waltere] changed NetSH names for LogRaker
		$NetshProperty.LogFileName = $NetshScenarioLogFile
		$NetshProperty.AutoLogger.AutoLoggerLogFileName = "`"$AutoLoggerLogFolder\$($LogPrefix)packetcapture-$SenarioStringForLog-AutoLogger.etl`""

		# Update secenario and log file name
		$NetshProperty.StartOption = $NetshProperty.StartOption + " scenario=$SenarioString traceFile=$($NetshProperty.LogFileName)"
		$NetshProperty.AutoLogger.AutoLoggerStartOption = $NetshProperty.AutoLogger.AutoLoggerStartOption + " scenario=$SenarioString traceFile=$($NetshProperty.AutoLogger.AutoLoggerLogFileName)"
	}Else{ # Non scenario trace case
		# Issue#362
		$NetshProperty.StartOption = $NetshProperty.StartOption + " traceFile=$($NetshProperty.LogFileName)"
		$NetshProperty.AutoLogger.AutoLoggerStartOption = $NetshProperty.AutoLogger.AutoLoggerStartOption + " traceFile=$($NetshProperty.AutoLogger.AutoLoggerLogFileName)"
	}

	# capture=yes/no
	If($global:BoundParameters.containskey('noPacket')){
		$Capture="capture=no"
	}Else{
		$Capture="capture=yes"
	}

	# Add capture=yes/no, report=yes/no and max log size
	$NetshProperty.StartOption = $NetshProperty.StartOption + " $Capture $Script:NetshTraceReport maxSize=$NetshMaxSize"
	$NetshProperty.AutoLogger.AutoLoggerStartOption = $NetshProperty.AutoLogger.AutoLoggerStartOption + " $Capture $Script:NetshTraceReport maxSize=$NetshMaxSize"

	# Add NetshOptions if it is configured
	$NetshOptions = $global:BoundParameters['NetshOptions']
	If(![string]::IsNullOrEmpty($NetshOptions)){
		# Issue#321 - Adjust netsh parameter for Windows Server 2012 or earlier
		If($OSBuild -le 9200){
			[System.Collections.ArrayList]$Token = $NetshOptions -split ' '
			For($i=0;$i -lt $Token.Count;$i++){
				If($Token[$i] -like "capturetype=*"){
					$Token.Remove($Token[$i]) # Remove entry for 'capturetype=XXX'
				}
			}
			$NetshOptions = $Token -join ' '
			$global:BoundParameters.Remove('NetshOptions') | Out-Null
			$global:BoundParameters.Add('NetshOptions',$NetshOptions)
			LogDebug "OSBuild=$OSBuild, NetshOptions=$NetshOptions"
		}
		$NetshProperty.StartOption = $NetshProperty.StartOption + " " + $NetshOptions
		$NetshProperty.AutoLogger.AutoLoggerStartOption = $NetshProperty.AutoLogger.AutoLoggerStartOption + " " + $NetshOptions
	}
	LogDebug "Netsh option = $($NetshProperty.StartOption)"
	LogDebug "Netsh AutoLogger option = $($NetshProperty.AutoLogger.AutoLoggerStartOption)"
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpXperfProperty{
	EnterFunc $MyInvocation.MyCommand.Name

	# Load parameters
	$Xperf = $global:BoundParameters['Xperf']
	$XperfMaxFile = $global:BoundParameters['XperfMaxFile']
	$XperfTag = $global:BoundParameters['XperfTag']
	$XperfPIDs = $global:BoundParameters['XperfPIDs']
	$XperfOptions = $global:BoundParameters['XperfOptions']

	# AutoLogger for SMB2, SBSL and Leak is not supported at this point.
	If($StartAutoLogger.IsPresent -and ($Xperf -eq 'SMB2' -or $Xperf -eq 'SBSL' -or $Xperf -eq 'Leak')){
		LogError "AutoLogger for `'$Xperf`' is not supported."
		CleanUpandExit
	}

	# Set DisablePagingExecutive.
	$RegValues = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -ErrorAction Ignore
	If($RegValues.DisablePagingExecutive -ne 1){
		$Command = "REG ADD `"HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management`" -v DisablePagingExecutive -d 0x1 -t REG_DWORD -f"
		Runcommands "Xperf" $Command
	}

	# Add a profile name to log file name.
	$XperfLogFile = "$global:LogFolder\$($LogPrefix)Xperf_$Xperf.etl"
	$XperfProperty.LogFileName = $XperfLogFile

	LogDebug "Updating Xperf option with `'$Xperf`' profile"
	If([String]::IsNullOrEmpty($XperfMaxFile) -or $XperfMaxFile -eq 0){
		$XperfMaxFile = 2048
	}
	$XperfParams = "-BufferSize 1024 -MinBuffers 256 -MaxBuffers 1024 -MaxFile $XperfMaxFile -FileMode Circular -f $global:LogFolder\xperf.etl"

	# Set stop option
	$XperfProperty.StopOption = "-stop -d $($XperfProperty.LogFileName)"

	# Start option and stop option for SMB2, SBSL and Leak
	Switch($Xperf) {
		'CPU'	 {$XperfProperty.StartOption = "-on PROC_THREAD+Latency+LOADER+Profile+interrupt+dpc+DISPATCHER+CSwitch+Power -stackWalk CSwitch+Profile+ReadyThread $XperfParams"}
		'General' {$XperfProperty.StartOption = "-on Base+Latency+CSwitch+PROC_THREAD+LOADER+Profile+interrupt+dpc+DISPATCHER+NETWORKTRACE+FileIO+Power+DISK_IO+DISK_IO_INIT+filename+FILE_IO+FILE_IO_INIT+flt_io_init+flt_io+flt_fastio+flt_io_failure+VIRT_ALLOC+POOL+REGISTRY+DRIVERS -stackWalk CSwitch+Profile+ReadyThread+ThreadCreate+SyscallEnter+DiskReadInit+DiskWriteInit+DiskFlushInit+FileRead+FileWrite+FileCreate+FileDelete+minifilterpreopinit+minifilterpostopinit+PoolAlloc+PoolAllocSession+PoolFree+PoolFreeSession+VirtualAlloc+VirtualFree $XperfParams"}
		'Disk'	{$XperfProperty.StartOption = "-on PROC_THREAD+LOADER+Profile+interrupt+dpc+DISK_IO+DISK_IO_INIT+filename+FILE_IO+FILE_IO_INIT+flt_io_init+flt_io+flt_fastio+flt_io_failure -stackwalk profile+DiskReadInit+DiskWriteInit+DiskFlushInit+FileRead+FileWrite+FileCreate+FileDelete+minifilterpreopinit+minifilterpostopinit $XperfParams"}
		'Memory'  {$XperfProperty.StartOption = "-on Base+CSwitch+POOL -stackwalk Profile+PoolAlloc+PoolAllocSession+PoolFree+PoolFreeSession+VirtualAlloc $XperfParams"}
		'Network' {$XperfProperty.StartOption = "-on Base+Latency+DISPATCHER+NETWORKTRACE+FileIO+DRIVERS -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile+SyscallEnter $XperfParams"}
		'Pool'	{$XperfProperty.StartOption = "-on Base+CSwitch+VIRT_ALLOC+POOL -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession+VirtualAlloc -PoolTag $XperfTag $XperfParams"}
		'PoolNPP' {$XperfProperty.StartOption = "-on Base+CSwitch+LOADER+VIRT_ALLOC+POOL+PROC_THREAD -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession+VirtualAlloc -PoolTag $XperfTag $XperfParams"}
		'Registry'{$XperfProperty.StartOption = "-on Base+REGISTRY+PROC_THREAD+NETWORKTRACE -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile+SyscallEnter $XperfParams"}
		'SMB2'	{
			$XperfProperty.StartOption = "-on Base+Latency+DISPATCHER+NETWORKTRACE+FILE_IO+FILE_IO_INIT+DRIVERS $XperfParams -stackwalk Profile+CSwitch+ReadyThread -start SMB2 -on d3bce2d2-92c9-44c7-befe-a27a96d413e9:::'stack'"
			$XperfProperty.StopOption = "-stop -stop SMB2 -d $($XperfProperty.LogFileName)"
		}
		'SBSL'	{
			$XperfProperty.StartOption = "-on Base+Latency+DISPATCHER+REGISTRY+NETWORKTRACE+FileIO -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile -BufferSize 1024 -start UserTrace -on `"Microsoft-Windows-Shell-Core+Microsoft-Windows-Wininit+Microsoft-Windows-Folder Redirection+Microsoft-Windows-User Profiles Service+Microsoft-Windows-GroupPolicy+Microsoft-Windows-Winlogon+Microsoft-Windows-Security-Kerberos+Microsoft-Windows-User Profiles General+e5ba83f6-07d0-46b1-8bc7-7e669a1d31dc+63b530f8-29c9-4880-a5b4-b8179096e7b8+2f07e2ee-15db-40f1-90ef-9d7ba282188a`" $XperfParams"
			$XperfProperty.StopOption = "-stop -stop UserTrace -d $($XperfProperty.LogFileName)"
		}
		'SBSLboot'{$XperfProperty.StartOption = "-on Base+Latency+DISPATCHER+REGISTRY+NETWORKTRACE+FileIO -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile $XperfParams"}
		'Leak'	{
			$XperfProperty.StartOption = "-on PROC_THREAD+LOADER+VIRT_ALLOC -stackwalk VirtualAlloc+VirtualFree $XperfParams -start HeapSession -heap -pids $XperfPIDs -stackwalk HeapAlloc+HeapRealloc"
			$XperfProperty.StopOption = "-stop -stop HeapSession -d $($XperfProperty.LogFileName)"
		}
		Default {
			LogError "Unknown option $Xperf was specified."
			CleanUpandExit
		}
	}

	# Start option for AutoLogger
	$XperfProperty.AutoLogger.AutoLoggerStartOption = $XperfProperty.StartOption -replace "^-on","-BootTrace"

	# If XperfOptions is available, Just append option in XperfOptions to the tail end.
	If(![string]::IsNullOrEmpty($XperfOptions)){ # Option from commmand line
		$XperfProperty.StartOption = $XpefProperty.StartOption + " " + $XperfOptions
		$XperfProperty.AutoLogger.AutoLoggerStartOption = $XpefProperty.AutoLogger.AutoLoggerStartOption + " " + $XperfOptions
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpProcmonProperty{
	EnterFunc $MyInvocation.MyCommand.Name

	# Respect passed $ProcmonPath. It it is null, use default procmon path.
	$ProcmonCmdPath = $global:BoundParameters['ProcmonPath']
	If(![String]::IsNullOrEmpty($ProcmonCmdPath)){
		If(Test-Path "$ProcmonCmdPath\procmon.exe"){
			$ProcmonProperty.CommandName = "$ProcmonCmdPath\procmon.exe"
		}Else{
			LogError "Invalid ProcmonPath `'$ProcmonPath`' was passed."
			CleanUpandExit
		}
	}

	$ProcmonCommand = Get-Command $ProcmonProperty.CommandName -ErrorAction Ignore
	If($ProcmonCommand -eq $Null){
		LogErrorFile "Procmon.exe not found."  # Procmon will be removed from AutoLog later. So just log it to log file.
		Return
	}

	# Check the version of Procmon.exe and add some switches accordingly.
	$ProcmonVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ProcmonCommand.Path).FileVersion
	LogDebug "Using $($ProcmonProperty.CommandName) with version $ProcmonVersion"
	If($ProcmonVersion -ne $Null -and $ProcmonVersion -gt 3.8){
		If(!([string]::IsNullOrEmpty($global:ProcmonRingBufferSize))){
			$RingBufferSize = $global:ProcmonRingBufferSize
		}Else{
			$RingBufferSize = 3096
		}
		$ProcmonProperty.StartOption = "/accepteula /RingBuffer /RingBufferSize $RingBufferSize /quiet /backingfile `"$ProcmonLogFile`""
		LogDebug "Procmon command line with buffer size: $($ProcmonProperty.StartOption)"
		$FlightRecorderMode = $True
	}

	# See if Procmon filter specfied by -ProcmonFilter exists.
	$ProcmonFilter = $global:BoundParameters['ProcmonFilter']
	If(![String]::IsNullOrEmpty($ProcmonFilter)){
		# Case for $ProcmonFilter has an absolute path.
		If(!(Test-Path -Path $ProcmonFilter)){
			# If not found, this might be relative path. So search recursively from current directory($ScriptFolder).
			LogDebug "Searching for $ProcmonFilter."
			$ProcmonFileterFile = Get-ChildItem -File $ProcmonFilter -Recurse -ErrorAction Ignore
			If($ProcmonFileterFile -eq $Null){
				LogError "-ProcmonFilter is specified but the file `'$ProcmonFilter`' does not exist."
				CleanUpandExit
			}Else{
				# In case that Get-ChildItem found the filter file, the specified path in $ProcmonFileterFile might be different from actual file path. Hence update the $ProcmonFilter.
				$ProcmonFilter = $ProcmonFileterFile.FullName
			}
		}
		LogDebug "Use $ProcmonFilter for Procmon filter."
		# Add filter to command line.
		If(Test-Path -Path $ProcmonFilter){
			$ProcmonProperty.StartOption = $ProcmonProperty.StartOption + " /LoadConfig `"$ProcmonFilter`""
			LogDebug "Procmon command line with filter: $($ProcmonProperty.StartOption)"
			If($FlightRecorderMode){
				LogInfo "Procmon filter is specified with flight recorder mode. In this case, flight recorder mode might be disabled." "Green"
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpPerfProperty{
	Param(
		[String]$Type
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If($Type -eq 'PerfMon'){
		$PerfProfile = $global:BoundParameters['PerfMon']
		If($global:BoundParameters.containskey('PerfIntervalSec')){
			$Script:PerfMonInterval = $global:BoundParameters['PerfIntervalSec']
		}
		$PerfMonProperty.TraceName = "PerfMon($PerfProfile) log"
		$PerfMonProperty.LogFileName = "$global:LogFolder\$($LogPrefix)PerfMon_$($PerfProfile)_$($Script:PerfMonInterval).blg"
	}
	
	If($Type -eq 'PerfMonLong'){
		$PerfProfile = $global:BoundParameters['PerfMonLong']
		If($global:BoundParameters.containskey('PerfLongIntervalMin')){
			$Script:PerfMonLongInterval = ([Int]$global:BoundParameters['PerfLongIntervalMin'] * 60)
		}
		$PerfMonLongProperty.TraceName = "PerfMonLong($PerfProfile) log"
		$PerfMonLongProperty.LogFileName = "$global:LogFolder\$($LogPrefix)PerfMonLong_$($PerfProfile)_$($Script:PerfMonLongInterval).blg"
	}

	$PerfCounterName = $PerfProfile + 'Counters'
	Try{
		$PerfCounters = Get-Variable -Name $PerfCounterName -ValueOnly -ErrorAction Stop
	}Catch{
		LogError "Invalid PerfMon counter name `'$PerfProfile`' was passed."
		LogInfo ("=> Please check supported counter name by running `'.\$ScriptName -ListSupportedPerfCounter`'") "Magenta"
		CleanUpandExit
	}
	$ConvertedCounterSet = ConvertToLocalPerfCounterName $PerfCounters
	If($ConvertedCounterSet.Count -gt 0){
		If($Type -eq 'PerfMon'){
			$PerfMonProperty.Providers = $ConvertedCounterSet
		}ElseIf($Type -eq 'PerfMonLong'){
			$PerfmonLongProperty.Providers = $ConvertedCounterSet
		}
	}Else{
		LogError "Failed to convert English counter name to local counter name."
		LogInfo " ..collecting registry hives for troubleshooting this PerfMon issue"
		LogInfo "=> Please check $global:ErrorLogFile" "Magenta"
		LogInfo "`nTo avoid this error, run AutoLog again with appended switch -noPerfmon" "Cyan"
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function FixUpFiddlerProperty{
	EnterFunc $MyInvocation.MyCommand.Name
	
	# Search fiddler path
	$FiddlerPaths = @("C:\Program Files\Fiddler", "C:\Program Files (x86)\Fiddler", "$env:userprofile\AppData\Local\Programs\Fiddler")
	ForEach($FiddlerPath in $FiddlerPaths){
		$IsFound = $False
		$FiddlerCommand = Join-Path $FiddlerPath 'ExecAction.exe'
		$Command = Get-Command $FiddlerCommand -ErrorAction Ignore
		If($Command -eq $Null){
			Continue
		}Else{
			$IsFound = $True
			Add-path $FiddlerPath
			$FiddlerProperty.CommandName = $FiddlerCommand
			break
		}
	}

	If(!$IsFound){
		LogError "Fiddler not found in below folders. Please download it from `'https://www.telerik.com/download/fiddler`' and install to one of below folders."
		ForEach($FiddlerPath in $FiddlerPaths){
			LogInfo "  - $FiddlerPath"
		}
		CleanUpAndExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function ProcessSet{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("-Set is specifid with $Set")

	# Check if set function corresponding to the option exists or not
	If(!$SupportedSetOptions.Contains($Set)){
		Write-Host ('ERROR: -Set ' + $Set + ' is invalid.') -ForegroundColor Red
		Write-Host ('Supported options are:')
		ForEach($Key in $SupportedSetOptions.Keys){
			Write-Host ('	o .\AutoLog.ps1 -Set ' + $Key + '   /// ' + $SupportedSetOptions[$Key])
		}
		CleanUpandExit
	}

	Try{
		$SetFuncName = "RunSet" + $Set
		Get-Command $SetFuncName -ErrorAction Stop | Out-Null
	}Catch{
		Write-Host ('ERROR: -Set ' + $Set + ' is invalid option. Possible option is:')
		CleanUpandExit
	}
	# Run set function
	LogDebug "[$($MyInvocation.MyCommand.Name)] Calling $SetFuncName"
	& $SetFuncName
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessUnset{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("-Unset is specifid with $Unset")

	# Check if set function corresponding to the option exists or not
	If(!$SupportedSetOptions.Contains($Unset)){
		Write-Host ('ERROR: -Unset ' + $Unset + ' is invalid.') -ForegroundColor Red
		Write-Host ('Supported options are:')
		ForEach($Key in $SupportedSetOptions.Keys){
			Write-Host ('	o .\AutoLog.ps1 -Unset ' + $Key)
		}
		CleanUpandExit
	}

	Try{
		$UnsetFuncName = "RunUnset" + $Unset
		Get-Command $UnsetFuncName -ErrorAction Stop | Out-Null
	}Catch{
		Write-Host ("ERROR: Unable to find a function for unsetting `'$Unset`'($UnsetFuncName)")
		CleanUpandExit
	}
	# Run set function
	LogDebug ("[$($MyInvocation.MyCommand.Name)] Calling $UnsetFuncName")
	& $UnsetFuncName
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStatus{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")
	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation
		}Catch{
			LogException "[ProcessStatus] An exception happened in RunPreparation" $_
			CleanUpandExit
		}
	}

	Write-Host ("Checking running traces.")
	$RunningScenarioObjectList = GetRunningScenarioTrace
	$RunningTraces = GetExistingTraceSession

	Write-Host ('Running scenario trace session:')
	If($RunningScenarioObjectList -ne $Null -or $RunningScenarioObjectList.Count -gt 0){
		ForEach($RunningScenarioObject in $RunningScenarioObjectList){
			Write-Host ""
			Write-Host ("	" + $RunningScenarioObject.ScenarioName + " scenario:")
			$RunningScenarioObjec.TraceListInScenario
			ForEach($TraceObject in $RunningScenarioObject.TraceListInScenario){
				Write-Host ("	  - " + $TraceObject.TraceName + ' with ' + $TraceObject.Providers.Count + ' providers')
			}
		}
	}Else{
		Write-Host ("	There is no running scenario trace.")
	}
	Write-Host ""
	# Checking running ETW traces and WPR/Procmon/Netsh/Perf. 
	Write-Host ('Running ETW trace session:')
	If($RunningTraces -ne $Null -or $RunningTraces.Count -gt 0){
		$etwCount=0
		ForEach($TraceObject in $RunningTraces){
			If($TraceObject.LogType -eq 'ETW'){
			   If($TraceObject.TraceName -like ("*Scenario_*Trace")){ # Scenario trace
				   continue
				}
				$etwCount++
				Write-Host ('	- ' + $TraceObject.TraceName + ' with ' + $TraceObject.Providers.Count + ' providers')
			}Else{
				$etwCount++
				Write-Host ('	- ' + $TraceObject.TraceName) # WPR/Procmon/Netsh/Perf
			}
		}
		If($etwCount -eq 0){
			Write-Host ("	There is no running session.")
		}
	}Else{
		Write-Host ("	There is no running session.")
	}
	Write-Host ""

	# Checking if AutoLogger is enabled or not.
	Write-Host ('AutoLogger session enabled:')
	$EnabledAutoLoggerTraces = GetEnabledAutoLoggerSession # This updates $TraceObject.AutoLogger.AutoLoggerEnabled

	#If($EnabledAutoLoggerTraces -ne $Null){
	#	UpdateAutoLoggerPath $EnabledAutoLoggerTraces
	#}

	$AutoLoggerCount=0
	ForEach($TraceObject in $EnabledAutoLoggerTraces){
		Write-Host ('	- ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
		$AutoLoggerCount++
		If($DebugMode.IsPresent){
			DumpCollection $TraceObject
		}
	}

	If($AutoLoggerCount -eq 0){
		Write-Host ('	There is no AutoLogger session enabled.')
	}Else{
		Write-Host ('Found ' + $AutoLoggerCount.ToString() + ' AutoLogger session(s).')
	}
	Write-Host ""
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessCreateBatFile{
	EnterFunc $MyInvocation.MyCommand.Name

	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")
	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation
		}Catch{
			LogException "[ProcessCreateBatFile] An exception happened in RunPreparation" $_
			CleanUpandExit
		}
	}

	$TraceSwitcheCount=0
	# Checking trace and command switches and add them to AutoLog.
	ForEach($RequestedTraceName in $global:ParameterArray){
	
		If($ControlSwitches.Contains($RequestedTraceName)){
			Continue # This is not switch for trace.
		}ElseIf($TraceSwitches.Contains($RequestedTraceName)){
			$TraceSwitcheCount++
			Continue
		}
	
		If($RequestedTraceName -eq 'NetshScenario'){
			$RequestedTraceName = 'Netsh' # NetshScenario uses Netsh object. So replace the name.
		}
		If($StartAutoLogger.IsPresent){
			# Only AutoLogger supported traces are added to AutoLog
			$AllAutoLoggerSupportedTraces =  $GlobalTraceCatalog | Where-Object{$_.AutoLogger -ne $Null}
			If($AllAutoLoggerSupportedTraces -eq $Null){
				Continue
			}
			$AutoLoggerSupportedTrace = $AllAutoLoggerSupportedTraces | Where-Object{$_.Name -eq $RequestedTraceName}
			If($AutoLoggerSupportedTrace -ne $Null){ # This trace has AutoLogger
				AddTraceToAutoLog $RequestedTraceName
			}
		}Else{
			# If not AutoLogger, just add all traces which are specified in option.
			AddTraceToAutoLog $RequestedTraceName
		}
	}
	
	# Check collection
	If($AutoLog.Count -eq 0){
		LogError ('AutoLog is null.')
		CleanUpandExit
	}

	CreateStartCommandforBatch $AutoLog
	CreateStopCommandforBatch $AutoLog
	LogInfo ("Batch file was created on $BatFileName.")
	If(!$StartAutoLogger.IsPresent){
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe $global:LogFolder }
	}Else{
		If((!$RemoteRun.IsPresent) -and !($global:IsServerCore)){ Explorer.exe $AutoLoggerLogFolder }
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessList{
	Param(
		[parameter(Mandatory=$False)]
		[String]$PODName
	)
	EnterFunc $MyInvocation.MyCommand.Name
	ProcessListSupportedCommands
	ProcessListSupportedNoOptions
	ProcessListSupportedLog $PODName
	ProcessListSupportedDiag $PODName
	ProcessListSupportedNetshScenario
	ProcessListSupportedWPRScenario
	ProcessListSupportedXperfProfile
	ProcessListSupportedSDP
	ProcessListSupportedTrace $PODName
	ProcessListSupportedScenarioTrace $PODName
	ProcessListSupportedPerfCounter
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessCollectEventLog{
	EnterFunc $MyInvocation.MyCommand.Name
	If(!$global:BoundParameters.ContainsKey('CollectEventLog')){
		LogDebug "ProcessCollectEventLog is called but CollectEventLog is not specified. Returning."
		Return
	}

	$EventLogs = $global:BoundParameters['CollectEventLog']
	LogInfo "CollectEventLog = $EventLogs"
	$EventLogList = @()
	ForEach($EventLog in $EventLogs){
		$EventLogConfiguration = Get-winevent -ListLog $EventLog -ErrorAction Ignore
		If($Null -eq $EventLogConfiguration){
			Continue
		}Else{
			$EventLogList += $EventLogConfiguration.LogName
		}
		FwExportEventLog $EventLogList
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function UpdateTSS{
	EnterFunc $MyInvocation.MyCommand.Name
	If(Test-Path -Path "$Scriptfolder\scripts\tss_update-script.ps1"){
		LogInfo "[update] AutoLog update starting..." green
		Push-Location -Path ".\scripts"
		Try{
			.\tss_update-script.ps1 -tss_action update -UpdMode $UpdMode -verOnline $Script:TssVerOnline
		}Catch{
			LogException "Exception happened in tss_update-script.ps1" $_
		}
		Pop-Location 
		LogInfo "[update] AutoLog update procedure completed." green
	}Else{
		LogWarn "[update] unable to find tss_update-script.ps1"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ReadConfigFile{
	EnterFunc $MyInvocation.MyCommand.Name
	If(!(Test-Path -Path $global:ConfigFile)){
		LogDebug ("Config file `'$global:ConfigFile`' does not exist.")
		Return
	}

	$Lines = Get-Content $global:ConfigFile
	ForEach($Line in $Lines){
		# Skip empty line
		If($Line.Length -eq 0){ 
			Continue
		}

		# Skip comment line and the line starting with space or tab.
		If($Line.Substring(0,1) -eq '@' -or $Line.Substring(0,1) -eq ' ' -or $Line.Substring(0,1) -eq "`t"){
			Continue
		}

		# In case the parameter is enabled but does not have a value like '_ErrorLimit=', skip it.
		$Token = $Line -split ('=')
		If($Token.Length -ne 2){ 
			LogWarn "Invalid line in tss_config file: $Line"
			Continue
		}

		# Remove double and single quote
		$Value = $Token[1] -Replace ("[`"`']")

		# Remove space at the end of value
		If($Value -match " *$"){
			$Value = $Value -replace " *$",""
		}

		Try{
			$script:FwConfigParameters.Add($Token[0], $Value)
		}Catch{
			LogException ("Exception happened in ParameterTalbe.Add() with $($Token[0])=$Value. Usually this happens when the same parameter is configured multiple times.") $_
			Return
		}
	}

	# If there is a parameter configured, copy the tss_config file to the log folder.
	If($FwConfigParameters.Count -eq 0){
		LogInfo "Config file (tss_config.cfg) exists but no parameter is configured."
		Return
	}Else{
		Try{
			LogDebug "Copying $ConfigFile to $global:LogFolder"
			Copy-Item $ConfigFile $global:LogFolder -ErrorAction Stop
		}Catch{
			LogWarn "Failed to copy $ConfigFile to $global:LogFolder"
		}
	}

	# ToDo: add additional parameter name(s) in below list, whenever tss_config.cfg adds a new parameter
	#'_RunDown','_noClearCache','_noRestart','_collectEvtSec','_RunPS_BCstatus','_BITSLOG_RESET','_BITSLOG_RESTART','_SCCMdebug','_NetLogonFlag','_LDAPcliProcess','_LDAPcliFlags','_FltMgrFlags','_GPEditDebugLevel' | ForEach-Object {
	#	If(!([string]::IsNullOrEmpty($FwConfigParameters[$_]))){
	#		Set-Variable -Name ('$global:' + ($_).replace("_","")) -scope Global
	#		$ConfigVarName = ('$global:' + ($_).replace("_",""))
	#		$ConfigVarValue = $FwConfigParameters[$_]
	#		LogDebug "ConfigVarName: $ConfigVarName - ConfigVarValue: $ConfigVarValue"
	#	}
	#}

	# Set all configured parameters to global variable so that POD module can access them.
	# Example: _EvtxLogSize is set to $global:EvtxLogSize. 
	# Note: '_'(underscore) at the beginning of parameter is removed when config parameter is converted to global variable.
	ForEach($Key in $FwConfigParameters.Keys){
		$ConfigVarName = $Key -replace "^_",''
		[String]$ConfigVarValue = $FwConfigParameters[$Key]

		# Convert string boolean to real boolean
		If($ConfigVarValue -eq '$True'){
			[Bool]$ConfigVarValue = $True
		}ElseIf($ConfigVarValue -eq '$False'){
			[Bool]$ConfigVarValue = $False
		}

		# If the value is number string, convert it to int32.
		If([int]::TryParse($ConfigVarValue,[ref]$Null)){ # convert number string to int
			[int]$ConfigVarValue = $ConfigVarValue
		}

		Try{
			Set-Variable -Name $ConfigVarName -Value $ConfigVarValue -scope Global -ErrorAction Stop
		}Catch{
			LogWarn "Failed to set $ConfigVarName=$ConfigVarValue"
			Continue
		}
		$ConfigValue = Get-Variable -Name $ConfigVarName -Scope Global
		LogDebug ("ConfigVarName: $($ConfigValue.Name) = " + $ConfigValue.Value)
	}

	$Value = $FwConfigParameters['_EnableMonitoring']
	If(!([string]::IsNullOrEmpty($Value)) -and ($Value.Substring(0,1) -eq 'y')){
		$Value = $FwConfigParameters['_MonitorIntervalInSec']
		If(!([string]::IsNullOrEmpty($Value))){
			$script:FwMonitorIntervalInSec = $Value
		}
		
		# Count monitoring events
		$TestList = @("_PortLoc", "_PortDest", "_SvcName", "_ShareName", "_DomainName", "_ProcessName", "_CommonTCPPort", "_RegDataKey", "_RegValueKey", "_RegKey", "_File", "_EventLogName", "_WaitTime", "_LogFile")
		$ConfiguredTestCount = 0
		ForEach($TestName in $TestList){
			$Value = $FwConfigParameters[$TestName]
			If($Value -ne $Null){
				$ConfiguredTestCount++
			}
		}
		If($ConfiguredTestCount -gt 0){
			$script:FwIsMonitoringEnabledByConfigFile = $True
			LogDebug "IsMonitoring is set to True"
			LogDebug "Number of monitoring events = $ConfiguredTestCount"
		}
	}

	If(!([string]::IsNullOrEmpty($FwConfigParameters['_EvtxLogSize']))){
		$global:FwEvtxLogSize = $FwConfigParameters['_EvtxLogSize']	#we# changed to global in #
	}
	
	if (!($global:BoundParameters['ProcDumpOption']	)) { #we#604
		$ProcDumpOptionFromConfig = $FwConfigParameters['_ProcDumpOption']
		If(![string]::IsNullOrEmpty($ProcDumpOptionFromConfig)){
			LogDebug "Use ProcDumpOption($ProcDumpOptionFromConfig) configured in tss_config.cfg"
			$script:ProcDumpOption = $ProcDumpOptionFromConfig
		} else {
			$script:ProcDumpOption="Both"		# default if not in config.cfg or in command-line
			LogDebug "Use ProcDumpOption($ProcDumpOption) - default configured in ReadConfigFile"
		}
	} else { LogDebug "Use ProcDumpOption($ProcDumpOption) from command-line" }

	if (!($global:BoundParameters['ProcDumpInterval']	)) { #we#604
		$ProcDumpIntervalFromConfig = $FwConfigParameters['_ProcDumpInterval']
		If(![string]::IsNullOrEmpty($ProcDumpIntervalFromConfig)){
			LogDebug "Use ProcDumpInterval($ProcDumpIntervalFromConfig) configured in tss_config.cfg"
			$script:ProcDumpInterval = $ProcDumpIntervalFromConfig
		} else {
			$script:ProcDumpInterval="3:10"	# default if not in config.cfg or in command-line
			LogDebug "Use ProcDumpInterval($script:ProcDumpInterval) - default configured in ReadConfigFile"
		}
	} else { LogDebug "Use ProcDumpInterval($ProcDumpInterval) from command-line" }
    LogDebug "[ReadConfigFile] ProcDumpInterval $script:ProcDumpInterval / global: $global:ProcDumpInterval  - ProcDumpOption $ProcDumpOption / global: $global:ProcDumpOption"
	
	# ToDo: Define default switch options for PerfMon, PerfMonLong, WPR, Xperf ?
	EndFunc $MyInvocation.MyCommand.Name
}

Function ValidateConfigFile{
	EnterFunc $MyInvocation.MyCommand.Name
	# Validate parameters for monitoring
	If($global:IsRemoting){
		$Value = $FwConfigParameters['_WriteEventToHosts']
		If([string]::IsNullOrEmpty($Value)){
			Throw ("_WriteEventToHosts has to be specified when remoting is enabled.")
		}Else{
			# Test if remote registry and WMI is enabled as these are required for remoting.
			$RemoteHosts = $Value -split ','
			ForEach($RemoteHost in $RemoteHosts){
				$reg = $Null
				Try{
					$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $RemoteHost)
				}Catch{
					# Do nothing
				}
				If($reg -eq $Null){
					Throw "Remote Registry service is not started on $RemoteHost. Please start it and run again or remove `'$RemoteHost`' from _WriteEventToHosts."
				}
			}
		}
		# _RemoteLogFolder is optional but if it has a value, it should be remote share.
		$Value = $FwConfigParameters['_RemoteLogFolder']
		If(!([string]::IsNullOrEmpty($Value)) -and $Value.Substring(0,2) -ne '\\'){
			Throw "_RemoteLogFolder has to be remote share but current value is $Value"
		}
		# Test access for the remote share
		If(!([string]::IsNullOrEmpty($Value)) -and !(Test-Path -Path $Value)){
			Throw "Unable to access to `'$Value`'."
		}
	}

	# Validate parameters for monitoring
	If($FwIsMonitoringEnabledByConfigFile){
		# _PortDest => _PortDestServerName needs to be configured.
		$Value = $FwConfigParameters['_PortDest']
		If(![string]::IsNullOrEmpty($Value)){
			$PortDestServerName = $FwConfigParameters['_PortDestServerName']
			If([string]::IsNullOrEmpty($PortDestServerName)){
				Throw ("_PortDestServerName needs to be configured.")
			}
		}

		# _ProcessName => _ProcessName should not contain '.exe'.
		$Value = $FwConfigParameters['_ProcessName']
		If(![string]::IsNullOrEmpty($Value) -and $Value.contains('.exe')){
			Throw ("_ProcessName($Value) cannot take name with `'.exe`'.")
		}

		# _ShareName => _ShareServerName must be specified.
		$Value = $FwConfigParameters['_ShareName']
		If(![string]::IsNullOrEmpty($Value)){
			$ShareServerName = $FwConfigParameters['_ShareServerName']
			If([string]::IsNullOrEmpty($ShareServerName)){
				Throw ("_ShareServerName needs to be configured.")
			}
		}

		# _CommonTCPPort => it must be one of 'RDP', 'SMB', 'HTTP' and 'WINRM'
		$Value = $FwConfigParameters['_CommonTCPPort']
		If(![string]::IsNullOrEmpty($Value)){
			If(!(($Value -eq 'SMB') -or ($Value -eq 'HTTP') -or ($Value -eq 'RDP') -or ($Value -eq 'WINRM'))){
				Throw ("_CommonTCPPort($Value) must be one of 'RDP', 'SMB', 'HTTP' and 'WINRM'.")
			}Else{
				$CommonTCPPortServerName = $FwConfigParameters['_CommonTCPPortServerName']
				If([string]::IsNullOrEmpty($CommonTCPPortServerName)){
					Throw ("_CommonTCPPortServerName needs to be configured.")
				}
			}
		}

		# _RegDataKey => _RegDataValue and _RegDataExpectedData are required.
		$Value = $FwConfigParameters['_RegDataKey']
		If(![string]::IsNullOrEmpty($Value)){
			$RegDataValue = $FwConfigParameters['_RegDataValue']
			$RegDataExpectedData = $FwConfigParameters['_RegDataExpectedData']
			If([string]::IsNullOrEmpty($RegDataValue) -or [string]::IsNullOrEmpty($RegDataExpectedData)){
				Throw ("Both _RegDataValue and _RegDataExpectedData need to be configured.")
			}
		}

		# _RegValueKey => _RegValueValue is required.
		$Value = $FwConfigParameters['_RegValueKey']
		If(![string]::IsNullOrEmpty($Value)){
			$RegValueValue = $FwConfigParameters['_RegValueValue']
			If([string]::IsNullOrEmpty($RegValueValue)){
				Throw ("_RegValueValue needs to be configured.")
			}
		}

		# _EventlogName => _Stop_EventID is required.
		$Value = $FwConfigParameters['_EventlogName']
		If(![string]::IsNullOrEmpty($Value)){
			$StopEventID = $FwConfigParameters['_Stop_EventID']
			If([string]::IsNullOrEmpty($StopEventID)){
				Throw ("_Stop_EventID needs to be configured.")
			}
		}

		# _WaitTime => time should be number
		$Value = $FwConfigParameters['_WaitTime']
		If(![string]::IsNullOrEmpty($Value)){
			$Token = $Value -split ':'
			If(![int]::TryParse($Token[0],[ref]$Null)){
				Throw ("_WaitTime can take only number but `'$($Token[0])`' was specified.")
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ReadParameterFromAutoLogReg{
	EnterFunc $MyInvocation.MyCommand.Name
	If(!(Test-Path "$global:AutoLogParamRegKey")){
		LogInfoFile "There are no parameter settings in AutoLog registry."
		Return $Null
	}Else{
		If(!$Status.IsPresent){ # In case of -Status, we don't want to show this message to make console log simple.
			LogInfo "Reading parameters from AutoLog registry."
		}
		
		$ParamArray = Get-Item "$global:AutoLogParamRegKey" | Select-Object -ExpandProperty Property -ErrorAction Ignore
		$RegValue = Get-ItemProperty -Path  "$global:AutoLogParamRegKey" -ErrorAction Ignore
		ForEach($Param in $ParamArray){
			$Data = $RegValue.$Param

			# Convert string boolean to boolean
			If($Data -eq "True"){
				$Data = $True
			}ElseIf($Data -eq "False"){
				$Data = $False
			}

			# Load data as a string array if data has delimiter(,).
			If($Data.gettype().Name -eq 'String'){
				If($Data.contains(',')){
					$Data = $Data -split ','
				}
			}

			LogInfoFile ('  - $' + "$Param($(($Data.gettype()).Name)) = $Data")
			Set-Variable -Name $Param -Value $Data -Scope Script
			If(!($global:BoundParameters.ContainsKey($Param))){
				$global:BoundParameters.Add($Param,$Data)
			}
			If($global:ParameterArray -notcontains $Param){
				$global:ParameterArray += $Param
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function SaveParameterToAutoLogReg{
	EnterFunc $MyInvocation.MyCommand.Name

	# Save parameter to AutoLog registry
	ForEach($Key in $global:BoundParameters.Keys){
		If($Key -ne 'Start' -and $Key -ne 'StartAutoLogger' -and $Key -ne 'StartNoWait' -and  $Key -ne 'NewSession' -and $Key -ne 'DebugMode'){
			SaveToAutoLogReg $Key $global:BoundParameters[$Key]
		}
	}
	SaveToAutoLogReg 'LogFolder' $global:LogFolder
	EndFunc $MyInvocation.MyCommand.Name
}

Function RemoveParameterFromAutoLogReg{
	EnterFunc $MyInvocation.MyCommand.Name

	# Delete parameters saved in AutoLog registry
	If(Test-Path -Path $global:AutoLogParamRegKey){
		LogInfo "Removing $global:AutoLogParamRegKey"
		Remove-Item $global:AutoLogParamRegKey -Force
	}

	EndFunc $MyInvocation.MyCommand.Name
}

Function Add-Path {
	<#
	.SYNOPSIS
	  Adds a Directory to the Current Path | Join-Path ?
	.DESCRIPTION
	  Add a directory to the current $ENV:path. This is useful for temporary changes to the path or, when run from your profile, for adjusting the path within your PowerShell prompt.
	.EXAMPLE
	  Add-Path -Directory "C:\Program Files\Notepad++"
	.PARAMETER Directory
	  The name of the directory to add to the current path.
	#>
	param(
		[Parameter(
		 Mandatory=$True,
		 ValueFromPipeline=$True,
		 ValueFromPipelineByPropertyName=$True,
		 HelpMessage='What directory would you like to add?')]
		[Alias('dir')]
		[string[]]$Directory
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$Path = $env:PATH.Split(';')
	foreach ($dir in $Directory) {
		if ($Path -contains $dir) {
			LogInfoFile "$dir is already present in PATH."
		} else {
			if (-not (Test-Path $dir)) {
			LogInfoFile "$dir does not exist in the filesystem"
			} else {
				$Path += $dir
			}
		}
	}
	$env:PATH = [String]::Join(';', $Path)
	EndFunc $MyInvocation.MyCommand.Name
}

Function RunFunction{
	<#
	.SYNOPSIS
	 Runs a function passed through argument.
	.DESCRIPTION
	 Check if the passed function exists and if it is not called before, run the function.
	.EXAMPLE
	 RunFunction "CollectDev_TESTLog"
	 RunFunction "CollectDev_TESTLog" $RunOnce:$False  # Allows multiple execution.
	.PARAMETER FuncName
	 The name of the function to be executed.
	.PARAMETER RunOnce
	 Boolean to determine if the function is allowed to be executed more than onece.
	.PARAMETER ThrowException
	 Determines if an exception is thrown from this function.
	#>
	param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$True)]
		[String]$FuncName,
		[Parameter(Mandatory=$False)]
		[String]$ParamString,
		[Parameter(Mandatory=$False)]
		[Bool]$RunOnce = $True,
		[Parameter(Mandatory=$False)]
		[Bool]$ThrowException = $False
	)
	EnterFunc "[$($MyInvocation.MyCommand.Name)] with $FuncName"

	$Func = $Null
	$Func = Get-Command $FuncName -CommandType Function -ErrorAction Ignore # Ignore exception
	
	If($Func -ne $Null){
		$PreviouslyExecutedFunction = $Script:ExecutedFunctionList | Where-Object {$_ -eq $FuncName}
		If($PreviouslyExecutedFunction -eq $Null){
			LogDebug "Adding $FuncName to ExecutedFunctionList." "Yellow"
			$Script:ExecutedFunctionList.Add($FuncName)
		}Else{
			If($RunOnce){
				LogInfoFile "Skipping running $FuncName() as it is already run before." #we# log to file only
				Return
			}
		}

		LogInfo "[$($MyInvocation.MyCommand.Name)] Calling $FuncName $ParamString"
		Try{
			If([string]::IsNullOrEmpty($ParamString)){
				& $FuncName
			}Else{
				& $FuncName $ParamString
			}
		}Catch{
			LogWarn "An error happened in $FuncName"
			LogException "An error happened in $FuncName" $_ $fLogFileOnly
			If($ThrowException){
				Throw $_.Exception.Message
			}
		}
	}Else{
		LogDebug "$FuncName was not found."
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function PreRequisiteCheckInStage1{
	EnterFunc $MyInvocation.MyCommand.Name

	# Issue#331 - Disallow starting more than one AutoLog instance at the same time.
	If($global:ParameterArray -contains 'Start' -or $global:ParameterArray -contains 'StartAutoLogger' -or $global:ParameterArray -contains 'Stop' -or $global:ParameterArray -contains 'CollectLog' -or $global:ParameterArray -contains 'StartDiag'){
		$AutoLogProcesses = Get-CimInstance Win32_Process | Where-Object {$_.Commandline -like "*AutoLog.ps1*-NewSession*"}
		If($AutoLogProcesses -ne $Null){
			$MyPID = $PID  # $PID is built-in env value that has PID of this instance of PowerShell.exe.
			ForEach($AutoLogProcess in $AutoLogProcesses){
				If($MyPID -ne $AutoLogProcess.ProcessId){
					LogInfo "ERROR: Currently another instance of AutoLog is running with PID $($AutoLogProcess.ProcessId)." "Red"
					CleanupAndExit
				}
			}
		}
	}

	# First thing we need to check is 'Constrained Language Mode' as this prevents most .net types from being accessed and it is very critical for this script.
	# https://devblogs.microsoft.com/PowerShell/PowerShell-constrained-language-mode/
	$ConstrainedLanguageMode = $ExecutionContext.SessionState.LanguageMode
	$LockdownPolicy = $Env:__PSLockdownPolicy
	If($ConstrainedLanguageMode -ne 'FullLanguage'){
		If($LockdownPolicy -eq $Null){
			$fIsLockdownByEnvironmentVariable = $False
		}Else{
			$fIsLockdownByEnvironmentVariable = $True
		}
	
		LogInfo ("Current constrained language mode is `'" + $ConstrainedLanguageMode + "`' but this script must be run with `'FullLanguage`' mode.") "Red"
		Write-Host ('Please ask administrator why $ExecutionContext.SessionState.LanguageMode is set to ' + $ConstrainedLanguageMode + '.') -ForegroundColor Red
		Write-Host ""
		If($fIsLockdownByEnvironmentVariable){
			Write-Host ("To fix this issue, remove `'__PSLockdownPolicy`' environment valuable.")
			Write-Host ""
		}
		CleanUpandExit
	}

	# Elevation Check
	# This script needs to be run with administrative privilege except for -CollectLog.
	If(((IsStart) -or $global:BoundParameters.ContainsKey('Stop')) -and !$noAdminChk.IsPresent){
		FwRunAdminCheck
	}

	# Disabling quick edit mode as somethimes this causes the script stop working until enter key is pressed.
	If($fQuickEditCodeExist){
		[DisableConsoleQuickEdit]::SetQuickEdit($True) | Out-Null
	}

	# Validate tss script version - timebomb if older than 30 days, but exclude -Update
	If( !$Update.IsPresent){
		$TSSver = $global:TssVerDate.SubString(0,10)
		$dateTSSver = [DateTime]($TSSver)
		$DiffDate = ((Get-Date) - $dateTSSver )
		If($DiffDate.Days -gt 30){
			LogError "AutoLog script is outdated more than 30 days. Please -Update or download latest version: 'https://aka.ms/getTSS' or 'https://cesdiagtools.blob.core.windows.net/windows/AutoLog.zip'"
			CleanUpandExit
		}
	}

	# At this moment, we don't support multiple scenario traces.
	If($Scenario.Count -gt 1){
		LogInfo "Currently multiple scenarios ($Scenario) are not supported." "Red"
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function PreRequisiteCheckInStage2{
	<#
	.SYNOPSIS
	 Inspects traces to be started
	.DESCRIPTION
	 Make sure $AutoLog is not empty and number of traces to be started does not exceed system limitation which is currently 56 sessions.
	#>
	EnterFunc $MyInvocation.MyCommand.Name
	
	# In stage2, we have $global:ParameterArray and $LogFolderName initialized

	# Parameter compatibility check
	Try{
		CheckParameterCompatibility
	}Catch{
		LogInfo "Detected compatibility error. Exiting..."
		CleanUpandExit
	}

	# Check if reg.exe is disabled. If it is, temporary enable it by setting DisableRegistryTools=0.
	If((IsStart) -or $Stop.IsPresent -or ![string]::IsNullOrEmpty($CollectLog) -or ![string]::IsNullOrEmpty($StartDiag)){
		If($global:OriginalDisableRegistryTools -gt 0){
			LogInfo "Registry editing has been disabled by your administrator. Current value of Reg-Key DisableRegistryTools = $OriginalDisableRegistryTools."
			ToggleRegToolsVal 0
		}
	}

	# Validate script folder name
	#if (($global:ScriptFolder -match '\s' ) -or ($global:ScriptFolder -match '[()]') ) {
	#	write-host -ForegroundColor red "TSS script path contains spaces or brackets or exclamation mark. Please rename/correct the TSS path: '$ScriptFolder'"
	#	CleanUpAndExit
	#}

	# Log folder check. It must be other than profile in case of -StartAutoLogger.
	If($StartAutoLogger.IsPresent -and ![string]::IsNullOrEmpty($LogFolderName)){
		if($LogFolderName -like "C:\Users\*"){
			LogError "Setting log folder to under profile($LogFolderName) is not supported in case of -StartAutoLogger. Please specify somewhere other than profile(ex. -LogFolderName D:\AutoLog)."
			CleanUpAndExit
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function PreRequisiteCheckForStart{
	EnterFunc $MyInvocation.MyCommand.Name

	# Do admin check again as it is possible for traces to be started without -Start switch now.
	# In this case, admin check in PreRequisiteCheckInStage1 is passed and we need to run admin check at this timing again.
	If($global:ParameterArray -notcontains 'noAdminChk'){
		FwRunAdminCheck
	}

	# Running AutoLog on x64 system with x86 powershell.exe may fail later.(#591)
	If (![Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem){
		LogError "Windows PowerShell Workflow is not supported in a Windows PowerShell x86-based console. Open a Windows PowerShell x64-based console, and then try again."
		CleanUpandExit
	}

	If($global:ParameterArray -contains 'PSR' -or $global:ParameterArray -contains 'Video' -and $global:ParameterArray -notcontains 'noRecording'){
		FwPlaySound
		LogInfo "Note for this step: If you do not agree on Recording, the solution for your issue might be delayed a lot, because MS support engineer needs to match the time (hh:mm:ss) of your problem (error message) exactly with the time stamps in debug data." "Magenta"
		LogInfo "[Action-Privacy] We need your consent to allow Problem Step Recording and-or Screen-Video recording, please answer Y or N" "Cyan"
		# Issue#373 - AutoLog hang in ISE
		$Answer = FwRead-Host-YN -Message "Press Y for Yes = allow recording, N for No (timeout=20s)" -Choices 'yn' -TimeOut 20
		#CHOICE /T 20 /C yn /D y /M " Press Y for Yes = allow recording, N for No "
		If(!$Answer){
			LogInfoFile "=== User declined screen recording/video ==="
			LogInfo "Run script with -noPSR, -noVideo or -noRecording again if you don't want your session to be recorded" "Red"
			CleanUpandExit
		}
	}

	# Video
	If($global:ParameterArray -contains 'Video'){
		If(!(Test-Path "HKLM:\Software\Microsoft\NET Framework Setup\NDP\v3.5")){
			LogInfo "-Video requires .NET 3.5 but not installed on this system." "Magenta"
			LogInfo "To download .NET Framework 3.5:"
			LogInfo "  1. Go to https://www.microsoft.com/download/details.aspx?id=21"
			LogInfo "  2. Select language and click [Download] button then install it manually."
			$RemoveVideo = $True
		}

		$VideoCommand = Get-Command $VideoProperty.CommandName -ErrorAction Ignore
		If($VideoCommand -eq $Null){
			LogWarn "$($VideoProperty.CommandName) not found."
			$RemoveVideo = $True
		}

		If($RemoveVideo){
			LogInfo "Removing -Video from parameter list and will continue without recording video."
			$global:ParameterArray = RemoveItemFromArray $global:ParameterArray "Video"
			$TraceObject = $AutoLog | Where-Object {$_.Name -eq 'Video'}
			If($TraceObject -ne $Null){
				$AutoLog.Remove($TraceObject) | Out-Null
			}
		}
	}

	# See if external commands exist. If not, remove the command from AutoLog.
	$RemovedExternalCommandList = New-Object 'System.Collections.Generic.List[Object]'
	ForEach($ExternalCommand in $ExternalCommandList.Keys){
		If($global:BoundParameters.ContainsKey($ExternalCommand)){
			$Command = Get-Command $ExternalCommandList[$ExternalCommand] -ErrorAction Ignore
			If($Command -eq $Null){
				$global:ParameterArray = RemoveItemFromArray $global:ParameterArray $ExternalCommand
				$global:BoundParameters.Remove($ExternalCommand) | Out-Null
				$TraceObject = $AutoLog | Where-Object {$_.Name -eq $ExternalCommand}
				If($TraceObject -ne $Null){
					$AutoLog.Remove($TraceObject) | Out-Null
					$RemovedExternalCommandList.Add($ExternalCommand)
				}
			}
		}
	}

	If($RemovedExternalCommandList.count -gt 0){
		If($global:IsLiteMode){
			LogInfo "You are using Lite version of AutoLog. Below log(s) will be not collected." "Magenta"
			LogInfo "Please download full version of AutoLog from 'https://aka.ms/getTSS' to collect all logs." "Magenta"
		}Else{
			LogInfo "Below command(s) does not exist. AutoLog will not collect the log." "Magenta"
		}
		ForEach($RemovedExternalCommand in $RemovedExternalCommandList){
			LogInfo "  - $RemovedExternalCommand" "Magenta"
		}
	}

	# Xperf
	If($global:ParameterArray -contains 'Xperf'){
		$Xperf = $global:BoundParameters['Xperf']
		$XperfTag = $global:BoundParameters['XperfTag']
		$XperfPIDs = $global:BoundParameters['XperfPIDs']

		Switch($Xperf){
			'Pool' {
				If([String]::IsNullOrEmpty($XperfTag)){
					LogError "Xperf with Pool profile needs -XperfTag switch. Please run with `'-Xperf $Xperf -XperfTag <PoolTag>`'."
					LogInfo "Ex.: .\AutoLog.ps1 -Xperf Pool -XperfTag TcpE+AleE+AfdE+AfdX" "Yellow"
					CleanUpAndExit
				}
			}
			'PoolNPP' {
				If([String]::IsNullOrEmpty($XperfTag)){
					LogError "Xperf with PoolNPP profile needs -xperftag switch. Please run with `'-Xperf $Xperf -XperfTag <PoolTag>`'."
					CleanUpAndExit
				}
			}
			'Leak' {
				If([String]::IsNullOrEmpty($XperfPIDs)){
					LogError "Xperf with Leak profile needs -XperfPIDs switch. Please run with `'-Xperf $Xperf -XperfPIDs <PID>`'."
					CleanUpAndExit
				}
			}
		}
	}

	# Sysmon
	If($global:BoundParameters.ContainsKey('SysMon')){

		# To see if sysmon was enabled by AutoLog, we check if 'Sysmon' service is running and also the 'sysmon' is stored in AutoLog reg.
		$SysMonService = Get-Service -Name "SysMon" -ErrorAction Ignore

		If($SysMonService -ne $Null){
			$RegValues = Get-ItemProperty -Path  $global:AutoLogParamRegKey -ErrorAction Ignore
			If($RegValues.SysMon -eq $Null){
				LogWarn "Detected running SysMon started from outside of AutoLog. AutoLog will NOT restart and stop the running SysMon."
				LogInfo "=> To stop running SysMon, run `'SysMon.exe -u -nobanner`' manually." "Cyan"
				If(!$noAsk.IsPresent){
					FwPlaySound
					$Answer = FwRead-Host-YN -Message "Do you want to continue? (timeout=20s)" -Choices 'yn' -TimeOut 20
					If(!$Answer){
						LogInfo "Exiting script."
						CleanUpandExit
					}
				}
				LogInfo "Removing -SysMon from script parameter."
				$global:ParameterArray = RemoveItemFromArray $global:ParameterArray 'SysMon'
				$global:BoundParameters.Remove('SysMon') | Out-Null
				# Remove SysMon from $AutoLog which is the list of traces to be collected.
				$TraceObject = $AutoLog | Where-Object {$_.Name -eq 'SysMon'}
				If($TraceObject -ne $Null){
					$AutoLog.Remove($TraceObject) | Out-Null
				}
			}
		}
	}

	# WaitEvent
	If($global:BoundParameters.ContainsKey('WaitEvent')){
		$Token = ($global:BoundParameters['WaitEvent']) -split ':'
		$EventType = $Token[0]
		Switch ($EventType){
			'LogFile' {
				$FileName = ($Token[1] + ':' + $Token[2])
				If(!(Test-Path -Path $FileName)){
					LogError "-WaitEvent was specified but passed file `'$FileName`' does not exist."
					CleanUpAndExit
				}
			}
		}
	}

	# Remoting
	If($global:IsRemoting){
		
		# Check if RemoteRegistry is running
		$SvcStatus = ((Get-Service 'RemoteRegistry' -ErrorAction Ignore).Status)
		If($SvcStatus -ne [System.ServiceProcess.ServiceControllerStatus]::Running){
			LogWarn "RemoteRegistry needs to be enabled for Remoting feature to work properly."
			FwPlaySound
			Write-Host ""
			$Answer = FwRead-Host-YN -Message "Do you want to start 'RemoteRegistry' service now"
			If($Answer){ # Yes
				Try{
					Start-Service -Name "RemoteRegistry" -ErrorAction Stop
					LogInfo "RemoteRegistry service started."
				}Catch{
					LogError "Unable to start 'RemoteRegistry' service. Please check if the service is disabled by policy."
					CleanUpAndExit
				}
			}Else{ # No
				LogInfoFile "=== User declined to start 'RemoteRegistry' service ==="
				LogError "Enable 'RemoteRegistry' service manually and then run the script again."
				CleanUpAndExit
			}
		}

		# Check if Firewall rules for remoting are enabled.
		$FWRuleEnabled = $True
		$script:FWRuleArray = @()
		$RulesRemoteEventLogSvc = Get-NetFirewallRule -Name "RemoteEventLogSvc*" -ErrorAction Ignore
		ForEach($RuleRemoteEventLogSvc in $RulesRemoteEventLogSvc){
			If($RuleRemoteEventLogSvc.Enabled -eq "False"){
				$script:FWRuleArray += $RuleRemoteEventLogSvc
				$FWRuleEnabled = $False
			}
		}
		$RuleDCOMIN = Get-NetFirewallRule -Name "ComPlusNetworkAccess-DCOM-In" -ErrorAction Ignore
		If($RuleDCOMIN -ne $Null -and $RuleDCOMIN.Enabled -eq "False"){
			$script:FWRuleArray += $RuleDCOMIN
			$FWRuleEnabled = $False
		}

		If(!$FWRuleEnabled){
			LogWarn "Below Firewall rule(s) needs to be enabled for Remoting feature to work properly."
			ForEach($FWRule in $script:FWRuleArray){
				Write-Host "   - $($FWRule.DisplayName)"
			}
			FwPlaySound
			Write-Host ""
			$Answer = FwRead-Host-YN -Message "Do you want to enable above firewall rules now"
			If($Answer){ # Yes
				ForEach($FWRule in $script:FWRuleArray){
					LogInfo "Enabling Firewall rule `'$($FWRule.DisplayName)`'"
					Try{
						$FWRule | Set-NetFirewallRule -Enabled True -ErrorAction Stop
					}Catch{
						LogError "Unable to enable Firewall rule. Remoting would not work on this system."
						CleanUpAndExit
					}
				}
			}Else{ # No
				LogInfoFile "=== User declined to enable above firewall rules ==="
				LogError "Enable above firewall rules manually and then run the script again."
				CleanUpAndExit
			}
		}

		$RemoteHosts = $global:BoundParameters['RemoteHosts']
		LogInfo "Testing if Write-EventLog work with specified remote hosts. This may take a while in case Firewall on remote host blocks the access."
		ForEach($RemoteHost in $RemoteHosts){
			Try{
				Write-EventLog -ComputerName $RemoteHost -LogName 'System' -EntryType Info -Source "Eventlog" -EventId 1 -Message "Test event from AutoLog" -Category 1 -ErrorAction Stop
			}Catch{
				$Message = "Unable to write an event to $RemoteHost. Remoting would not work on specified remote hosts($RemoteHost)"
				LogError $Message
				LogException $Message $_ $True
				# Bail out(Reset enabled Firewall rules and exit). 
				If($script:FWRuleArray.Count -ne 0){
					ForEach($FWRule in $script:FWRuleArray){
						LogInfo "Disabling Firewall rule `'$($FWRule.DisplayName)`' setting as it was enabled temporary."
						$FWRule | Set-NetFirewallRule -Enabled False
					}
					$script:FWRuleArray = $Null
				}
				CleanUpAndExit
			}
		}
	}

	# Check 1: Make sure $AutoLog is not empty.
	If($AutoLog.Count -eq 0){
		If($StartAutoLogger.IsPresent){
			LogInfo "ERROR: There are no traces that support AutoLogger in specified switch or scenario. Exiting." "Red"
		}Else{
			LogInfo 'ERROR: There are no traces to start. Please check switches you specified or scenario. Exiting.' "Red"
		}
		CleanUpandExit
	}

	# Check 2: Validate $AutoLog
	Try{
		ValidateCollection $AutoLog
	}Catch{
		LogException "An exception happened in ValidateCollection" $_
		CleanUpandExit
	}

	# Check 3: trace count. If it is more than 56 sessions, stop unnecessary sessions 
	#		  and see it gets less than 56. It is still over 56, show error and exit.
	If($AutoLog.count -ne 0){
		$ETWTracesObjectList = $AutoLog | Where-Object {$_.LogType -eq 'ETW'}
		If($ETWTracesObjectList -ne $Null -and $ETWTracesObjectList.count -ne 0){
			# Inspect the trace provider and count number of trace to be started.
			$TraceList = New-Object 'System.Collections.Generic.List[Object]'
			ForEach($ETWTracesObject in $ETWTracesObjectList){
				ForEach($Provider in $ETWTracesObject.Providers){
					If($Provider -like "*!*"){ # Multi etl
						$TraceFileName = ($Provider -split '!')[1]  # 2nd token is trace name
						$TraceName = $ETWTracesObject.Name + $TraceFileName
						$FoundTrace = $TraceList | Where-Object {$_ -eq $TraceName}
						If($FoundTrace -eq $Null){
							LogDebug "1: Adding $TraceFileName in $($ETWTracesObject.Name) to TraceList"
							$TraceList.Add($TraceName)
						}
					}Else{ # Normal trace
						LogDebug "2: Adding $($ETWTracesObject.Name) to TraceList"
						$TraceList.Add($ETWTracesObject.Name)
						break
					}
				}
			}
		}Else{
			LogDebug "No ETW traces found."
		}

		$AutoLogTraceCount = $TraceList.Count

		# Add ETW session count for commands
		ForEach($Key in $ETWSessionCountForCommand.Keys){
			$CommandTraceObject = $Null
			$CommandTraceObject = $AutoLog | Where-Object {$_.Name -eq $Key}
			If($CommandTraceObject -ne $Null){
				LogDebug "3: Adding $Key with trace count ($($ETWSessionCountForCommand[$Key])) to AutoLogTraceCount"
				$AutoLogTraceCount += $ETWSessionCountForCommand[$Key]
			}
		}

		# Get number of existing trace sessions
		$MaxETWSessionCount = 56	#we# system wide max number of sessions 
		$RunningSessionList = $Null
		$RunningSessionList = GetETWSessionByLogman
		$SessionCount = $RunningSessionList.Count
		$TotalExpectedTraceCount = $SessionCount + $AutoLogTraceCount + 3	#we# +3, as Network scenarios often fail with error 1450 = ERROR_NO_SYSTEM_RESOURCES, as i.e. netsh needs an additional session
		LogInfoFile "No. of AutoLog trace session=$AutoLogTraceCount / Existing sessions=$SessionCount"
		If($TotalExpectedTraceCount -gt $MaxETWSessionCount){
			LogInfo "Number of trace session ($AutoLogTraceCount for AutoLog plus $SessionCount for existing sessions) will exceed system wide max number of session ($MaxETWSessionCount). Trying to stop unnessessary running ETW sessions."
			# Stopping unnecessary sessions
			$DeletedTraceCount=0
			ForEach($RunningSession in $RunningSessionList){
				Write-Output "Running logman.exe -stop $RunningSession -ets" | Out-File -Append "$global:LogFolder\Stopped-ETWSessionList.txt"
				Write-Output "logman.exe -stop $RunningSession -ets" | Out-File -Append "$global:LogFolder\LogManStop.cmd"
				logman.exe -stop $RunningSession -ets | Out-File -Append "$global:LogFolder\Stopped-ETWSessionList.txt"
				If($LASTEXITCODE -eq 0){
					$DeletedTraceCount++
				}
			}
			LogWarn "$DeletedTraceCount traces has been stopped to create room to run AutoLog. See `'Stopped-ETWSessionList.txt`' in $global:LogFolder to see stopped traces."

			# Double check if we have enough space to run etw trace by AutoLog.
			$RunningSessionList = $Null
			$RunningSessionList = GetETWSessionByLogman
			$SessionCount = $RunningSessionList.Count
			$TotalExpectedTraceCount = $SessionCount + $AutoLogTraceCount
			# If total number of session is still larger than $MaxETWSessionCount, show error message and exit.
			If($TotalExpectedTraceCount -gt $MaxETWSessionCount){
				LogError "Number of trace session($AutoLogTraceCount for AutoLog and $SessionCount for existing sessions) will be $TotalExpectedTraceCount and it exceeds system total maximum number of session($MaxETWSessionCount)."
				Write-Host "Please try manually run $global:LogFolder\LogManStop.cmd from elevated commpand prompt to reduce running ETW sessions. And then run AutoLog again."
				Write-Host "> $global:LogFolder\LogManStop.cmd" -ForegroundColor Yellow
				CleanUpAndExit
			}
		}

		# Check 4: Check if there is enough free space
		$LogDrive = $global:LogFolder.Substring(0, 1)
		LogDebug "Log drive is $LogDrive drive (Log folder = $global:LogFolder)"
		If($LogDrive -eq "\"){
			$FreeInMB = $Null # This is network drive and we won't calculate free size in this case.
		}Else{
			$Drive = Get-PSDrive $LogDrive
			$FreeInMB = [Math]::Ceiling(($Drive.Free / 1024 / 1024))
		}

		If($FreeInMB -ne $Null){
			$EstimatedLogSizeInMB = CalculateLogSize
			If($EstimatedLogSizeInMB -ne $Null){
				# Show caluculated size and if it is larger than available space, ask user if he wants to continue.
				LogInfo ("Estimated max log size = " + [Math]::Ceiling($EstimatedLogSizeInMB / 1024) + "GB (Free size of $Drive drive = " + [Math]::Ceiling($FreeInMB / 1024) + "GB)`n") "Cyan"
				If($EstimatedLogSizeInMB -gt $FreeInMB){
					LogInfo ("$global:ScriptPrefix may consume " + $EstimatedLogSizeInMB / 1024 + "GB at the maximum but free size of $Drive drive is " + [Math]::Ceiling($FreeInMB / 1024) + "GB.") "Magenta"
					LogInfo ("You can change log folder using -LogFolderName switch.") "Cyan"
					LogInfo ("Example: .\$ScriptName -Start -<TraceSwitch> -LogFolderName D:\AutoLog") "Cyan"
					FwPlaySound
					# Issue#373 - AutoLog hang in ISE
					$Answer = FwRead-Host-YN -Message "Do you want to continue collecting data?" -Choices 'yn'
					#CHOICE /C yn /M " Do you want to continue collecting data? "
					If(!$Answer) {
						LogInfo "Exiting script."
						CleanUpAndExit
					}
				}
			}
		}
	}Else{
		LogDebug "AutoLog is empty."
		Return
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CalculateLogSize{
	[OutputType([Int])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name

	If($AutoLog.Count -eq 0){
		LogError "$AutoLog has not been initialized yet."
		Return $Null
	}

	# WPR
	If($global:BoundParameters.ContainsKey('WPR')){
		LogInfo "WARNING: WPR might consume large amount of free disk space if you run for long term. Use -Xperf instead in case you need to limit disk usage." "Magenta"
		LogInfo "Ex) .\AutoLog.ps1 -Xperf General -XperfMaxSize 10240  # Limit log size to 10GB"

		# Below calculation is applicable for in-memory mode but we use it for file mode as well since we don't have formula for file mode.
		$MemorySizeInGB = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).Sum /1gb
		$LogSizeInGB.WPR = [Math]::Round(($MemorySizeInGB * 0.8), [MidpointRounding]::AwayFromZero)  # 80% of total amount of physical memory.(Issue#407)
	}

	# Xperf
	If($global:BoundParameters.ContainsKey('XperfMaxFile')){
		$XperfMaxSizeInGB = [Math]::Round(($global:BoundParameters['XperfMaxFile'] / 1024), [MidpointRounding]::AwayFromZero)
		If([String]::IsNullOrEmpty($XperfMaxSizeInGB) -or $XperfMaxSizeInGB -le 0){
			$XperfMaxSizeInGB = 2
		}
		$LogSizeInGB.Xperf = $XperfMaxSizeInGB
	}

	# Calculate estimated log size and if free size of log drive is not enough, show warning message
	$EstimatedLogSize = 0
	If($AutoLog.Count -ne 0){
		# 1. We caluculate size of all ETW traces. It is caluculated with 2GB per a trace.
		$ETWTraceObjects = $AutoLog | Where-Object {$_.LogType -eq 'ETW'}
		$EstimatedLogSizeInMB = $ETWTraceObjects.Count * $Script:ETLMaxSize # $Script:ETLMaxSize = 1024MB by default
		LogDebug ("Added " + [Math]::Ceiling($EstimatedLogSizeInMB / 1024) + "GB for ETW")

		# Caluculate size of multiple etl file trace.
		ForEach($TraceObject in $ETWTraceObjects){
			$ETLFileList = New-Object 'System.Collections.Generic.List[PSObject]'
			# Counting number of files in this trace provider list
			ForEach($TraceProvider in $TraceObject.Providers){
				$Token = $TraceProvider -split '!'
				If($Token.Count -gt 1){
					$EtlFile = $Token[1] # 2nd token is etl file name
					$EtlFileInFileList = $ETLFileList | Where-Object {$_ -eq $EtlFile}
					If($EtlFileInFileList -eq $Null){
						$ETLFileList.Add($EtlFile)
					}
				}
			}
			If($ETLFileList.Count -gt 1){
				# Multiple etl files case
				$EstimatedLogSizeInMB += (($ETLFileList.Count - 1) * $Script:ETLMaxSize)
				LogDebug ("Found multi etl files trace($($TraceObject.Name)). This trace contains $($ETLFileList.Count) files and adding " + (($($ETLFileList.Count)-1) * $Script:ETLMaxSize / 1024) + "GB")
			}
		}

		# 2. Add log size for command switch
		ForEach($Key in $CommandSwitches.Keys){
			If($global:ParameterArray -Contains $Key){
				LogDebug "Adding $($LogSizeInGB.$Key)GB for $Key"
				$EstimatedLogSizeInMB += ($LogSizeInGB.$Key * 1024)
			}
		}
	}
	LogDebug ("Log size = " + [Math]::Ceiling($EstimatedLogSizeInMB / 1024) + "GB")
	EndFunc ($MyInvocation.MyCommand.Name + "($EstimatedLogSizeInMB)")
	Return $EstimatedLogSizeInMB
}

Function RegisterPurgeTask{
	EnterFunc $MyInvocation.MyCommand.Name
	If($global:OSVersion.Build -gt 9200){	#_# Get-ScheduledTask is not supported on 2008-R2
		$TaskIntervalInMinute = 5 # 5 minutes interval by default
		$PurgeScriptName = "$global:ScriptsFolder\tss_Purgelog.ps1"
		If($StartAutologger.IsPresent){
			$PurgeTaskName = $Script:PurgeTaskNameForAutologger
			$Trigger = New-ScheduledTaskTrigger -AtStartup
		}Else{
			$PurgeTaskName = $Script:PurgeTaskName
			$Trigger = New-ScheduledTaskTrigger -once -at (get-date)
		}
		
		If(!(Test-Path -Path "$global:ScriptsFolder\tss_Purgelog.ps1")){
			Throw "tss_Purgelog.ps1 not found."
		}
		
		# Create purge task
		$Actions = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument "& $PurgeScriptName"
		$Principal = New-ScheduledTaskPrincipal -UserID 'SYSTEM' -RunLevel Highest
		$Settings = New-ScheduledTaskSettingsSet
		$task = New-ScheduledTask -Action $Actions -Principal $Principal -Trigger $Trigger -Settings $Settings
		LogInfo "Registering a task($PurgeTaskName) to purge log files."
		Register-ScheduledTask -TaskName $PurgeTaskName -InputObject $task -ErrorAction Ignore | Out-Null
		
		# Add repetition settings.
		$t = Get-ScheduledTask -TaskName $PurgeTaskName
		$t.Triggers.Repetition.Interval = ("PT" + $TaskIntervalInMinute + "M")
		Set-ScheduledTask -InputObject $t | Out-Null
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function UnRegisterPurgeTask{
	EnterFunc $MyInvocation.MyCommand.Name
	If($global:OSVersion.Build -gt 9200){	#_# Get-ScheduledTask is not supported on 2008-R2
		$TaskNames = @($Script:PurgeTaskName, $Script:PurgeTaskNameForAutologger)
		ForEach($TaskName in $TaskNames){
			$Task = $Null
			$Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Ignore
			If($Task -ne $Null){
				LogInfo "Deleting `'$TaskName`' task."
				Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
			}
		}

		$PurgeLog = "C:\Windows\temp\$($env:COMPUTERNAME)__Log-PurgeTask.txt"
		If(Test-Path -Path $PurgeLog){
			Move-Item $PurgeLog $global:LogFolder -ErrorAction SilentlyContinue
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

#endregion FW Core functions

#region monitoring functions
Function Test_File{
	[OutputType([Bool])]
	param(
		[ValidateNotNullOrEmpty()]
		[Parameter(Mandatory=$True)]
		[String]$FilePath,
		[Parameter(Mandatory=$False)]
		[Bool]$SignalOnCreation = $False
	)
	LogDebug "Test_File with $FilePath is called($SignalOnCreation)."

	If(Test-Path $FilePath){
		If($SignalOnCreation){
			LogInfo "File $FilePath got created. Test_File is signaled." "Red"
			# copy new file 
			Copy-Item $FilePath -Destination $global:LogFolder
			Return $False # Signaled.
		}Else{
			Return $True
		}
	}Else{
		If($SignalOnCreation){
			Return $True
		}Else{
			LogInfo "File $FilePath got removed. Test_File is signaled." "Red"
			Return $False # Signaled
		}
	}
}

Function Test_RegData{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyRoot,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyPath,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$ValueName,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$ExpectedData,
		[Parameter(Mandatory=$False)]
		[Bool]$IsOpposite = $False
	)

	$RegKeyPath = $KeyRoot + ":\" + $KeyPath
	$RegFullPath = $RegKeyPath + "\" + $ValueName # Used only for debug message
	LogDebug "Test_RegData for $RegFullPath with expected value $ExpectedData is called."

	$RegData = Get-ItemProperty $RegKeyPath -name $ValueName -ErrorAction Ignore
	If(($RegData -ne $Null) -and ($RegData.$ValueName -eq $ExpectedData)){
		If($IsOpposite){
			LogDebug "$ValueName is still $($RegData.$ValueName)"
			Return $True
		}Else{
			LogInfo "$ValueName becomes $ExpectedData. Test_Reg for $RegFullPath is signaled." "Red"
			Return $False # Signaled(Expected data is set to the registry.
		}
	}Else{
		If($IsOpposite){
			LogInfo "$ValueName was changed to $($RegData.$ValueName). Test_Reg for $RegFullPath is signaled." "Red"
			Return $False # Signaled
		}Else{
			LogDebug "`'$RegFullPath`' does not exist or value($($RegData.$ValueName)) is not expected value($ExpectedData) yet."
			Return $True
		}
	}
}

Function Test_RegValue{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyRoot,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyPath,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$ValueName,
		[Parameter(Mandatory=$False)]
		[Bool]$IsOpposite = $False
	)

	$RegKeyPath = $KeyRoot + ":\" + $KeyPath
	$RegFullPath = $RegKeyPath + "\" + $ValueName # Used only for debug message
	LogDebug "Test_RegValue for `'$RegFullPath`' is called."

	# Check if key exists
	Try{
		$KeyObject = Get-ItemProperty -Path $RegKeyPath -ErrorAction Stop
	}Catch{
		If($IsOpposite){
			Return $True
		}Else{
			LogInfo "Key `'$RegKeyPath`' does not exist. Test_RegValue is signaled." "Red"
			Return $False # Signaled. Key is aleady removed hence report as a signaled case.
		}
	}

	# Check if the value exists
	If($KeyObject.$ValueName -eq $Null){
		If($IsOpposite){
			Return $True
		}Else{
			LogInfo "Value `'$RegFullPath`' got removed. Test_RegValue is signaled." "Red"
			Return $False # Signaled. Value got moved.
		}
	}Else{
		If($IsOpposite){
			LogInfo "Value `'$RegFullPath`' got created. Test_RegValue is signaled." "Red"
			Return $False # Signaled. Value got created.
		}Else{
			Return $True
		}
	}
}

Function Test_RegKey{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyRoot,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$KeyPath,
		[Parameter(Mandatory=$False)]
		[Bool]$IsOpposite = $False
	)

	$RegKeyPath = $KeyRoot + ":\" + $KeyPath
	LogDebug "Test_RegKey for `'$RegKeyPath`' is called."

	# Check if key exists
	If(Test-Path $RegKeyPath){
		If($IsOpposite){
			LogInfo "Key `'$RegKeyPath`' got created. Test_RegValue is signaled." "Red"
			Return $False
		}Else{
			Return $True # Signaled. Key was created hence report as a signaled case.
		}
	}Else{
		If($IsOpposite){
			Return $True
		}Else{
			LogInfo "Key `'$RegKeyPath`' got removed. Test_RegValue is signaled." "Red"
			Return $False # Signaled. Key was removed hence report as a signaled case.
		}
	}
}

Function Test_PortLoc{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$PortLoc
	)
	LogDebug "Test_PortLoc with port $PortLoc is called."

	$Ports = $PortLoc -split '/'
	$Count = $Ports.Count
	ForEach($PortNumber in $Ports){
		$TcpTestStatus = Get-NetTCPConnection -State Listen -LocalPort $PortNumber -ErrorAction Ignore
		If(($TcpTestStatus -eq $Null) -or ($TcpTestStatus.TcpTestSucceeded -eq $False)){
			LogInfo "Test_PortLoc for $PortNumber is signaled." "Red"
			$Count--
		}
	}
	If($Count -eq 0){
		LogInfo "Test_PortLoc is signaled." "Red"
		Return $False # signaled.
	}Else{
		Return $True
	}
}

Function Test_PortDest{
	#we# consider FwTest-TCPport
	[OutputType([Bool])]
	param(
		[ValidateNotNullOrEmpty()]
		[String]$ServerName,
		[ValidateNotNullOrEmpty()]
		[String]$Port
	)
	LogDebug "Test_PortDest with port $Port on $ServerName is called."
	$Ports = $Port -split '/'
	$Count = $Ports.Count
	ForEach($PortNumber in $Ports){
		$TcpTestStatus = Test-Netconnection -ComputerName $ServerName -Port $PortNumber -InformationLevel "Detailed" -ErrorAction Ignore -WarningAction Ignore
		If(($TcpTestStatus -eq $Null) -or ($TcpTestStatus.TcpTestSucceeded -eq $False)){
			LogInfo "Test_PortDest for port $PortNumber on $ServerName is signaled." "Red"
			$Count--
		}
	}

	If($Count -eq 0){
		LogInfo "Test_PortDest is signaled." "Red"
		Return $False # signaled.
	}Else{
		Return $True
	}
}

Function Test_Share{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$ServerName,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$ShareName
	)
	$SharePath = "\\$ServerName\$ShareName"
	LogDebug "Test_Share with $SharePath is called."

	# check if $ShareName is reachable via SMB
	If((Test-Path $SharePath)){
		Return $True
	}Else{
		LogInfo "Test_Share for unreachable $SharePath is signaled." "Red"
		Return $False # Signaled
	}
} 

Function Test_LogFile{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$LogFilePath,
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String]$SearchString
	)
	LogDebug "Test_LogFile for Search-string $SearchString exists in file $LogFilePath is called."
	If(Select-String -Path $LogFilePath -Pattern $SearchString){
		LogInfo " => please be sure that the Search-string (or RegEx) '$SearchString' in file '$LogFilePath' is not already existant at start of tracing." "Magenta"
	}
	# check if string $SearchString does not exist in Log file $LogFilePath
	If(!(Select-String -Path $LogFilePath -Pattern $SearchString)){
		# copy Log file
		Copy-Item $LogFilePath -Destination $global:LogFolder
		Return $True
	}Else{ # $SearchString found!
		LogInfo "Test_LogFile for Search-string '$SearchString' in file '$LogFilePath' is signaled." "Red"
		Return $False # Signaled
	}
}

Function Test_CommonTCPPort{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[ValidateSet("SMB", "HTTP", "RDP", "WINRM")]
		[String]$Protocol,
		[Parameter(Mandatory=$False)]
		[String]$ServerName
	)
	LogDebug "Test_CommonTCPPort with $Protocol on $ServerName is called."

	$TcpTestStatus = Test-NetConnection -ComputerName $ServerName -CommonTCPPort $Protocol -InformationLevel "Detailed" -ErrorAction Ignore -WarningAction Ignore
	If($TcpTestStatus -eq $Null){
		LogError "ERROR: Someting wrong happend in Test-Netconnection. Return false so that monitor function to be existed."
		Return $False
	}
	If(!($TcpTestStatus.TcpTestSucceeded)){
		LogInfo "$ServerName stopped listening on $Protocol. TestCommonTCPPort is signaled." "Red"
		Return $False # Signaled
	}Else{
		Return $True
	}
	Return $True
}

Function Test_LDAP{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[String]$DomainName
	)
	LogDebug "Test_LDAP with $DomainName is called."
	$TestStatus = nltest /DSGETDC:$DomainName /LDAPONLY | Out-Null
	If($LASTEXITCODE -ne 0 ){
		LogInfo "DC in Domain $DomainName is not reachable via /LDAPONLY, result: $TestStatus - LASTEXITCODE: $LASTEXITCODE" "Red"
		Return $False # Signaled
	}
	Return $True
}

Function Test_HNSL2Tunnel{
	#[OutputType([Bool])]
	LogDebug "Test_HNSL2Tunnel gone is called."
	if (get-command Get-HNSNetwork -ErrorAction SilentlyContinue) {
		$HNSL2Tunnel = Get-HNSNetwork | where {($_.Type -eq "l2tunnel")}
		if ("$HNSL2Tunnel" -eq "$null" ) {
			LogInfo "L2Tunnel Network gone is signaled" "Red"
			Return $False # Signaled
		}
		Return $True
	}Else{ LogInfo "WARNING: There is no HNSL2Tunnel on this system" "Magenta"}
}

Function Test_Svc{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $SvcName
	)
	LogDebug "Test_Svc with $SvcName is called."

	# check if service status is Running  (not Stopped)
	$SvcStatus = ((Get-Service $SvcName -ErrorAction Ignore).Status)
	#_#if ($SvcStatus -ne "Running"){
	if ($SvcStatus -ne [System.ServiceProcess.ServiceControllerStatus]::Running){
		LogInfo "$SvcName stopped running: $SvcStatus. Test_Svc is signaled." "Red"
		Return $False # Signaled
	}Else{
		Return $True
	}
} 

Function Test_Process{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[String] $ProcessName
	)
	LogDebug "Test_Process with $ProcessName is called."

	# check if Process is running 
	$ProcessObject = Get-Process -Name $ProcessName -ErrorAction Ignore
	If($ProcessObject -eq $Null){
		LogInfo "$ProcessName is not running. Test_Process is signaled." "Red"
		Return $False # Signaled
	}Else{
		Return $True
	}
}

Function Test_EventLog{
	<# Name: Test_EventLog [-EventIDs -EventlogName -CheckIntInSec -WaitTimeInSec -EventData -EvtDataPartial -EvtDataOperator]
		
	if you invoke from CMD:
	 PowerShell -noprofile "&{Invoke-Command -ScriptBlock {$EventID=30800;$SearchBackTime=60000;$EventlogName="Microsoft-Windows-SmbClient/Operational"; Get-WinEvent -LogName $EventlogName -FilterXPath "*[System[EventID=$EventID and TimeCreated[timediff(@SystemTime) <= $SearchBackTime]]]" -MaxEvents 5 -ErrorAction SilentlyContinue}}"
	 PowerShell -noprofile "&{Invoke-Command -ScriptBlock {Get-WinEvent -LogName "Microsoft-Windows-SmbClient/Operational"  -FilterXPath "*[System[EventID=30800]]" -MaxEvents 3 -ErrorAction SilentlyContinue }}"

		#Eventlogs location on disk: "C:\Windows\System32\winevt\Logs\Microsoft-Windows-SmbClient%4Operational.evtx"
	Example to delete Source
	 Get-CimInstance win32_nteventlogfile -Filter "logfilename='Microsoft-Windows-SmbClient/Operational'" | foreach {$_.sources}
	 Remove-Eventlog -Source "TSS"

	For Testing:
	 you can watch for 40961/40962 in "Microsoft-Windows-PowerShell/Operational", which is logged when starting a  new PoSh window

	.SYNOPSIS
	Purpose: Monitor Eventlogs for specific event and stop script; in combi with TSS: stop the script based on EventIDs in a non classic Eventlog
		The stop trigger condition is true if the EventID is found in specified Eventlog up to CheckIntInSec back in time, the control is given back to calling script.
		From CMD script you can invoke this PowerShell script by: PowerShell -noprofile -file "tss_EvtMon.ps1" -EventID 30800 -EventlogName "Microsoft-Windows-SmbClient/Connectivity" -EventData 0
		Multiple EventIDs are separated by '/', for example -EventID 40961/40962
		Multiple EventData strings are separated by '/', for example -EventData C:\Windows\System32\calc.exe/C:\Windows\System32\cmd.exe

	If you experience PS error '...is not digitally signed.' change Policy to RemoteSigned or Bypass by running the command:
	 Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
	 
	SYNTAX: MonitorEventLog -EventID 30800 -EventlogName "Microsoft-Windows-SmbClient/Connectivity" -EventData 'find-my-string'


	.DESCRIPTION
	The script will stop, once the specific details EventID(s) and Eventdata string(s) are all met.
	You need to run the script in Admin PowerShell window, if you want to monitor 'Security' Event Log
	You can append the -verbose parameter to see more details.
	When entering -EventData string, please enter the complete string as seen in Event 'XML View', for example 'C:\Windows\System32\calc.exe'
	 as seen in 'XML View' <Data Name="NewProcessName">C:\Windows\System32\calc.exe</Data> 
	In additin to any specific EventID, the script will also listen on EventID 999 in Application eventlog, and stop when it sees 999 sent by a remote system as a stop trigger.

	.PARAMETER EventIDs
		The Event ID wot watch for, separate multiple IDs with '/', Ex.: 30800/30809
	.PARAMETER CheckIntInSec
		Specify how often (time-interval in seconds) to search for given EventID(s)
	.PARAMETER EventlogName
		Specify name of Eventlog, i.e. "Microsoft-Windows-PowerShell/Operational" or "Microsoft-Windows-SmbClient/Operational"
	.PARAMETER WaitTimeInSec
		Force a wait time in seconds after an event is found,  this will instruct tss to stop x seconds later.
	.PARAMETER EventData
		Specify a complete string that is seen in Eventlog XML view <Data>"your complete string"</Data>
	.PARAMETER EvtDataPartial
		Specify a unique keyword that is part of the complete message, to allow search for partial event data message
		This does not require a full string between <Data> .. </Data>, partial match is ok
	.PARAMETER EvtDataOperator
		combine multiple EventData search terms by AND or OR operator (default = OR)
		
	.EXAMPLE
	 MonitorEventLog -EventID 30800 -EventlogName "Microsoft-Windows-SmbClient/Connectivity" -EventData 0

	.EXAMPLE
	 MonitorEventLog -EventID 4688/4689 -EventlogName "Security" -EventData C:\Windows\System32\calc.exe/C:\Windows\System32\cmd.exe -verbose
	 
	This will monitor for multiple EventIDs  4688 and 4689, checking if either string 'C:\Windows\System32\calc.exe' or 'C:\Windows\System32\cmd.exe' exist in given EventID(s) 

	.EXAMPLE
	 MonitorEventLog -EventID 40961/40962 -EventlogName "Microsoft-Windows-PowerShell/Operational" -EventData 0
	 
	 This will monitor for multiple EventIDs 40961 and 40962 in Microsoft-Windows-PowerShell/Operational, will be triggered as soon as a new PowerShell window opens

	.EXAMPLE
	 MonitorEventLog -EventID 4624 -EventlogName "Security" -EventData "Contoso.com/User1" -EvtDataPartial -EvtDataOperator "AND"
	 
	 This will monitor for EventID 4624 in Security eventlog, will be triggered as soon as a Logon attempt from "User1" in domain "Contoso.com" is logged, AND means both criteria must match; omitting -EvtDataOperator or choosing "OR" will fire if one criteria is found in EventID 4624
	 
	 
	 .EXAMPLE

	  [Info] for testing it is sufficient to specify an existing "Source", i.e.
	  Write-EventLog -LogName "Application" -Source "Outlook" -EventID 59 -EntryType Information -Message "Test this EventID as stop trigger." -Category 1 -RawData 10,20 -ComputerName $Env:Computername
	  Note, you can also use the script tss_EventCreate.ps1 to fire such event.

	.OUTPUTS
	Returns $True if the specified event is not recorded. Return $False if the event is recorded.

	.LINK
	waltere@microsoft.com;Sergey.Akinshin@microsoft.com
	#>
	[OutputType([Bool])]
	Param(
		[Parameter(Mandatory=$True,Position=0,HelpMessage='Choose the EventID, or multiple separated by slash / ')]
		[string[]]$EventIDs, 		# separate multiple IDs with '/', Ex.: 30800/30809
		[Parameter(Mandatory=$False,Position=2,HelpMessage='Choose name of EventLog-File' )]
		[string]$EventlogName, 		# name of Eventlog, i.e. "Microsoft-Windows-PowerShell/Operational" #"Microsoft-Windows-SmbClient/Operational"
		[Parameter(Mandatory=$False,Position=3,HelpMessage='Choose the amount of time to search back in seconds ')]
		[Int32]$CheckIntInSec = 0,	# specify time-interval in seconds to search back, # how often in seconds should the evenlog file be scanned?
		[Parameter(Mandatory=$False,Position=4,HelpMessage='Choose Stop WaitTime in Sec')]
		[Int32]$WaitTimeInSec = 0,	# this specifis the forced wait time after an event is detected
		[Parameter(Mandatory=$False,Position=5,HelpMessage='optional: complete string in any EventData, or multiple separated by slash / ')]
		[string[]]$EventData = '0',	#'3221226599' # = STATUS_FILE_NOT_AVAILABLE / '3221225996' = STATUS_CONNECTION_DISCONNECTED / '0' = STATUS_SUCCESS
		[Parameter(Mandatory=$False,Position=6,HelpMessage='Search for keywords in event Message')]
		[Switch]$EvtDataPartial,	# allow search for partial event data message
		[Parameter(Mandatory=$False,Position=7,HelpMessage='choose operator for EventData: AND OR')]
		[string]$EvtDataOperator="OR",	# AND will fire only if both conditions are true
		[Parameter(Mandatory=$False,Position=8,HelpMessage='choose operator for EventData: AND OR')]
		[string]$EvtMaxEvents=1		# number of latest events with same EventID to investigate;
	)
	EnterFunc $MyInvocation.MyCommand.Name
	[Int32]$MaxEvents = $EvtMaxEvents	# Specifies the maximum number of events that Get-WinEvent returns.  
	[Int32]$SearchBackTime = 0 #amount of time in MilliSec to search back
	[string[]]$Event_ID_list=$EventIDs.split("/")
	[array]$xpaths= @()
	$EvtDataStrings = $EventData.split("/")
	[string]$EvtDataStrings_Or = $EventData.replace("/","|")  # default OR operator in partial EventData search
	[string[]]$EvtDataStrings_And = $EventData.Split("/")  # implement AND operator for multple partial EventData words

	If($CheckIntInSec -gt 0){
		LogDebug "Sleep $CheckIntInSec(CheckIntInSec) seconds."
		Start-Sleep -second $CheckIntInSec
	}

	# Check if the evenlog log name is valid.
	Try{
		$logDetails =  Get-WinEvent -ListLog $EventlogName -ErrorAction Stop
	}Catch{
		$PossibleEventLogNames = @()
		$Tokens = $EventlogName -split ' '
		ForEach($Token in $Tokens){
			LogInfo "$Token"
			$PossibleEventLogNames += Get-WinEvent -ListLog "*$Token*" -ErrorAction Ignore
		}
		$Tokens = $EventlogName -split '/'
		$PossibleEventLogNames += Get-WinEvent -ListLog "*$($Tokens[0])*" -ErrorAction Ignore
		If($PossibleEventLogNames.Count -ne 0){
			LogWarn "Unable to find `'$EventlogName`'"
			$PossibleEventLogNames = $PossibleEventLogNames | Get-Unique
			LogInfo "Possible correct Event log name would be following:"
			ForEach($PossibleEventLogName in $PossibleEventLogNames){
				$PossibleEventLogName
				Write-Host "   - $($PossibleEventLogName.LogName)"
			}
		}
		LogError "Unable to find `'$EventlogName`'. The name of the event log might not be valid."
		Throw $_ # Rethrow the exception to go into recovery process.
	}

	# Remove '-' and '/'. We will create a valuable this is the name for it.
	$tempName = $EventlogName -replace "-",""
	$EventlogNameForValuable = $tempName -replace "/",""
	$FwLastSearchStartTime = ($EventlogNameForValuable + $Event_ID_list[0])
	$CurrentTime = Get-Date

	$LastSearchTime = Get-Variable -Name $FwLastSearchStartTime -Scope Script -ValueOnly -ErrorAction Ignore
	If($LastSearchTime -eq $Null){
		New-Variable -Name $FwLastSearchStartTime -Scope Script -Value (Get-Date)
		$LastSearchTime = Get-Variable -Name $FwLastSearchStartTime -Scope Script -ValueOnly
		$TimeDiff = New-TimeSpan $FwScriptStartTime $CurrentTime
		LogDebug "Script start time			 : $FwScriptStartTime"
	}Else{
		$TimeDiff = New-TimeSpan $LastSearchTime $CurrentTime
	}

	$SearchBackTime = $TimeDiff.TotalSeconds * 1000 + 1000 # Interval sec from last search or script start time + 1 sec(buffer).

	# For debug log
	Set-Variable -Name $FwLastSearchStartTime -Scope Script -Value (Get-Date) # Update last search time. This is used when this function is called next time.
	$LastSearchTimeVariable = Get-Variable -Name $FwLastSearchStartTime -Scope Script # $LastSearchTimeVariable is used for just message only
	LogDebug "Eventlog name                 : $EventlogName"
	LogDebug "EventIDs                      : $Event_ID_list"
	LogDebug "Last search time variable name: $($LastSearchTimeVariable.Name)"
	LogDebug "Last search start time        : $LastSearchTime"
	LogDebug "Current time                  : $CurrentTime"
	LogDebug "SearchBackTime                : $SearchBackTime msec" # Search back time
	LogDebug "EvtDataStrings:"
	ForEach($EvtDataString in $EvtDataStrings){
		LogDebug "	- $EvtDataString"
	}
	LogDebug "EvtDataStrings_Or:  $EvtDataStrings_Or"
	LogDebug "EvtDataStrings_And: count: $($EvtDataStrings_And.count) Search for: [1] $($EvtDataStrings_And[0]) AND [2] $($EvtDataStrings_And[1])"
	
	foreach ($EventID in $Event_ID_list){
		if ($EvtDataPartial) {	# This does not require a full string between <data> .. </data>, partial match is ok
			$xpath = 
@"
*[System[TimeCreated[timediff(@SystemTime) <= $SearchBackTime]]
[EventID=$EventID]]
"@
			$xpaths += $xpath
			LogDebug "---- EventID: $EventID - Xpath: `n$xpath"
		}Else{ # full match of 'EvtDataString'
			foreach($EvtDataString in $EvtDataStrings){
				if($EventData -ne '0'){
					LogDebug "EventData=$EvtDataString"
					$xpath = 
@"
*[System[TimeCreated[timediff(@SystemTime) <= $SearchBackTime]]
[EventID=$EventID]]
[EventData[Data='$EvtDataString']]
"@
				}Else{
					$xpath = 
@"
*[System[TimeCreated[timediff(@SystemTime) <= $SearchBackTime]]
[EventID=$EventID]]
"@
				}
				$xpaths += $xpath
			}
			LogDebug "---- EventID: $EventID - Xpath: `n$xpath"
		}
	}

	$IsFound = $False
	If($EvtDataPartial -and ($EvtDataOperator -ne "OR")){
		# Partial Event message and Operator = "AND"
		LogDebug "-- xpathCount: $($xpaths.count)"
		ForEach($xpath in $xpaths){
			LogDebug "1(Partial + AND): Get-WinEvent -LogName $EventlogName -MaxEvents $MaxEvents -FilterXPath $xpath -ErrorAction Ignore | Select-Object -Property Properties -ExpandProperty Properties with `'$EvtDataStrings_And`'"
			$Events = Get-WinEvent -LogName $EventlogName -MaxEvents $MaxEvents -FilterXPath $xpath -ErrorAction Ignore | Select-Object -Property Properties -ExpandProperty Properties
			If($Events -eq $Null){
				LogDebug "1: No event found."
			}
			ForEach($Event in $Events){
				LogDebug "1: Found event: $($Event.Value)"
				$Count = 0
				ForEach($EvtDataString in $EvtDataStrings_And){
					If([String]($Event.Value) -match $EvtDataString){
						$Count++
						LogDebug "1: Event message `"$($Event.Value)`" matches `'$EvtDataString`'(count=$Count/$($EvtDataStrings_And.count))"
						If($Count -eq $EvtDataStrings_And.Count){
							# Met all search keywords!
							If($WaitTimeInSec -ne 0){
								LogDebug "1: Wait for $WaitTimeInSec seconds."
								Start-Sleep -second $WaitTimeInSec
							}
							$IsFound = $True
						}
					}
				}
			}
		}
	}Else{
		LogDebug "-- xpathCount: $($xpaths.count)"
		ForEach($xpath in $xpaths){
			# Partial Event message and Operator = "OR", or no Partial
			If($EvtDataPartial -and ($EventData -ne 0)){
				# search for partial string in EventData
				If($EvtDataOperator -ieq "OR"){ # Operator "OR", default
					LogDebug "2(Partial + OR): Get-WinEvent -LogName $EventlogName -MaxEvents $MaxEvents -FilterXPath $xpath -ErrorAction Ignore | Select-Object -Property Properties -ExpandProperty Properties with `'$EvtDataStrings_Or`'"
					$Events = Get-WinEvent -LogName $EventlogName -MaxEvents $MaxEvents -FilterXPath $xpath -ErrorAction Ignore | Select-Object -Property Properties -ExpandProperty Properties
					ForEach($Event in $Events){
						If([String]($Event.Value) -match $EvtDataStrings_Or){
							LogDebug "Found `"$($Event.Value)`""
							If($WaitTimeInSec -ne 0){
								LogDebug "2: Wait for $WaitTimeInSec seconds."
								Start-Sleep -second $WaitTimeInSec
							}
							$IsFound = $True # Signaled.
						}
					}
				}
			}Else{
				# search for full string in EventData or only event id case(no event data search)
				$Message = "3(Full): Get-WinEvent -MaxEvents $MaxEvents -LogName $EventlogName -FilterXPath $xpath "
				LogDebug $Message
				$EvtEntry = Get-WinEvent -MaxEvents $MaxEvents -LogName $EventlogName -FilterXPath $xpath -ErrorAction Ignore |select Message,Id,TimeCreated
				If($EvtEntry -eq $Null){
					LogDebug "3: Get-WinEvent returns ObjectNotFound"
				}Else{
					LogDebug ("Get-WinEvent returns $EvtEntry")
					$IsFound = $True
					If($WaitTimeInSec -ne 0){
						LogDebug "3: Wait for $WaitTimeInSec seconds."
						Start-Sleep -second $WaitTimeInSec
					}
					$IsFound = $True # Signaled.
				}
			}
		}
	}
	EndFunc "$($MyInvocation.MyCommand.Name) with IsFound=$IsFound"
	If($IsFound){
		Return $False # Signaled.
	}Else{
		Return $True
	}
}

Function WaitTime{
	[OutputType([Bool])]
	param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[Int] $WaitTime,
		[Parameter(Mandatory=$True)]
		[Bool] $Second
	)

	If($Second){
		 LogDebug "Wait for $WaitTime seconds"
		$WaitSeconds = $WaitTime
	}Else{
		$WaitSeconds = ($WaitTime * 60)
	}
	Start-Sleep -Seconds $WaitSeconds
	Return $False
}

Function Test_StopCondition{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Test_StopCondition is called. If condition is met, signal event"
	if (Test-Path .\Config\StopCondition.txt){
		Try{
			$Result = Invoke-Command -ScriptBlock ([scriptblock]::Create((Get-Content ".\Config\StopCondition.txt")))
			if ($Result) {LogInfo "custom Test_StopCondition is $True => signal event." "Red"}
			Return !($Result) # (-not $True) = False = Signaled
		}Catch{ Throw $_ }
	}Else{ LogInfo "WARNING: The file .\Config\StopCondition.txt is missing" "Magenta"}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CreateTestProperty{
	[OutputType([System.Collections.Hashtable])]
	param(
		[Parameter(Mandatory=$True)]
		[String]$TestParameter
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " with $TestParameter")
	$Token = $TestParameter -split (':')
	$TestType = $Token[0]
	Switch($TestType){
		'PortLoc'{ # Test_PortLoc -Port <PortNumber>
			If($Token.Length -ne 2){
				LogError ("Passed parameter for PortLoc `'$TestParameter`' is invalid. See below usage.")
				LogError ("Example: -WaitEvent PortLoc:PortNumber => -WaitEvent PortLoc:3389")
				Return $Null
			}
			$params = @{Port = $Token[1]}
			$TestName = "Local port(PortLoc)-unreachable Test ($TestParameter)"
			$FunctionName = 'Test_PortLoc'
		}
		'PortDest'{ # Test_PortDest -ServerName [ServerName] -Port <PortNumber>
			If($Token.Length -ne 3){
				LogError ("Passed parameter for PortDest `'$TestParameter`' is invalid. See below usage.")
				LogError ("Example: -WaitEvent PortDest:RemoteServer:PortNumber => -WaitEvent PortDest:RemoteServer:445")
				Return $Null
			}
			$params = @{ServerName = $Token[1]; Port = $Token[2]}
			$TestName = "Remote port(PortDest)-unreachable Test ($TestParameter)"
			$FunctionName = 'Test_PortDest'
		}
		'Svc'{ # Test_Svc -SvcName <ServiceName>
			If($Token.Length -ne 2){
				LogError ("Passed parameter for Svc `'$TestParameter`' is invalid. See below usage.")
				LogError ("Example: -WaitEvent Svc:rpcss")
				Return $Null
			}
			$params = @{SvcName = $Token[1]}
			$TestName = "Svc(Service)-stopped Test ($TestParameter)"
			$FunctionName = 'Test_Svc'
		}
		'Share'{ # Test_Share -ServerName <ServerName> -ShareName <ShareName>
			If($Token.Length -ne 3){
				LogError ("Passed parameter for Share `'$TestParameter`' is invalid. See below usage.")
				LogError ("Example: -WaitEvent share:TestServer:ShareName")
				Return $Null
			}
			$params = @{ServerName = $Token[1]; ShareName = $Token[2]}
			$TestName = "Unreachable-File-Share Test ($TestParameter)"
			$FunctionName = 'Test_Share'
		}
		'LogFile'{ # Test_LogFile -LogFilePath <LogFilePath> -SearchString <SearchString>
			# As separator is ':', LogFilePath is split into two tokens; need to combine them again.
			$LogFilePath = $Token[1] + ':' + $Token[2]
			$LogFilePath = $LogFilePath -replace ("`"",'') # remove double quote
			$LogFilePath = $LogFilePath -replace ("`'",'') # remove single
			If($Token.Length -le 3){
				Write-host "Token.Length: $($Token.Length) - LogFilePath $LogFilePath -  $($Token[0]) - [1+2] $($Token[1]) + $($Token[2]) = $LogFilePath - SearchSTring: $($Token[3])"
				LogError ("Passed parameter for LogFile `'$TestParameter`' is invalid. See below usage.")
				LogInfo ("Example: -WaitEvent LogFile:'LogFilePath':'SearchString'")
				Return $Null
			}
			$params = @{LogFilePath = $LogFilePath; SearchString = $Token[3]}
			$TestName = "Search-String in LogFile Test ($TestParameter)"
			$FunctionName = 'Test_LogFile'
		}
		'Process'{ # Test_Process -ProcessName <ProcessName>
			If($Token.Length -ne 2){
				LogError ("Passed parameter for Process stopped`'$TestParameter`' is invalid")
				LogError ("Example: -WaitEvent Process:Notepad  Note: Don`'t add `'.exe`' for the process name.")
				Return $Null
			}
			$params = @{ProcessName = $Token[1]}
			$TestName = "Process-stopped Test ($TestParameter)"
			$FunctionName = 'Test_Process'
		}
		'LDAP'{ # Test_LDAP -DomainName <DomainName>
			If($Token.Length -ne 2){
				LogError ("Passed parameter for LDAP Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$params = @{DomainName = $Token[1]}
			$TestName = "LDAP-Domain Test ($TestParameter)"
			$FunctionName = 'Test_LDAP'
		}
		'SMB' { # Test_CommonTCPPort -Protocol SMB -ServerName <xxx>
			If($Token.Length -eq 1){
				$ServerName = 'localhost'
			}ElseIf($Token.Length -eq 2){
				$ServerName = $Token[1]
			}ElseIf($Token.Length -gt 2){
				LogError ("Passed parameter for SMB Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$params = @{Protocol = $Token[0]; ServerName=$ServerName}
			$TestName = "SMB Test ($TestParameter)"
			$FunctionName = 'Test_CommonTCPPort'
		}
		'HTTP' { # Test_CommonTCPPort -Protocol HTTP -ServerName <xxx>
			If($Token.Length -eq 1){
				$ServerName = 'localhost'
			}ElseIf($Token.Length -eq 2){
				$ServerName = $Token[1]
			}ElseIf($Token.Length -gt 2){
				LogError ("Passed parameter for HTTP Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$params = @{Protocol = $Token[0]; ServerName=$ServerName}
			$TestName = "HTTP Test ($TestParameter)"
			$FunctionName = 'Test_CommonTCPPort'
		}
		'RDP' { # Test_CommonTCPPort -Protocol RDP -ServerName <xxx>
			If($Token.Length -eq 1){
				$ServerName = 'localhost'
			}ElseIf($Token.Length -eq 2){
				$ServerName = $Token[1]
			}ElseIf($Token.Length -gt 2){
				LogError ("Passed parameter for RDP Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$params = @{Protocol = $Token[0]; ServerName=$ServerName}
			$TestName = "RDP Test ($TestParameter)"
			$FunctionName = 'Test_CommonTCPPort'
		}
		'WINRM' { # Test_CommonTCPPort -Protocol WINRM -ServerName <xxx>
			If($Token.Length -eq 1){
				$ServerName = 'localhost'
			}ElseIf($Token.Length -eq 2){
				$ServerName = $Token[1]
			}ElseIf($Token.Length -gt 2){
				LogError ("Passed parameter for WINRM Test `'$TestParameter`' is invalid")
				Return $Null
			}
			$params = @{Protocol = $Token[0]; ServerName=$ServerName}
			$TestName = "WINRM Test ($TestParameter)"
			$FunctionName = 'Test_CommonTCPPort'
		}
		'RegData' { # [RegData] Test_RegData -RegPath <xxx>
			# Expected format = RegData:$KeyRoot:$KeyPath:$ValueName:$ExpectedData => At least need 5 tokens
			If($Token.Length -lt 5){
				LogError ("Passed parameter for RegData test `'$TestParameter`' is invalid")
				LogError "Expected format is `'RegData:KeyRoot:KeyPath:ValueName:ExpectedData`' or `'RegData:KeyRoot:KeyPath:ValueName:ExpectedData:True`'"
				Return $Null
			}

			# Root key needs to be converted to PowerShell format
			Switch($Token[1]){
				'HKEY_LOCAL_MACHINE'{
					$KeyRoot = 'HKLM'
				}
				'HKEY_CURRENT_USER'{
					$KeyRoot = 'HKCU'
				}
				'HKEY_CLASSES_ROOT'{
					$KeyRoot = 'HKCR'
				}
				'HKLM'{$KeyRoot = $Token[1]}
				'HKCU'{$KeyRoot = $Token[1]}
				'HKCR'{$KeyRoot = $Token[1]}
				default{
					$KeyRoot = $Token[1]
					LogError ("Invalid key root `'$KeyRoot`' was specified.")
					Return $Null
				}
			}
			# Remove backslash at first string from registy key path
			$KeyPath = $Token[2]
			$KeyPath = [regex]::replace($KeyPath, "^\\", '') # \aaa\bbb => aaa\bbb

			# 
			If(($Token[5] -ne $Null) -and $Token[5] -eq 'True'){
				$IsOpposite = $True
			}Else{
				$IsOpposite = $False
			}

			$params = @{KeyRoot = $KeyRoot; KeyPath = $KeyPath ;ValueName=$Token[3]; ExpectedData =$Token[4]; IsOpposite = $IsOpposite}
			$TestName = "Registry-Data Test ($TestParameter)"
			$FunctionName = 'Test_RegData'
		}
		'RegValue' { # [RegValue] Test_RegValue 
			# Expected format = RegValue:$KeyRoot:$KeyPath:$ValueName => At least need 4 tokens
			If($Token.Length -lt 4){
				LogError ("Passed parameter for RegValue test `'$TestParameter`' is invalid")
				LogError "Expected format is `'RegValue:KeyRoot:KeyPath:ValueName`' or `'RegValue:KeyRoot:KeyPath:ValueName:True`'"
				LogInfo "Example: 'RegValue:HKLM:System\CurrentControlSet\Services\i8042prt\Parameters\OverrideKeyboardType`'"
				Return $Null
			}

			# Root key needs to be converted to PowerShell format
			Switch($Token[1]){
				'HKEY_LOCAL_MACHINE'{
					$KeyRoot = 'HKLM'
				}
				'HKEY_CURRENT_USER'{
					$KeyRoot = 'HKCU'
				}
				'HKEY_CLASSES_ROOT'{
					$KeyRoot = 'HKCR'
				}
				'HKLM'{$KeyRoot = $Token[1]}
				'HKCU'{$KeyRoot = $Token[1]}
				'HKCR'{$KeyRoot = $Token[1]}
				default{
					$KeyRoot = $Token[1]
					LogError ("Invalid key root `'$KeyRoot`' was specified.")
					Return $Null
				}
			}
			# Remove backslash at first string from registy key path
			$KeyPath = $Token[2]
			$KeyPath = [regex]::replace($KeyPath, "^\\", '') # \aaa\bbb => aaa\bbb

			# 
			If(($Token[4] -ne $Null) -and $Token[4] -eq 'True'){
				$IsOpposite = $True
			}Else{
				$IsOpposite = $False
			}

			$params = @{KeyRoot = $KeyRoot; KeyPath = $KeyPath ;ValueName=$Token[3]; IsOpposite = $IsOpposite}
			$TestName = "Registry-Value Test ($TestParameter)"
			$FunctionName = 'Test_RegValue'
		}
		'RegKey' { # [RegKey] Test_RegKey -KeyRoot <xxx> -KeyPath <xxx>
			# Expected format is 'RegData:$KeyRoot:$KeyPath' => At least need 3 tokens
			If($Token.Length -lt 3){
				LogError ("Passed parameter for RegKey test `'$TestParameter`' is invalid")
				LogError "Expected format is `'RegKey:KeyRoot:KeyPath`' or `'RegData:KeyRoot:KeyPath:True`'"
				LogInfo "Example: 'RegKey:HKLM:System\CurrentControlSet\Services\i8042prt\Parameters`'"
				Return $Null
			}

			# Root key needs to be converted to PowerShell format
			Switch($Token[1]){
				'HKEY_LOCAL_MACHINE'{
					$KeyRoot = 'HKLM'
				}
				'HKEY_CURRENT_USER'{
					$KeyRoot = 'HKCU'
				}
				'HKEY_CLASSES_ROOT'{
					$KeyRoot = 'HKCR'
				}
				'HKLM'{$KeyRoot = $Token[1]}
				'HKCU'{$KeyRoot = $Token[1]}
				'HKCR'{$KeyRoot = $Token[1]}
				default{
					$KeyRoot = $Token[1]
					LogError ("Invalid key root `'$KeyRoot`' was specified.")
					Return $Null
				}
			}
			# Remove backslash at first string from registy key path
			$KeyPath = $Token[2]
			$KeyPath = [regex]::replace($KeyPath, "^\\", '') # \aaa\bbb => aaa\bbb

			If(($Token[3] -ne $Null) -and $Token[3] -eq 'True'){
				$IsOpposite = $True
			}Else{
				$IsOpposite = $False
			}

			$params = @{KeyRoot = $KeyRoot; KeyPath = $KeyPath; IsOpposite = $IsOpposite}
			$TestName = "Registry-Key Test ($TestParameter)"
			$FunctionName = 'Test_RegKey'
		}
		'File' { # Test_File -FilePath <xxx>
			# Expected format is 'File:FilePath' => At least need 2 tokens
			If($Token.Length -lt 3){
				LogError ("Passed parameter for File test `'$TestParameter`' is invalid")
				LogError "Expected format is `'File:FilePath`' or `'File:FilePath:True`'"
				LogInfo "Example: File:`"D:\data\test.txt`""
				Return $Null
			}
			# As separator is ':', file path is split into two tokens; need to combine them again.
			$FilePath = $Token[1] + ':' + $Token[2]
			$FilePath = $FilePath -replace ("`"",'') # remove double quote
			$FilePath = $FilePath -replace ("`'",'') # remove single

			If(($Token[3] -ne $Null) -and $Token[3] -eq 'True'){
				$SignalOnCreation = $True
			}Else{
				$SignalOnCreation = $False
			}

			$params = @{FilePath = $FilePath; SignalOnCreation = $SignalOnCreation}
			$TestName = "File-exists Test ($TestParameter)"
			$FunctionName = 'Test_File'
		}
		'BranchCache' {
			#ToDo:
		}
		'Evt' {
			If($Token.Length -lt 3){
				LogError ("Passed parameter for Evt test `'$TestParameter`' is invalid")
				LogError ("Example: -WaitEvent Evt:100:System")
				Return $Null
			}
			If([string]::IsNullOrEmpty($Token[3])){
				$CheckIntInSec = 0
			}Else{
				$CheckIntInSec = $Token[3]
			}
			If([string]::IsNullOrEmpty($Token[4])){
				$WaitTimeInSec = 0
			}Else{
				$WaitTimeInSec = $Token[4]
			}
			If([string]::IsNullOrEmpty($Token[5])){
				$EventData = '0'
			}Else{
				$EventData = $Token[5] -replace ("`"","") # remove double quote
			}
			If([string]::IsNullOrEmpty($Token[6])){
				$EvtDataPartial = $True
			}Else{
				If($Token[6] -eq 'True'){
					$EvtDataPartial = $True
				}ElseIf($Token[6] -eq 'False'){
					$EvtDataPartial = $False
				}
			}
			If([string]::IsNullOrEmpty($Token[7])){
				$EvtDataOperator = "OR"
			}Else{
				$EvtDataOperator = $Token[7]
			}

			# make hardcoded '$MaxEvents = 1' configurable in Function Test_EventLog(#600)
			If($global:BoundParameters.ContainsKey('MaxEvents')){
				$EvtMaxEvents = $global:BoundParameters['MaxEvents']
			}Else{
				$EvtMaxEvents = 1  # default is 1
			}

			$params = @{
				EventIDs = $Token[1]
				EventlogName = $Token[2]
				CheckIntInSec = $CheckIntInSec
				WaitTimeInSec = $WaitTimeInSec
				EventData = $EventData
				EvtDataPartial = $EvtDataPartial
				EvtDataOperator = $EvtDataOperator
				EvtMaxEvents = $EvtMaxEvents
			}
			$TestName = "Evt(Event) Test ($TestParameter)"
			$FunctionName = 'Test_Eventlog'
		}
		'StopEvt'{
			$params = @{
				EventIDs = $Token[1]
				EventlogName = $Token[2]
				CheckIntInSec = 0
				WaitTimeInSec = 0
				EventData = '0'
				EvtDataPartial = $False
				EvtDataOperator = "OR"
				EvtMaxEvents = 1
			}
			$TestName = "StopEvt Test for remoting ($TestParameter)"
			$FunctionName = 'Test_Eventlog'
		}
		'Time'{
			$Second = $False
			If(![String]::IsNullOrEmpty($Token[2]) -and $Token[2] -like 'sec*'){
				$Second = $True
			}
			$params = @{
				WaitTime = $Token[1]
				Second = $Second
			}
			$TestName = "Time(Wait timer) event ($TestParameter)"
			$FunctionName = 'WaitTime'
		}
		'HNSL2Tunnel' {
			$TestName = "HNSL2Tunnel Test"
			$FunctionName = 'Test_HNSL2Tunnel'
		}
		'StopCondition' {
			$TestName = "StopCondition Test"
			$FunctionName = 'Test_StopCondition'
		}
		default {
			LogError ("Passed parameter $TestType is invalid. Any events will not be monitored and will stop active traces now.")
			Return $Null
		}
	}
	$TestProperty = @{
		TestName = $TestName
		Function = $FunctionName
		Parameters = $params
		ErrorCount = 0
	}
	EndFunc $MyInvocation.MyCommand.Name
	Return $TestProperty
}

#endregion monitoring functions

#region FW functions for custom object
Function StartAutoLogClock{
	EnterFunc $MyInvocation.MyCommand.Name

	If($global:IsServerCore -or $global:IsRemoteHost -or $RemoteRun.IsPresent){
		LogDebug "This is sever core or remote session and will not start TSS Clock"
		Return
	}

	$TSSClockPath =  ".\Scripts\tss-clock.ps1"
	$TSSClockProcess = Get-CimInstance Win32_Process | Where-Object {$_.Commandline -like "*tss-clock*"}
	If($TSSClockProcess -eq $Null){
		If(Test-Path -Path $TSSClockPath){
			# See if we in the process of UEX_RDS, UEX_WVD, UEX_Win32k and UEX_DWM.
			$noTopMost = $False
			If($global:ParameterArray -like '*UEX_RDS' -or $global:ParameterArray -like '*UEX_WVD' -or $global:ParameterArray -like '*UEX_Win32k' -or $global:ParameterArray -like '*UEX_DWM'){
				$noTopMost = $True
			}

			# Show clock in background using Start-Process
			If($noTopMost){ # RDS case
				LogInfo "Starting TSS Clock without topmost."
				Start-Process "PowerShell.exe" ".\Scripts\tss-clock.ps1 -noTopMost" -noNewWindow
			}Else{ # Normal case
				LogInfo "Starting TSS Clock"
				Start-Process "PowerShell.exe" ".\Scripts\tss-clock.ps1" -noNewWindow
			}
		}Else{
			LogDebug "$TSSClockPath does not exist."
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopAutoLogClock{
	EnterFunc $MyInvocation.MyCommand.Name
	$TSSClockProcesses = Get-CimInstance Win32_Process | Where-Object {$_.Commandline -like "*tss-clock*"}
	If($TSSClockProcesses -ne $Null){
		ForEach($TSSClockProcess in $TSSClockProcesses){
			LogInfoFile "Stopping TSS Clock (PID:$($TSSClockProcess.ProcessId))"
			#Write-Host ""
			Stop-Process -Id $TSSClockProcess.ProcessId -ErrorAction Ignore
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectGPresult{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	If($Status.IsPresent){
		$RegValue = Get-ItemProperty -Path  "$global:AutoLogParamRegKey" -ErrorAction Ignore
		$GPresultInReg = $RegValue.GPresult
		If(![String]::IsNullOrEmpty($GPresultInReg) -and ($GPresultInReg -eq 'Both' -or $GPresultInReg -eq 'Stop')){
			$fResult = $True
		}
	}ElseIf($Stop.IsPresent){
		# In case of -Stop, $script:GPresult is set in ReadParameterFromAutoLogReg().
		If(![String]::IsNullOrEmpty($script:GPresult) -and ($script:GPresult -eq 'Both' -or $script:GPresult -eq 'Stop')){
			$fResult = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

#endregion FW functions for custom object

#region DEFENDER
function EndTimedoutProcess ($process, $ProcessWaitMin) {
	$proc = Get-Process $process -EA SilentlyContinue
	if ($proc) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] Waiting max $ProcessWaitMin minutes on $process processes to complete"
		Wait-Process -InputObject $proc -Timeout ($ProcessWaitMin * 60) -EA SilentlyContinue
		$ProcessToEnd = Get-Process | Where-Object { $_.Name -eq "$process" } -EA SilentlyContinue
		if ($ProcessToEnd -ne $null) {
			Write-Host "timeout reached ..."
			foreach ($prc in $ProcessToEnd) { stop-Process $prc -Force -EA SilentlyContinue }
		}
	}
}
function Start-NetTraces {
	if ($NetTraceI) {
		New-Item -ItemType Directory -Path "$resultOutputDir\NetTraces" -ErrorAction SilentlyContinue | out-Null
		$traceFile = "$resultOutputDir\NetTraces\NetTrace.etl"
		LogInfo "[$($MyInvocation.MyCommand.Name)] Stopping any running network trace profiles"
		FwCheck-Command-verified "netsh.exe"
		$StopNetCommand = Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "trace stop"
		FwCheck-Command-verified "netsh.exe"
		$StopWfpCommand = Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "wfp capture stop"
		start-sleep 1
		$NetshProcess = Get-Process | Where-Object { $_.Name -eq "netsh" } -ErrorAction SilentlyContinue
		if ($NetshProcess -ne $null) {
			foreach ($process in $NetshProcess) { stop-Process $process -Force }
		}
		FwCheck-Command-verified "ipconfig.exe"
		$FlushDns = Start-Process -PassThru -WindowStyle minimized ipconfig.exe -ArgumentList "/flushdns"
		FwCheck-Command-verified "netsh.exe"
		$CleanArpCache = Start-Process -PassThru -WindowStyle minimized netsh.exe -ArgumentList "interface ip delete arpcache"
		start-sleep 1
		LogInfo "[$($MyInvocation.MyCommand.Name)] Now starting a new network trace with Duration: $MinutesToRun min - Enter 'q' to stop"
		if ($buildNumber -le 7601) {
			FwCheck-Command-verified "netsh.exe"
			$StartNetCommand = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace start overwrite=yes capture=yes scenario=InternetClient report=yes maxSize=500 traceFile=`"$traceFile`" fileMode=circular"
		}
		else {
			FwCheck-Command-verified "netsh.exe"
			$StartNetCommand = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace start overwrite=yes capture=yes scenario=InternetClient_dbg report=yes maxSize=500 traceFile=`"$traceFile`" fileMode=circular"
		}
		FwCheck-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging allowedconnections enable"  # enable firewall logging for allowed traffic
		FwCheck-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging droppedconnections enable"  # enable firewall logging for dropped traffic
		FwCheck-Command-verified "netsh.exe"
		$StartWFTraces = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "wfp capture start file=wfpdiag.cab keywords=19" # start capturing  WFP log
		FwCheck-Command-verified "netstat.exe"
		&netstat -anob | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStart.txt"
		"Netstat output above was taken at: " + (Get-Date) | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStart.txt" -Append
		if (($OSPreviousVersion) -and (!$MDfWS)) {
			$OMSPath = "$env:ProgramFiles\Microsoft Monitoring Agent\Agent\Tools"
			if (Test-Path -path $OMSPath) {
				$MMAPathExists = "True"
				Get-Service HealthService | Stop-Service -ErrorAction SilentlyContinue
				&$OMSPath\StopTracing.cmd | Out-Null
				&$OMSPath\StartTracing.cmd VER | Out-Null
				Get-Service HealthService | Start-Service -ErrorAction SilentlyContinue
			}
		}
	}
}

function Stop-NetTraces {
	if ($NetTraceI) {
		FwCheck-Command-verified "netstat.exe"
		&netstat -anob | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStop.txt"
		"Netstat output above was taken at: " + (Get-Date) | Out-File "$resultOutputDir\NetTraces\NetStatOutputAtStop.txt" -Append
		FwCheck-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging allowedconnections disable"  # disable firewall logging for allowed traffic
		FwCheck-Command-verified "netsh.exe"
		$StartWFLogging = Start-Process -WindowStyle hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "advfirewall set allprofiles logging droppedconnections disable"  # disable firewall logging for dropped traffic
		FwCheck-Command-verified "netsh.exe"
		Start-Process -NoNewWindow netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "wfp capture stop"
		FwCheck-Command-verified "netsh.exe"
		LogInfo "[$($MyInvocation.MyCommand.Name)] Stopping network and wfp traces may take a while..."
		Start-Process -WindowStyle Hidden netsh.exe -WorkingDirectory "$resultOutputDir\NetTraces" -ArgumentList "trace stop"
		Copy-Item $env:SystemRoot\system32\LogFiles\Firewall\pfirewall.log -Destination "$resultOutputDir\NetTraces\" -ErrorAction SilentlyContinue
		if (($MMAPathExists) -and (!$MDfWS)) { 
			&$OMSPath\StopTracing.cmd | Out-Null
			Copy-Item $env:SystemRoot\Logs\OpsMgrTrace\* -Destination "$resultOutputDir\NetTraces\" -ErrorAction SilentlyContinue
		}	
		# Dump HOSTS file content to file
		Copy-Item $env:SystemRoot\System32\Drivers\etc\hosts -Destination "$resultOutputDir\SystemInfoLogs" -ErrorAction SilentlyContinue
		EndTimedoutProcess "netsh" 10
	}
}

function StartTimer {
	$TraceStartTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
	##Write-Report -section "general" -subsection "traceStartTime" -displayname "Trace StartTime: " -value $TraceStartTime
	$timeout = New-TimeSpan -Minutes $MinutesToRun
	$sw = [diagnostics.stopwatch]::StartNew()
	Create-OnDemandStartEvent
	# if ($RemoteRun) {
	# 	Write-Warning "Trace started... Note that you can stop this non-interactive mode by running 'MDEClientAnalyzer.cmd' from another window or session"
	# 	Wait-OnDemandStop
	# } else {
		while ($sw.elapsed -lt $timeout) {
			Start-Sleep -Seconds 1
			$rem = $timeout.TotalSeconds - $sw.elapsed.TotalSeconds
			Write-Progress -Activity "Collecting traces, run your scenario now and press 'q' to stop data collection at any time" -Status "Progress:"  -SecondsRemaining $rem -PercentComplete (($sw.elapsed.Seconds / $timeout.TotalSeconds) * 100)
			if ([console]::KeyAvailable) {
				$key = [System.Console]::ReadKey() 
				if ( $key.key -eq 'q') {
					LogInfo "[$($MyInvocation.MyCommand.Name)] The trace collection action was ended by user exit command"
					break 
				}
			}
		}
	# }
	$TraceStopTime = "{0:dd/MM/yyyy h:mm:ss tt zzz}" -f (get-date)
	##Write-Report -section "general" -subsection "traceStopTime" -displayname "Trace StopTime: " -value $TraceStopTime 
}

function Create-OnDemandStopEvent {
	Write-host "Another non-interactive trace is already running... stopping log collection and exiting."
	Write-EventLog -LogName "Application" -Source "MDEClientAnalyzer" -EventID 2 -EntryType Information -Message "MDEClientAnalyzer is stopping a running log set" -Category 1
	[Environment]::Exit(1)
}

function Create-OnDemandStartEvent {
	Write-EventLog -LogName "Application" -Source "MDEClientAnalyzer" -EventID 1 -EntryType Information -Message "MDEClientAnalyzer is starting OnDemand traces" -Category 1	
}
function Write-Report($section, $subsection, $displayName, $value, $alert) { 
	$subsectionNode = $script:xmlDoc.CreateNode("element", $subsection, "")    
	$subsectionNode.SetAttribute("displayName", $displayName)

	$eventContext1 = $script:xmlDoc.CreateNode("element", "value", "")
	$eventContext1.psbase.InnerText = $value
	$subsectionNode.AppendChild($eventContext1) | out-Null

	if ($value -eq "Running") {
		$alert = "None"
	} elseif (($value -eq "Stopped" -or $value -eq "StartPending")) {
		$alert = "High"
	}

	if ($alert) {
		$eventContext2 = $script:xmlDoc.CreateNode("element", "alert", "")
		$eventContext2.psbase.InnerText = $alert
		$subsectionNode.AppendChild($eventContext2) | out-Null
	}

	$checkresult = $DisplayName + ": " + $value
	# Write message to the ConnectivityCheckFile
	$checkresult | Out-File $connectivityCheckFile -append

	$xmlRoot = $script:xmlDoc.SelectNodes("/MDEResults")
	$InputNode = $xmlRoot.SelectSingleNode($section)
	$InputNode.AppendChild($subsectionNode) | Out-Null
}

# Initialize XML log - for consumption by external parser
function InitXmlLog {
	$script:xmlDoc = New-Object System.Xml.XmlDocument								 
	$script:xmlDoc = [xml]"<?xml version=""1.0"" encoding=""utf-8""?><MDEResults><general></general><devInfo></devInfo><EDRCompInfo></EDRCompInfo><MDEDevConfig></MDEDevConfig><AVCompInfo></AVCompInfo><events></events></MDEResults>"
}

# Define C# functions to extract info from Windows Security Center (WSC)
# WSC_SECURITY_PROVIDER as defined in Wscapi.h or http://msdn.microsoft.com/en-us/library/bb432509(v=vs.85).aspx
# And http://msdn.microsoft.com/en-us/library/bb432506(v=vs.85).aspx
$wscDefinition = @"
		[Flags]
        public enum WSC_SECURITY_PROVIDER : int
        {
            WSC_SECURITY_PROVIDER_FIREWALL = 1,				// The aggregation of all firewalls for this computer.
            WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS = 2,	// The automatic update settings for this computer.
            WSC_SECURITY_PROVIDER_ANTIVIRUS = 4,			// The aggregation of all antivirus products for this computer.
            WSC_SECURITY_PROVIDER_ANTISPYWARE = 8,			// The aggregation of all anti-spyware products for this computer.
            WSC_SECURITY_PROVIDER_INTERNET_SETTINGS = 16,	// The settings that restrict the access of web sites in each of the Internet zones for this computer.
            WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL = 32,	// The User Account Control (UAC) settings for this computer.
            WSC_SECURITY_PROVIDER_SERVICE = 64,				// The running state of the WSC service on this computer.
            WSC_SECURITY_PROVIDER_NONE = 0,					// None of the items that WSC monitors.
			
			// All of the items that the WSC monitors.
            WSC_SECURITY_PROVIDER_ALL = WSC_SECURITY_PROVIDER_FIREWALL | WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS | WSC_SECURITY_PROVIDER_ANTIVIRUS |
            WSC_SECURITY_PROVIDER_ANTISPYWARE | WSC_SECURITY_PROVIDER_INTERNET_SETTINGS | WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL |
            WSC_SECURITY_PROVIDER_SERVICE | WSC_SECURITY_PROVIDER_NONE
        }

        [Flags]
        public enum WSC_SECURITY_PROVIDER_HEALTH : int
        {
            WSC_SECURITY_PROVIDER_HEALTH_GOOD, 			// The status of the security provider category is good and does not need user attention.
            WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED,	// The status of the security provider category is not monitored by WSC. 
            WSC_SECURITY_PROVIDER_HEALTH_POOR, 			// The status of the security provider category is poor and the computer may be at risk.
            WSC_SECURITY_PROVIDER_HEALTH_SNOOZE, 		// The security provider category is in snooze state. Snooze indicates that WSC is not actively protecting the computer.
            WSC_SECURITY_PROVIDER_HEALTH_UNKNOWN
        }

		
        [DllImport("wscapi.dll")]
        private static extern int WscGetSecurityProviderHealth(int inValue, ref int outValue);

		// code to call interop function and return the relevant result
        public static WSC_SECURITY_PROVIDER_HEALTH GetSecurityProviderHealth(WSC_SECURITY_PROVIDER inputValue)
        {
            int inValue = (int)inputValue;
            int outValue = -1;

            int result = WscGetSecurityProviderHealth(inValue, ref outValue);

            foreach (WSC_SECURITY_PROVIDER_HEALTH wsph in Enum.GetValues(typeof(WSC_SECURITY_PROVIDER_HEALTH)))
                if ((int)wsph == outValue) return wsph;

            return WSC_SECURITY_PROVIDER_HEALTH.WSC_SECURITY_PROVIDER_HEALTH_UNKNOWN;
        }
"@

function CollectDefenderLog
{
	EnterFunc $MyInvocation.MyCommand.Name
	$ProcessWaitMin = 5	# wait max minutes to complete
	$NetTraceI = $True
	If($global:BoundParameters.ContainsKey('DefenderDurInMin')){
		$global:DefenderDurInMin = $global:DefenderDurInMin
	} else {$global:DefenderDurInMin = 5}
	$MinutesToRun = $global:DefenderDurInMin
	InitXmlLog
	LogInfo "[$($MyInvocation.MyCommand.Name)] Running Defender Get-Logs"
	#Store paths for MpCmdRun.exe usage
	if (((FwGet-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath) -and ($OSBuild -ge 14393)) -or ($MDfWS)) {
		$MsMpEngPath = FwGet-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Value ImagePath
		[System.IO.DirectoryInfo]$CurrentMpCmdPath = $MsMpEngPath -replace "MsMpEng.exe" -replace """"
		$MpCmdRunCommand = Join-Path $CurrentMpCmdPath "MpCmdRun.exe"
		$MpCmdResultPath = "$env:ProgramData\Microsoft\Windows Defender\Support"
	}
	elseif (Test-Path -path "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe") {
		$CurrentMpCmdPath = "$env:ProgramFiles\Microsoft Security Client\"
		$MpCmdRunCommand = "$env:ProgramFiles\Microsoft Security Client\MpCmdRun.exe"
		$MpCmdResultPath = "$env:ProgramData\Microsoft\Microsoft Antimalware\Support"
	}
	[string]$OSProductName = FwGet-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value ProductName
	
	$resultOutputDir = Join-Path $global:LogFolder "MDEClientAnalyzerResult"
	$SysLogs = Join-Path $resultOutputDir "SystemInfoLogs"
	$connectivityCheckFile = Join-Path $SysLogs "MDEClientAnalyzer.txt"

	New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
	New-Item -ItemType Directory -Path "$resultOutputDir\SystemInfoLogs" -ErrorAction SilentlyContinue | out-Null

	Start-NetTraces
	StartTimer
	Stop-NetTraces
	

	New-Item -ItemType Directory -Path "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue | out-Null
	if ($MpCmdRunCommand) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] Running MpCmdRun -GetFiles..."
		FwCheckAuthenticodeSignature $MpCmdRunCommand
		&$MpCmdRunCommand -getfiles | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		Copy-Item -Path "$MpCmdResultPath\MpSupportFiles.cab" -Destination "$resultOutputDir\DefenderAV" -ErrorVariable GetFilesErr | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		LogInfo "[$($MyInvocation.MyCommand.Name)] Copying file '$MpCmdResultPath\MpSupportFiles.cab' to '$resultOutputDir\DefenderAV'"
		$GetFilesErr | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		#Copy-Item -path "C:\Users\Public\Downloads\Capture.npcap" -Destination "$resultOutputDir\DefenderAV" -ErrorAction SilentlyContinue -verbose -ErrorVariable CopyNpCap | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		#$CopyNpCap | Out-File "$resultOutputDir\DefenderAV\GetFilesLog.txt" -Append
		# Dump Defender related polices
		Get-ChildItem "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -recurse | Out-File "$resultOutputDir\DefenderAV\Policy-DefenderAV.txt"
		Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\" -recurse | Out-File "$resultOutputDir\DefenderAV\Policy-Firewall.txt"
		Get-ChildItem "HKU:\S-1-5-18\SOFTWARE\Microsoft\Windows Defender" -recurse -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\DefenderAV\Policy-SystemService.txt"
		Get-ChildItem "HKU:\S-1-5-20\SOFTWARE\Microsoft\Windows Defender" -recurse -ErrorAction SilentlyContinue | Out-File "$resultOutputDir\DefenderAV\Policy-NetworkService.txt"
	}
	FwCheck-Command-verified "fltmc.exe"
	&fltmc instances -v "$env:SystemDrive" > $resultOutputDir\SystemInfoLogs\filters.txt
	if ($OSProductName.tolower() -notlike ("*server*")) {
		Write-output "`r`n##################### Windows Security Center checks ######################" | Out-File $connectivityCheckFile -Append
		$wscType = Add-Type -memberDefinition $wscDefinition -name "wscType" -UsingNamespace "System.Reflection", "System.Diagnostics" -PassThru
 
		"            Firewall: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_FIREWALL) | Out-File $connectivityCheckFile -Append
		"         Auto-Update: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_AUTOUPDATE_SETTINGS) | Out-File $connectivityCheckFile -Append
		"          Anti-Virus: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTIVIRUS) | Out-File $connectivityCheckFile -Append
		"        Anti-Spyware: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTISPYWARE) | Out-File $connectivityCheckFile -Append
		"   Internet Settings: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_INTERNET_SETTINGS) | Out-File $connectivityCheckFile -Append
		"User Account Control: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) | Out-File $connectivityCheckFile -Append
		"         WSC Service: " + $wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_SERVICE) | Out-File $connectivityCheckFile -Append

		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_FIREWALL) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_POOR) {
			Write-output "Windows Defender firewall settings not optimal" | Out-File $connectivityCheckFile -Append
		}
		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_USER_ACCOUNT_CONTROL) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_POOR) {
			Write-output "User Account Controller (UAC) is switched off" | Out-File $connectivityCheckFile -Append
		}
		if ($wscType[0]::GetSecurityProviderHealth($wscType[1]::WSC_SECURITY_PROVIDER_ANTIVIRUS) -eq $wscType[2]::WSC_SECURITY_PROVIDER_HEALTH_GOOD) {
			Write-output "Windows Defender anti-virus is running and up-to-date" | Out-File $connectivityCheckFile -Append
		}
	}

	LogInfo "[$($MyInvocation.MyCommand.Name)]. Done Defender Get-Logs"

	EndFunc $MyInvocation.MyCommand.Name
}
#endregion DEFENDER


#endregion script functions
<#----------------  FUNCTIONS END  ----------------#>
#region MAIN
#------------------------------------------------------------------
#								MAIN 
#------------------------------------------------------------------

$global:BoundParameters = $MyInvocation.BoundParameters

# If there is no option, add -Help switch to BoundParameters to show help message
If($global:BoundParameters.Count -eq 0){
	$global:BoundParameters.Add('Help',$True)
}

# Initialize ParameterArray
$global:ParameterArray = @()
ForEach($Key in $MyInvocation.BoundParameters.Keys){
	$global:ParameterArray += $Key
}

# Display script version
If((IsStart) -and $global:BoundParameters.ContainsKey('NewSession')){
	LogInfo "AutoLog Script Version: $global:TssVerDate" "Cyan"
}

If((IsStart) -and !$global:BoundParameters.ContainsKey('Start')){
	$global:BoundParameters.Add('Start',$True)
	$global:ParameterArray = InsertArrayIntoArray -Array $global:ParameterArray -insertAfter 0 -valueToInsert 'Start'
}

# Set $AutoLogCommandline. This is used when new PowerShell session is created.
$Script:AutoLogCommandline = $MyInvocation.Line

# Start new PowerShell session to clear all pre-existing global variables and run on fresh environment.
If($global:ParameterArray -notcontains 'NewSession' -and ((IsStart) -or $global:ParameterArray -contains 'StartAutoLogger' -or $global:ParameterArray -contains 'Stop' -or $global:ParameterArray -contains 'CollectLog'-or $global:ParameterArray -contains 'StartDiag')){
	If($Host.Name -match "ISE"){
		If($global:ParameterArray -contains 'StopAutologger'){
			LogError "-StopAutologger is no longer used. Please use '-Stop' instead to stop and delete autologger sessions."
			CleanUpAndExit
		}
		LogWarn "AutoLog is running on PowerShell ISE. Global variables created in previous run might be reused and that causes expected behavior. When you see value in tss_config file is updated but not reflected in the session, please relaunch the PowerShell ISE and run it again for workaround."
	}Else{
		# To handle path having space, use &(call operator) to start new powershell session
		$CommandArg = $MyInvocation.Line -replace "^.*ps1.",""  # & 'C:\temp\AutoLog (1)\AutoLog.ps1' -Dev_TEST1 => -Dev_TEST1
		$CommandArg = $CommandArg -replace "-StopAutologger","-Stop"  # Replace -StopAutologger with -Stop as -StopAutologger is no longer used.
		$cmdline = "& '$($MyInvocation.MyCommand.Path)' $CommandArg -NewSession" 

		# Replacing double quote(") with single quote(') - Issue#595
		$cmdline = $cmdline -replace "`"","`'"
		#LogInfoFile "Starting a new PSSession."
		PowerShell.exe $cmdline
		Exit
	}
}

If(!$noPrereqC.IsPresent){
	PreRequisiteCheckInStage1
}Else{
	LogInfo "Skipping PreRequisiteCheckInStage1() as -noPrereqC was specified."
}

# Show EULA if needed.
If($AcceptEULA.IsPresent){
	$eulaAccepted = ShowEULAIfNeeded "AutoLog" 2  # Silent accept mode.
}Else{
	$eulaAccepted = ShowEULAIfNeeded "AutoLog" 0  # Show EULA popup at first run.
}

if ($eulaAccepted -ne "Yes")
{
   LogInfo "EULA Declined"
   Exit
}

# Clear previous errors
If($Error.Count -ne 0){
	$PreviousError = $Error | foreach { $_ } # $PreviousError will be saved to log file after the initialization of $LogFolder is completed.
}
$Error.Clear()

#
# region Global variables
#
$global:ScriptPrefix 	= 'AutoLog'
$global:ScriptName 		= $MyInvocation.MyCommand.Name
$global:ScriptFolder 	= Split-Path $MyInvocation.MyCommand.Path -Parent
$global:ScriptsFolder 	= $global:ScriptFolder + "\scripts"
$global:ConfigFolder	= $global:ScriptFolder + "\config"
$global:ConfigFile		= $global:ConfigFolder + "\tss_config.cfg"
$global:InvocationLine	= $($MyInvocation.Line) #we# to enable inspect in AutoLog_[POD].psm1
$global:IsRemoting		= $False
$global:ProcDump		= ""
$global:OperatingSystemInfo = global:FwGetOperatingSystemInfo
$global:OSBuild			= [int]$global:OperatingSystemInfo.CurrentBuildHex
$global:OSVersion		= [environment]::OSVersion.Version # This is just for compatibility.
$global:OriginalDisableRegistryTools = (Get-ItemProperty -ErrorAction Ignore -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System).DisableRegistryTools
$global:AutoLogRegKey		= "HKLM:Software\Microsoft\CESDiagnosticTools\AutoLog" # To support autologger and purge task, need to set params to under HKLM
$global:AutoLogParamRegKey = "$global:AutoLogRegKey\Parameters"
$global:IsServerCore	= IsServerCore
$global:IsServerSKU 	= FwGetSrvSKU
$global:IsISE 			= $Host.Name -match "ISE Host"
$global:IsRemoteHost 	= $Host.Name -match "RemoteHost"
$global:IsLiteMode		= IsLiteMode
$global:RegAvailable = $True
# below ProgressPreference should only be set if we are running in Azure Serial Console
If($RemoteRun.IsPresent) {$global:ProgressPreference = "SilentlyContinue"} else {$global:ProgressPreference = "Continue"} #we# test for P2: powershell ( serial console): "Win32 internal error "Access is denied" 0x5 occurred while reading the console output buffer. (#675) 

# Global variables previously (only defined) in _NET.psm1
$global:Sys32			= $Env:SystemRoot + "\system32"
$global:PoolmonPath 	= $global:ScriptFolder + "\Bin\Poolmon.exe"
$global:HandlePath 		= $global:ScriptFolder + "\Bin\Handle.exe"
$global:DirScript		= $global:ScriptFolder
$global:DirRepro		= $global:LogFolder
$global:RegKeysModules = @()
$global:EvtLogNames = @()
$global:ScriptFolder
$global:RunningCollect = "Basic"
$global:EvtDaysBack=30

# Make sure all *.ps1/.psm1 files are Unblocked 
Get-ChildItem -Recurse -Path $global:ScriptFolder\*.ps* | Unblock-File -Confirm:$false

# In case of stop, read parameters from AutoLog registry and set them to $global:BoundParameters
If($Stop.IsPresent -or $Status.IsPresent){
	ReadParameterFromAutoLogReg # This adds params to $global:BoundParameters
}

# # Version check
# #If(($OperatingSystemInfo.OSVersion -lt 10) -and !($OperatingSystemInfo.OSVersion -eq 6 -and $OperatingSystemInfo.CurrentBuildHex -ge 9200)){
# If($OSBuild -le 9200){ #we# OSver is lower then Win2012 
# 	LogInfo "This script is supported starting with Windows 8.1 or Windows Server 2012 R2" "Cyan"
# 	Write-Host ("... running on OS: $global:OSVersion with PS version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) `n [Beta-phase] ...parts of the script may not work or throw errors running on older OS - NOT tested!") -ForegroundColor Red
# 	Write-Host ""
# 	#_# CleanUpandExit #we# uncommenting for now to test with Win7/2008R2 with updated PS version v5
# }

# Global variables for sub Folder and data locations
$global:LogPrefix 		= $env:COMPUTERNAME + "_" + "$(Get-Date -f yyMMdd-HHmmss)_" 
$global:LogSuffix 		= "-$(Get-Date -f yyyy-MM-dd.HHmm.ss)"  

# Log sub folder
$LogSubFolder = 'AutoLog_' + $env:COMPUTERNAME + "_" + "$(Get-Date -f yyMMdd-HHmmss)_" 

# Log folders
# 1. If -LogFolderName exists, set it to $global:LogFolder
# 2. Set default log foldername($global:LogRoot + $LogSubFolder)
# 3. If 'LogFolder' is saved in AutoLog registry, set it to $global:LogFolder
If($global:BoundParameters.ContainsKey('Start') -and $global:BoundParameters.ContainsKey('LogFolderName')){
	$global:LogRoot = $LogFolderName + "\"
	$global:LogFolder = $LogFolderName + "\" + $LogSubFolder
}Else{ # Normal case
	$global:LogRoot = "$env:LOCALAPPDATA\AutoLog\"
	$global:LogFolder = $global:LogRoot + $LogSubFolder

	# If 'LogFolder' exists in AutoLog reg, overwrite the $global:LogFolder with the LogFolder in reg.
	If(Test-Path "$global:AutoLogParamRegKey"){
		$RegValues = Get-ItemProperty -Path  $global:AutoLogParamRegKey -ErrorAction SilentlyContinue
		If($RegValues -ne $Null){
			If($($RegValues.LogFolder)){	#_# fix to avoid LogFolder=''
				LogDebug "Found LogFolder in AutoLog reg. Set it to LogFolder"
				$global:LogRoot = Split-Path $($RegValues.LogFolder) -Parent
				$global:LogFolder = $RegValues.LogFolder
			}
		}
	}

	# in case of collecting -SDP only, shorten subfolder to SDP_<specialty>
	if (($MyInvocation.BoundParameters.keys[0] -eq "SDP") -and ($global:BoundParameters.Count -le 2)) {
		$SDPcombi = ([string]::Concat($SDP)).replace(',','_') # $SDP is string array
		$global:LogFolder = "$env:LOCALAPPDATA\AutoLog" + '\SDP_' + $SDPcombi
	}
}
If((IsTraceOrDataCollection)){
	LogInfo "[$($MyInvocation.MyCommand.Name)] LogFolder is set to `'$global:LogFolder`'"
}

$global:PrefixCn	= $global:LogFolder + "\" + $Env:Computername + "_"
$global:PrefixTime	= $global:LogFolder + "\" + $global:LogPrefix

# Error log
$global:ErrorLogFile = "$global:LogFolder\$($LogPrefix)_Log-Warn-Err-Info.txt"
$global:ErrorVariableFile = "$global:LogFolder\$($LogPrefix)_ErrorVariable.txt"
$global:TempCommandErrorFile = "$global:LogFolder\$($LogPrefix)Command-Error.txt" #"$env:TMP\AutoLog-Command-Error.txt"

# Output log - used for transcription
$global:TranscriptLogFile = "$global:LogFolder\$($LogPrefix)_Log-transcript.txt"

if($StartNoWait.IsPresent -or $StartAutoLogger.IsPresent){
	$global:TranscriptLogFile = "$global:LogFolder\$($LogPrefix)_LogStart.txt"
	$global:ErrorLogFile = "$global:LogFolder\$($LogPrefix)_LogStart-Warn-Err-Info.txt"
	$global:ErrorVariableFile = "$global:LogFolder\$($LogPrefix)_LogStart_ErrorVariable.txt"
}

if($Stop.IsPresent){
	$global:TranscriptLogFile = "$global:LogFolder\$($LogPrefix)_LogStop.txt"
	$global:ErrorLogFile = "$global:LogFolder\$($LogPrefix)_LogStop-Warn-Err-Info.txt"
	$global:ErrorVariableFile = "$global:LogFolder\$($LogPrefix)_LogStop_ErrorVariable.txt"
}

LogDebug ("============================	 Log files	 ============================")
LogDebug ("LogFolder            : $global:LogFolder")
LogDebug ("LogSubFolder         : $LogSubFolder")
LogDebug ("ErrorLogFile         : $global:ErrorLogFile")
LogDebug ("ErrorVariableFile    : $global:ErrorVariableFile")
LogDebug ("TempCommandErrorFile : $global:TempCommandErrorFile")
LogDebug ("TranscriptLogFile    : $global:TranscriptLogFile")
LogDebug ("===========================================================================")
	
#Create Log Folder if it does not exist
If((IsTraceOrDataCollection)){ #we# added $PreviousError
	Try{
		FwCreateLogFolder $global:LogFolder
		# Log previous errors
		If($Null -ne $PreviousError){
			$PreviousError | Out-File -FilePath "$global:LogFolder\$($LogPrefix)_Pre-start-ErrorVariable.txt"
		}
	}Catch{
		LogException "Unable to create log folder. " $_
	}
}

# Before starting logging, close existing session.
Close-Transcript

# Log console output only when script starts component trace or data collection
If((IsTraceOrDataCollection)){
	Try{
		LogInfoFile "Starting transcription: $TranscriptLogFile"
		Start-Transcript -Append -Path $TranscriptLogFile | Out-Null
		LogInfoFile "Commandline: $($MyInvocation.Line)" # Log commandline first.
		# Log PS window type
		[string]$PSMode = ($ExecutionContext.SessionState.LanguageMode)
		If($Host.Name -match "ISE"){ LogInfoFile "$global:ScriptName v$global:TSSverDate script execution is attempted in 'PowerShell ISE' window ($($Host.Name))  PSMode: $PSMode"} else { LogInfoFile "$global:ScriptName v$global:TSSverDate script execution is running in regular 'PowerShell' window ($($Host.Name)) PSMode: $PSMode"}
		#LogInfo "... running AutoLog v$global:TSSverDate on OS: $global:OSVersion with PS version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
	}Catch{
		LogError ("Error happened in Start-Transcript")
	}
	If(!(IsRegCommandAvailable)){
		LogInfoFile "global:RegAvailable is set to false"
		$global:RegAvailable = $False
	}
}

# #_# checking online for latest public version
# if (( -Not $noVersionChk.IsPresent) -or ($global:ParameterArray -notcontains 'noVersionChk')){
# 	If (( -Not $noUpdate.IsPresent) -and ((IsStart) -or $StartAutoLogger.IsPresent -or ![string]::IsNullOrEmpty($StartDiag) -or ![string]::IsNullOrEmpty($CollectLog))) {
# 		LogInfo "Checking if a new version is available on https://aka.ms/getTSS"
# 		CheckVersion($global:TssVerDate)
# 	}
# }
<#
# ToDo: possibly run AutoUpdate in production here (do it while in broad Testing phase)
If (( -Not $noUpdate.IsPresent) -and ($Script:fUpToDate -eq $False) -and ((IsStart) -or $StartAutoLogger.IsPresent -or ![string]::IsNullOrEmpty($StartDiag) -or ![string]::IsNullOrEmpty($CollectLog))) {
	UpdateTSS	# skip this step with -noUpdate #_# -> keeping active while beta testing, # -> remove for production
}
#> 

#
# Set $global:EnableCOMDebug to use the value in AutoLog_UEX.psm1
If($EnableCOMDebug.IsPresent){
	$global:EnableCOMDebug = $EnableCOMDebug
}

#
# Set $global:StartAutoLogger to use the value in AutoLog_NET.psm1 and other modules
If($StartAutoLogger.IsPresent){
	$global:StartAutoLogger = $StartAutoLogger
}

#
# Get CustomParams
#
If($CustomParams.Count -eq 0) {			
	write-debug ("CustomParams input is not provided")
	$global:CustomParams = @()
	}
else {
	$global:CustomParams = $CustomParams
	LogInfo ("Custom Parameters: " + $CustomParams)
	}

# Executing external PS script and exiting
#
If([string]::IsNullOrEmpty($ExternalScript)) {			
	write-debug "AutoLog started without providing external script"}
else
{
	$ScriptPath = Split-Path $MyInvocation.InvocationName 
	$Command = $ScriptPath + "\" + $ExternalScript
	write-host ("Starting external script: " + $Command)
	& "$ScriptPath\$ExternalScript"
	CleanUpandExit
}

#region --- PerfMon Counters
# Global perf counter
$global:GeneralCounters = @(
	'\Process(*)\*'
	'\Process V2(*)\*'
	'\Processor(*)\*'
	'\Processor information(*)\*'
	'\Memory(*)\*'
	'\System(*)\*'
	'\PhysicalDisk(*)\*'
	'\LogicalDisk(*)\*'
)

$global:SMBCounters = @(
	$global:GeneralCounters
	'\Server(*)\*'
	'\Server Work Queues(*)\*'
	'\SMB Client Shares(*)\*'
	'\SMB Direct Connections(*)\*'
	'\SMB Server(*)\*'
	'\SMB Server Sessions(*)\*'
	'\SMB Server Shares(*)\*'
	'\Network Adapter(*)\*'
	'\Network Interface(*)\*'
	'\Network QoS Policy(*)\*'
	'\Paging File(*)\*' 
	'\Redirector\*' 
	)

$global:NETCounters = @(
	$global:SMBCounters
	'\Browser\*'
	'\Cache\*'
	'\Thread(*)\*'
	'\Netlogon(*)\*'
	'\Objects\*'
	'\Terminal Services\*'
	'\.NET CLR Memory(*)\*'
	'\IP\*'
	'\UDP\*'
	'\UDPv4\*'
	'\TCPv4\*'
	'\IPv4\*'
	'\UDPv6\*'
	'\TCPv6\*'
	'\IPv6\*'
	'\WFPv4\*'
	'\WFPv6\*'
	'\ICMP\*'
	'\IPsec Driver\*'
	'\IPsec Connections\*'
	'\IPsec AuthIP IPv6\*'
	'\IPsec AuthIP IPv4\*'
	'\IPHTTPS Global(*)\*'
	'\IPHTTPS Session\*'
	'\DNS\*'
	'\DHCP Server\*'
	'\DHCP Server v6\*'
	'\DFS Namespace Service Referrals\*'
	'\Per Processor Network Activity Cycles(*)\*'
	'\Per Processor Network Interface Card Activity(*)\*'
	'\RaMgmtSvc\*'
	'\RAS Port(*)\*'
	'\RAS Total\*'
	'\WINS Server\*'
	'\NBT Connection(*)\*'
	)

$global:BCCounters = @(
	$global:NETCounters
	'\BranchCache\*' 
	'\BranchCache Kernel Mode\*' 
	'\Client Side Caching\*'
	)

$global:DCCounters = @(
	$global:NETCounters
	'\NTDS(*)\*' 
	'\Database(lsass)\*' 
	'\DirectoryServices(*)\*' 
	'\AD FS(*)\*'
	)

$global:SQLCounters = @(
	$global:NETCounters
	'\.NET CLR Exceptions(*)\*'
	'\.NET CLR Interop(*)\*'
	'\.NET CLR Jit(*)\*'
	'\.NET CLR Loading(*)\*'
	'\.NET CLR LocksAndThreads(*)\*'
	'\.NET CLR Remoting(*)\*'
	'\.NET CLR Security(*)\*'
	'\ACS/RSVP Service(Service)\*'
	'\Active Server Pages\*'
	'\AppleTalk(*)\*'
	'\ASP.NET\*'
	'\ASP.NET Applications(__Total__)\*'
	'\ASP.NET Apps Rds V1 Beta2(__Total__)\*'
	'\ASP.NET Rds V1 Beta2\*'
	'\Distributed Transaction Coordinator\*'
	'\FTP Service(_Total)\*'
	'\FTP Service(Default FTP Site)\*'
	'\Http Indexing Service\*'
	'\IAS Accounting Clients\*'
	'\IAS Accounting Server\*'
	'\IAS Authentication Clients\*'
	'\IAS Authentication Server\*'
	'\Indexing Service\*'
	'\Indexing Service Filter\*'
	'\Internet Information Services Global\*'
	'\Job Object\*'
	'\Job Object Details\*'
	'\LogicalDisk(_Total)\*'
	'\MacFile Server\*'
	'\Microsoft Gatherer\*'
	'\Microsoft Gatherer Projects(*)\*'
	'\Microsoft Search\*'
	'\Microsoft Search Catalogs(*)\*'
	'\Microsoft Search Indexer Catalogs(*)\*'
	'\MSSQL$*:Access Methods\*'
	'\MSSQL$*:Advanced Analytics(*)\*'
	'\MSSQL$*:Availability Replica(*)\*'
	'\MSSQL$*:Backup Device\*'
	'\MSSQL$*:Batch Resp Statistics(*)\*'
	'\MSSQL$*:Broker Activation\*'
	'\MSSQL$*:Broker Statistics\*'
	'\MSSQL$*:Broker TO Statistics\*'
	'\MSSQL$*:Broker/DBM Transport\*'
	'\MSSQL$*:Buffer Manager\*'
	'\MSSQL$*:Buffer Node(*)\*'
	'\MSSQL$*:Catalog Metadata(*)\*'
	'\MSSQL$*:CLR\*'
	'\MSSQL$*:Columnstore(*)\*'
	'\MSSQL$*:Cursor Manager by Type(*)\*'
	'\MSSQL$*:Cursor Manager Total\*'
	'\MSSQL$*:Database Mirroring(*)\*'
	'\MSSQL$*:Database Replica(*)\*'
	'\MSSQL$*:Databases(*)\*'
	'\MSSQL$*:Deprecated Features\*'
	'\MSSQL$*:Exec Statistics(*)\*'
	'\MSSQL$*:FileTable\*'
	'\MSSQL$*:General Statistics\*'
	'\MSSQL$*:Http Storage(*)\*'
	'\MSSQL$*:Latches\*'
	'\MSSQL$*:Locks(*)\*'
	'\MSSQL$*:Memory Broker Clerks(*)\*'
	'\MSSQL$*:Memory Manager\*'
	'\MSSQL$*:Memory Node(*)\*'
	'\MSSQL$*:Plan Cache(*)\*'
	'\MSSQL$*:Query Store(*)\*'
	'\MSSQL$*:Replication Agents(Distribution)\*'
	'\MSSQL$*:Replication Agents(Logreader)\*'
	'\MSSQL$*:Replication Agents(Merge)\*'
	'\MSSQL$*:Replication Agents(Queuereader)\*'
	'\MSSQL$*:Replication Agents(Snapshot)\*'
	'\MSSQL$*:Replication Dist.\*'
	'\MSSQL$*:Replication Logreader(*)\*'
	'\MSSQL$*:Replication Merge\*'
	'\MSSQL$*:Replication Snapshot\*'
	'\MSSQL$*:Resource Pool Stats(*)\*'
	'\MSSQL$*:SQL Errors(*)\*'
	'\MSSQL$*:SQL Statistics\*'
	'\MSSQL$*:Transactions\*'
	'\MSSQL$*:Transactions(*)\*'
	'\MSSQL$*:User Settable(User counter 1)\*'
	'\MSSQL$*:User Settable(User counter 10)\*'
	'\MSSQL$*:User Settable(User counter 2)\*'
	'\MSSQL$*:User Settable(User counter 3)\*'
	'\MSSQL$*:User Settable(User counter 4)\*'
	'\MSSQL$*:User Settable(User counter 5)\*'
	'\MSSQL$*:User Settable(User counter 6)\*'
	'\MSSQL$*:User Settable(User counter 7)\*'
	'\MSSQL$*:User Settable(User counter 8)\*'
	'\MSSQL$*:User Settable(User counter 9)\*'
	'\MSSQL$*:Wait Statistics(*)\*'
	'\MSSQL$*:Workload Group Stats(*)\*'
	'\NNTP Commands(*)\*'
	'\NNTP Commands(_Total)\*'
	'\NNTP Server(*)\*'
	'\NNTP Server(_Total)\*'
	'\Print Queue(_Total)\*'
	'\ProcessorPerformance\*'
	'\SMTP NTFS Store Driver(*)\*'
	'\SMTP NTFS Store Driver(_Total)\*'
	'\SMTP Server(*)\*'
	'\SMTP Server(_Total)\*'
	'\SQL Server 2016 SQL Server XTP Storage(*)\*'
	'\SQL Server 2016 SQL Server XTP Transaction Log(*)\*'
	'\SQL Server 2016 XTP Cursors(*)\*'
	'\SQL Server 2016 XTP Databases(*)\*'
	'\SQL Server 2016 XTP Garbage Collection(*)\*'
	'\SQL Server 2016 XTP IO Governor(*)\*'
	'\SQL Server 2016 XTP Phantom Processor(*)\*'
	'\SQL Server 2016 XTP Transactions(*)\*'
#	'\Telephony\*'
	'\Web Service(_Total)\*'
	'\Web Service(Administration Web Site)\*'
	'\Web Service(Default Web Site)\*'
	'\Windows Media Station Service\*'
	'\Windows Media Unicast Service\*'
	'\XTP Cursors(*)\*'
	'\XTP Garbage Collection(*)\*'
	'\XTP Phantom Processor(*)\*'
	'\XTP Transactions(*)\*'
	'\Hyper-V Virtual Machine Summary\*' 
	'\Hyper-V Virtual Network Adapter\*' 
	'\Hyper-V Virtual Storage Device\*' 
	'\Hyper-V Virtual Switch\*' 
	'\Hyper-V Virtual Switch Port\*' 
	'\Hyper-V VM IO APIC\*' 
	'\Hyper-V VM Remoting\*' 
	'\Hyper-V VM Save, Snapshot, and Restore\*' 
	'\Hyper-V VM Vid Driver\*' 
	'\Hyper-V VM Vid Message Queue\*' 
	'\Hyper-V VM Vid Numa Node\*' 
	'\Hyper-V VM Vid Partition\*' 
	'\Hyper-V VM worker Process Memory Manager\*' 
	'\SQLServerDatabase Replica\*'
	)
	
$global:HyperVCounters = @(
	$global:GeneralCounters
	'\Hyper-V Hypervisor Logical Processor(*)\*'
	'\Hyper-V Hypervisor Virtual Processor(*)\*'
	'\Hyper-V Hypervisor Root Virtual Processor(*)\*'
	'\Hyper-V Dynamic Memory Balancer(*)\*'
	'\Hyper-V Dynamic Memory VM(*)\*('
	'\Hyper-V Virtual IDE Controller (Emulated)(*)\*'
	'\Hyper-V Virtual Storage Device(*)\*'
	'\Hyper-V Hypervisor Partition(*)\*'
	'\Hyper-V Hypervisor Root Partition(*)\*'
	'\Hyper-V Legacy Network Adapter(*)\*'
	'\Hyper-V Virtual Network Adapter(*)\*'
	'\Hyper-V Virtual Switch(*)\*'
	'\Hyper-V Virtual Switch Port(*)\*'
	'\Hyper-V Virtual Switch Processor(*)\*'
	'\Hyper-V VM Vid Partition(*)\*'
	'\Hyper-V VM Vid Numa Node(*)\*'
	#'\Hyper-V Dynamic Memory Integration Service(*)\*'
	#'\Hyper-V Hypervisor(*)\*'
	#'\Hyper-V Replica VM(*)\*'
	#'\Hyper-V Virtual Machine Bus(*)\*'
	#'\Hyper-V Virtual Machine Health Summary(*)\*'
	#'\Hyper-V VM Remoting(*)\*'
	#'\Hyper-V VM Save, Snapshot, and Restore(*)\*'
)

$global:BIZCounters = @(
	$global:NETCounters
	'\BizTalk:Messaging(*)\*' 
	'\XLANG/s Orchestrations(*)\*' 
	'\Distributed Transaction Coordinator\*' 
	'\BizTalk:Message Agent(*)\*' 
	'\BizTalk:Message Box:General Counters(*)\*' 
	'\BizTalk:Message Box:Host Counters(*)\*' 
	'\.Net Data Provider for SqlServer(*)\*'
	)

$global:NCCounters = @(
	$global:NETCounters
	'\Cache\*' 
	'\.NET CLR LocksAndThreads(*)\*' 
	'\Network Controller\*'
	)

$global:ALLCounters = @(
	$global:SQLCounters
	'\NTDS(*)\*'
	'\Database(lsass)\*'
	'\DirectoryServices(*)\*'
	'\Cluster Storage Hybrid Disks(*)\*'
	'\Cluster CSV Volume Cache\*'
	'\RDMA Activity(*)\*'
	'\HTTP Service Url Groups(*)\*'
	'\HTTP Service Request Queues(*)\*'
	'\GPU Engine\*'
	#_# '\Security System-Wide Statistics\*'	#we# see issue #383, reason for duplication of this counter on some 2022 Cluster nodes is unclear, no repro on 2019
	)
	If($OSBuild -lt 20348){	#383 do not add for Srv2022 or Win11
		$global:ALLCounters += '\Security System-Wide Statistics\*'
	}
#endregion --- PerfMon Counters

# initialize variables
If((IsStart) -or $StartAutoLogger.IsPresent -or $Stop.IsPresent -or !([string]::IsNullOrEmpty($StartDiag)) -or !([string]::IsNullOrEmpty($CollectLog))){
	if ([Environment]::Is64BitOperatingSystem -eq $True){
		$Global:ProcArch = 'x64'
	}else{
		$Global:ProcArch = 'x86'
	} # Binaries are supposed to be located in $global:ScriptFolder\BIN$Global:ProcArch or $global:ScriptFolder\BIN
	
	#add support for ARM (i.e. for Defender)
	[string]$arch = (Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture
	if ($arch -like "ARM*") {
		$Global:ProcArch = 'ARM'
		$global:ARM = $true
	}

	# add AutoLog Binary folders (\BIN***, \BIN) to $Env:Path #we#
	foreach ($sub in @("bin$Global:ProcArch", "bin")){
		Add-path (Join-Path -Path $(Split-Path $MyInvocation.MyCommand.Path -Parent) -ChildPath $sub)
	}

	# Add $Env:WinDir\System32 if it is missing
	$CommandPaths = $Env:Path -split ';'
	If($CommandPaths -notcontains "$Env:WinDir\System32"){
		LogInfoFile "Adding $Env:WinDir\System32 to PATH"
		Add-path "$Env:WinDir\System32"
	}

	# Set-/Clear-Variables Mini/Beta/Mode #we# 
	if($Mini){
		Set-Variable -scope Global -name Mini -Value $true
	}else{
		if ($Global:Mini){
			Clear-Variable -scope Global -name Mini
		}
	}
	if($beta){
		Set-Variable -scope Global -name beta -Value $true
	}else{
		if ($Global:beta){
			Clear-Variable -scope Global -name beta
		}
	}
	if($Mode){
		Set-Variable -scope Global -name Mode -Value $Mode
	}else{
		if ($Global:Mode){
			Clear-Variable -scope Global -name Mode
		}
	}
	if($DefenderDurInMin){
		Set-Variable -scope Global -name DefenderDurInMin -Value $DefenderDurInMin
	}else{
		if ($Global:DefenderDurInMin){
			Clear-Variable -scope Global -name DefenderDurInMin
		}
	}
}
$global:BinArch			= "\Bin" + $global:ProcArch

# Global variables previously (only defined) in _NET.psm1
<#
If($global:ProcArch -eq "x64"){
	$global:NotMyFaultPath =  $global:ScriptFolder + $BinArch + "\NotMyfault64c.exe"
}Else{
	$global:NotMyFaultPath =  $global:ScriptFolder + $BinArch + "\NotMyfaultc.exe"
}
#>
If($global:ProcArch -eq 'ARM') {$global:NotMyFaultPath =  $global:ScriptFolder + $BinArch + "\NotMyfaultc.exe"} else {$global:NotMyFaultPath =  $global:ScriptFolder + "\Bin\NotMyfaultc.exe"}
$global:DFSutilPath 	= $global:ScriptFolder + $BinArch + "\DFSutil.exe"
$global:PstatPath 		= $global:ScriptFolder + $BinArch + "\Pstat.exe"

#
# Script/Local variables
#
$script:FwScriptStartTime = Get-Date
$script:FwMonitorIntervalInSec = 5 #we# _MonitorIntervalInSec is configurable in tss_config.cfg
$global:ErrorLimit = 1
$script:FwIsMonitoringEnabledByConfigFile = $False
$script:RemoteStopEventID = 999	#we# _Remote_Stop_EventID is configurable in tss_config.cfg, as some customer use 999 for their app
$script:FwConfigParameters = @{}
$script:LogZipFileSuffix = '' # variables for descriptive $LogZipFile
$script:LogZipFileSuffixScn = ''
$Script:DataCollectionCompleted = $False
$Script:UsePartnerTTD = $False
$Script:fInRecovery = $False
$Script:fPreparationCompleted = $False
$script:StopAutologger = $False
$Script:PurgeTaskName = "AutoLog Purge Task"
$Script:PurgeTaskNameForAutologger = "AutoLog Purge Task for AutoLogger"
$Script:IsCrashInProgress = $False

# Collections
$script:ETWPropertyList = New-Object 'System.Collections.Generic.List[Object]'
$CommandPropertyList = New-Object 'System.Collections.Generic.List[Object]'
$globalTraceCatalog = New-Object 'System.Collections.Generic.List[Object]'
$AutoLog = New-Object 'System.Collections.Generic.List[Object]'
$TraceDefinitionList = New-Object 'System.Collections.Generic.List[Object]'
$StoppedTraceList = New-Object 'System.Collections.Generic.List[Object]'
$script:RunningScenarioObjectList = New-Object 'System.Collections.Generic.List[Object]'
$Script:ExecutedFunctionList = New-Object 'System.Collections.Generic.List[Object]'
$Script:DelayedExecutionList = New-Object 'System.Collections.Generic.List[Object]'
$Script:DelayedExecutionListForScenario = New-Object 'System.Collections.Generic.List[Object]'


# Color settings
if ($Host.Name -match "ISE")
{
	$Host.privatedata.ConsolePaneBackgroundColor = 'Black' # this works in PowerShell ISE only
	$Host.privatedata.ConsolePaneForegroundColor = 'Cyan'  # this works in PowerShell ISE only
}
else
{
	$Host.privatedata.ProgressBackgroundColor = 'Black'
	$Host.privatedata.ProgressForegroundColor = 'Cyan'
}


#
# ETL Tracig options
#
$Script:ETLMode = "circular" # other option is newfile
$Script:ETLMaxSize = "1024"  # for newfile we should use 500
$Script:ETLNumberToKeep = ""  # don't use it for circular mode, for newfile default is 10 and it can be provided.

If($global:BoundParameters.ContainsKey('EtlOptions')){
	$args = $EtlOptions.Split(":")
	$Script:ETLmode = $args[0]
	if (($Script:ETLmode -ne "circular") -and ($Script:ETLmode -ne "newfile"))
	{
		LogError "Invalid ETLOptions! ETLOption must contain either `'circular`' or `'newfile`'"
		CleanUpandExit
	}
	if (($Script:ETLmode -ne "circular") -and ($global:BoundParameters.ContainsKey('StartAutologger')))
	{
		LogError "Invalid ETLOptions! ETLOption must contain `'circular`' for -StartAutologger"
		CleanUpandExit
	}
	$Script:ETLMaxSize = $args[1]
	$Script:ETLNumberToKeep = $args[2]
	if(([string]::IsNullOrEmpty($Script:ETLNumberToKeep)) -and ($Script:ETLmode -eq "newfile") )
		{
			$Script:ETLNumberToKeep = "10" #default for newfile mode
		}
	if(([string]::IsNullOrEmpty($Script:ETLMaxSize)) -and ($Script:ETLmode -eq "newfile") )
		{
			$Script:ETLMaxSize = "512" #default for newfile mode
		}

	if($Script:ETLmode -eq "circular")
		{
			$Script:ETLNumberToKeep = "" #default for circular mode
		}
	if(([string]::IsNullOrEmpty($Script:ETLMaxSize)) -and ($Script:ETLmode -eq "circular") )
		{
			$Script:ETLMaxSize = "1024" #default for circular mode
		}
}

LogDebug ("============================== ETL Option ================================")
LogDebug ("ETLOptions: $EtlOptions")
LogDebug ("ETLMode=" + $Script:EtlMode + "   ETLMaxSize=" + $Script:ETLMaxSize + "   ETLNumberToKeep=" + $Script:ETLNumberToKeep)
LogDebug ("==========================================================================")

# AutoLogger
$AutoLoggerLogFolder = $global:LogFolder
$AutoLoggerPrefix = 'autosession\'
$AutoLoggerBaseKey = 'HKLM:\System\CurrentControlSet\Control\WMI\AutoLogger\'

# Batch file
$BatFileName = "$global:LogFolder\AutoLog.cmd"
$StartAutoLoggerBatFileName = "$AutoLoggerLogFolder\StartAutoLogger.cmd"
$StopAutoLoggerBatFileName = "$AutoLoggerLogFolder\StopAutoLogger.cmd"

# Read-only valuables
Set-Variable -Name 'fLogFileOnly' -Value $True -Option readonly

# Loading all POD modules.
LogDebug " ---> Loading all POD modules."
foreach($file in Get-ChildItem $Scriptfolder)
{
	$extension = [IO.Path]::GetExtension($file)
	if ($extension -eq ".psm1" )
	{
		$modName = ($file.Name).substring(0, ($file.Name).length - 5)
		$modPath = "$Scriptfolder\$($file.Name)"
		Remove-Module $modName -ErrorAction Ignore
		#LogDebug ("Remove module for $modName completed")
		Import-Module $modPath -DisableNameChecking
		#LogDebug ("Import module for $modPath completed")
	}
}
LogDebug " <--- Finished Loading all POD modules."
	
###
### Create trace properties and build trace list
###
If(!(IsStart)){
	# In case of not -Start, we add all traces to trace list to know what traces are currently running.
	$RequestedTraceList = $TraceSwitches.Keys
}

# For customETL
If($global:ParameterArray -Contains 'customETL'){
	$WIN_CustomETLProviders = @(
		$CustomETL	# List of user provided custom ETL providers, i.e. -CustomETL '{CBDA4DBF-8D5D-4F69-9578-BE14AA540D22}','Microsoft-Windows-PrimaryNetworkIcon'
	)
	LogInfoFile "Adding CustomETL providers: $CustomETL"
}

# Load all trace providers defined in POD modules
$ALLPODsProviderArray = Get-Variable -Name "*Providers"

LogDebug " ---> Building TraceDefinitionList"
ForEach($TraceProvider in $ALLPODsProviderArray){
	$TraceName = $TraceProvider.Name -replace ("Providers","")
	$ETEfileList = New-Object 'System.Collections.Generic.List[Object]'
	#If(($TraceProvider.value[0]).contains('!')){				  milanmil210527 commented
	If(!([string]::IsNullOrEmpty($TraceProvider.value[0])) -and (($TraceProvider.value[0]).contains('!'))){ #milanmil210527 added
		# This is possible multiple etl file trace. So check if this has really multiple etl file
		ForEach($Provider in $TraceProvider.value){
			$Token = $Provider -split ('!')
			$ETLFile = $ETEfileList | Where-Object {$_ -eq $Token[1]}
			If($ETLFile -eq $Null){
				$ETEfileList.add($Token[1]) 
			}
		}
		If($ETEfileList.Count -gt 1){
			$TraceDefinitionList += @{Name = $TraceName; Provider = $TraceProvider.value; MultipleETLFiles = 'yes'}
		}Else{
			$TraceDefinitionList += @{Name = $TraceName; Provider = $TraceProvider.value}
		}
	}Else{
		$TraceDefinitionList += @{Name = $TraceName; Provider = $TraceProvider.value}
	}
}
LogDebug " <--- done Building TraceDefinitionList"

<#
If($DebugMode.IsPresent){
	LogDebug "======================	 Trace Definition List	 ======================"
	ForEach($TraceDefinition in $TraceDefinitionList){
		Write-Host ($TraceDefinition.Name + " ") -NoNewline -ForegroundColor Green
	}
	Write-Host ""
	LogDebug "==========================================================================="
}
#>

# Read tss_config.cfg file and validate parameters
If((IsStart) -or ($CollectLog)){ # enable tss_config parameters for -CollectLog
	Try{
		LogDebug "Reading tss_config.cfg file"
		ReadConfigFile
		ValidateConfigFile
		If($DebugMode.IsPresent){
			LogInfo "====================== CONFIG PARAMETERS ======================"
			ForEach($Key in $FwConfigParameters.Keys){
				LogInfo ("  - $Key=" + $FwConfigParameters[$Key])
			}
			LogInfo "==============================================================="
		}
	}Catch{
		LogException "Invalid parameter(s) is configured in tss_config.cfg" $_
		CleanUpAndExit
	}
}

$WPRLogFile = "$global:LogFolder\$($LogPrefix)WPR_$WPR.etl"
$WPRBootTraceSupportedVersion = @{OS=10;Build=15063} # BootTrace is supported from RS2+
$WPRAutLoggerKey = "$AutoLoggerBaseKey\WPR_initiated_WprApp_boottr_WPR Event Collector"

$WPRProperty = @{
	Name = 'WPR'
	TraceName = 'WPR'
	LogType = 'Command'
	CommandName = 'wpr.exe'
	Providers = $Null
	LogFileName = "`"$WPRLogFile`""
	StartOption = "-start GeneralProfile -start CPU -start DiskIO -start FileIO -Start Registry -FileMode -recordtempto $global:LogFolder"
	StopOption = "-stop $WPRLogFile"
	PreStartFunc = $Null
	PostStopFunc = $Null
	StopTimeOutInSec = 1800 # 30 minutes
	AutoLogger = @{
		AutoLoggerEnabled = $False
		AutoLoggerLogFileName = "$AutoLoggerLogFolder\WPR-BootTrace$LogSuffix.etl"
		AutoLoggerSessionName = 'WPR(BootTrace)'
		AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot FileIO -addboot DiskIO -addboot Registry -filemode -recordtempto $AutoLoggerLogFolder"
		AutoLoggerStopOption = "-BootTrace -stopboot `"$AutoLoggerLogFolder\WPR-BootTrace$LogSuffix.etl`""
		AutoLoggerKey = "$AutoLoggerBaseKey" + "WPR_initiated_WprApp_boottr_WPR Event Collector"
	}
	Wait = $True
	#SupportedOSVersion = @{OS=10;Build=10240}
	SupportedOSVersion = @{OS=6;Build=9600}	#we# 2012-R2+
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.WPR
	StopPriority = $StopPriority.WPR
	WindowStyle = $Null
}

If($global:ParameterArray -contains "xperf"){
	$XperfLogFile = "$global:LogFolder\$($LogPrefix)Xperf-$Xperf.etl"
}Else{
	$XperfLogFile = "$global:LogFolder\$($LogPrefix)Xperf.etl"
}
$XperfProperty = @{
	Name = 'Xperf'
	TraceName = 'Xperf'
	LogType = 'Command'
	CommandName = "xperf.exe"
	Providers = $Null
	LogFileName = $XperfLogFile
	StartOption = "-on"  # This will set in FixUpXperfProperty later
	StopOption = "-stop -d $XperfLogFile"
	PreStartFunc = $Null
	PostStopFunc = $Null
	StopTimeOutInSec = 1800 # 30 minutes
	AutoLogger = @{
		AutoLoggerEnabled = $False
		AutoLoggerLogFileName = "$AutoLoggerLogFolder\Xperf-BootTrace$LogSuffix.etl"
		AutoLoggerSessionName = 'Xperf(BootTrace)'
		AutoLoggerStartOption = "-BootTrace"
		AutoLoggerStopOption = "-stop -d $AutoLoggerLogFolder\Xperf-BootTrace$LogSuffix.etl"
		AutoLoggerKey = "HKLM:\System\CurrentControlSet\Control\WMI\GlobalLogger"
	}
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Xperf
	StopPriority = $StopPriority.Xperf
	WindowStyle = $Null
}

# Netsh(Packet capturing)
$NetshLogFile = "$global:LogFolder\$($LogPrefix)Netsh_packetcapture.etl"
if ($OSBuild -le 9200) { $Script:NetshTraceReport ="report=no" } else { $Script:NetshTraceReport ="report=disabled" }	#we#  preferred Report mode depends on OS

$NetshProperty = @{
	Name = 'Netsh'
	TraceName = 'Netsh'
	LogType = 'Command'
	CommandName = 'netsh.exe'
	Providers = $Null
	LogFileName = "`"$NetshLogFile`""
	StartOption = "trace start fileMode=circular"  # This will be updated in FixUpNetshProperty() later.
	StopOption = 'trace stop'
	PreStartFunc = $Null
	PostStopFunc = $Null
	StopTimeOutInSec = 600 # 10 minutes
	AutoLogger = @{
		AutoLoggerEnabled = $False
		AutoLoggerLogFileName = "$AutoLoggerLogFolder\$($LogPrefix)packetcapture-AutoLogger.etl"
		AutoLoggerSessionName = 'Netsh(persistent=yes)'
		AutoLoggerStartOption = "trace start persistent=yes fileMode=circular"
		AutoLoggerStopOption = 'trace stop'
		AutoLoggerKey = "$AutoLoggerBaseKey" + "-NetTrace-$env:UserDomain-$env:username"
	}
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Netsh
	StopPriority = $StopPriority.Netsh
	WindowStyle = $Null
}


#If($OperatingSystemInfo.OSVersion -eq 6 -and $OSBuild -eq 9600){ #we# fails for 2012*
If($OSBuild -eq 9600){ 
	$NetshProperty.AutoLogger.AutoLoggerKey = "$AutoLoggerBaseKey\NetTrace-$env:UserDomain-$env:username"
}

# Netsh WFPdiag
$WFPdiagLogfile = "$global:Logfolder\$LogPrefix" + "WFPdiag.cab"
$WFPdiagProperty = @{
	Name = 'WFPdiag'
	TraceName = 'Netsh WFPdiag'
	LogType = 'Custom'
	CommandName = $Null
	Providers = $Null
	LogFileName = "$global:Logfolder\$LogPrefix" + "WFPdiag.cab"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartWFPdiag'
	StopFunc = 'StopWFPdiag'
	PostStopFunc = $Null
	DetectionFunc = 'DetectWFPdiag'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.WFPdiag
	StopPriority = $StopPriority.WFPdiag
	WindowStyle = $Null
}

$PktMonProperty = @{
	Name = 'PktMon'
	TraceName = 'PktMon(Packet Monitor)'
	LogType = 'Custom'
	CommandName = $Null
	Providers = $Null
	LogFileName = "$global:Logfolder\$LogPrefix" + "PktMon.etl"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartPktMon'
	StopFunc = 'StopPktMon'
	PostStopFunc = $Null
	DetectionFunc = 'DetectPktMon'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = @{OS=10;Build=17763}
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.PktMon
	StopPriority = $StopPriority.PktMon
	WindowStyle = $Null
}

$FiddlerProperty = @{
	Name = 'Fiddler'
	TraceName = 'Fiddler'
	LogType = 'Custom'
	CommandName = "ExecAction.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartFiddler'
	StopFunc = 'StopFiddler'
	PostStopFunc = $Null
	DetectionFunc = 'DetectFiddler'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Fiddler
	StopPriority = $StopPriority.Fiddler
	WindowStyle = $Null
}

$SysMonProperty = @{
	Name = 'SysMon'
	TraceName = 'Sysmon(System Monitor)'
	LogType = 'Custom'
	CommandName = $Null
	Providers = $Null
	LogFileName = "$global:Logfolder\$env:computername-Microsoft-Windows-Sysmon-Operational.txt"  # This is just a place holder. This file will not be used.
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartSysMon'
	StopFunc = 'StopSysMon'
	PostStopFunc = $Null
	DetectionFunc = 'DetectSysMon'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.SysMon
	StopPriority = $StopPriority.SysMon
	WindowStyle = $Null
}

$ProcmonLogFile = "$global:LogFolder\$($LogPrefix)Procmon.pml"
$fDonotDeleteProcmonReg = $False
$ProcmonProperty = @{
	Name = 'Procmon'
	TraceName = 'Procmon'
	LogType = 'Command'
	CommandName = "Procmon.exe"
	Providers = $Null
	LogFileName = "`"$ProcmonLogFile`""
	StartOption = "/accepteula /quiet /backingfile `"$ProcmonLogFile`""
	StopOption = '/accepteula /Terminate'
	PreStartFunc = $Null
	PostStopFunc = $Null
	StopTimeOutInSec = 900 # 15 minutes
	AutoLogger = @{
		AutoLoggerEnabled = $False
		AutoLoggerLogFileName = "$AutoLoggerLogFolder\Procmon-BootLogging.pml"
		AutoLoggerSessionName = 'Procmon(BootLogging)'
		AutoLoggerStartOption = '/accepteula /EnableBootLogging'
		AutoLoggerStopOption = "/accepteula /ConvertBootLog `"$AutoLoggerLogFolder\Procmon-BootLogging.pml`""
		AutoLoggerKey = 'HKLM:\System\CurrentControlSet\Services\Procmon24'
	}
	Wait = $False
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Procmon
	StopPriority = $StopPriority.Procmon
	WindowStyle = "Minimized"
}

$PSRProperty = @{
	Name = 'PSR'
	TraceName = 'PSR(Problem Steps Recorder)'
	LogType = 'Command'
	CommandName = 'psr.exe'
	Providers = $Null
	LogFileName = "`"$global:LogFolder\$($LogPrefix)PSR.zip`""
	StartOption = "/start /output `"$($global:LogFolder)\$($LogPrefix)PSR.zip`" /maxsc 100 /gui 0"
	StopOption = '/stop'
	PreStartFunc = 'PSRPrestart'
	StartFunc = $Null
	StopFunc = $Null
	PostStopFunc = 'PSRPostStop'
	DetectionFunc = $Null
	StopTimeOutInSec = 30
	AutoLogger = $Null
	Wait = $False
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.PSR
	StopPriority = $StopPriority.PSR
	WindowStyle = $Null
}

# Video
$wmvFile = "$global:LogFolder\$($LogPrefix)VideoRepro.wmv"
$VideoLogFile = "$global:LogFolder\$($LogPrefix)VideoRepro.log"
$VideoProperty = @{
	Name = 'Video'
	TraceName = 'Video recorder'
	LogType = 'Command'
	CommandName = 'RecorderCommandLine.exe'
	Providers = $Null
	LogFileName = $wmvFile
	StartOption = "-start -fullscreen -output $wmvFile -overwrite -log $VideoLogFile"
	StopOption = '-stop'
	PreStartFunc = $Null
	PostStopFunc = $Null
	AutoLogger = $Null
	Wait = $False
	StopTimeOutInSec = 30
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Video
	StopPriority = $StopPriority.Video
	WindowStyle = "Minimized"
}

$LiveKDProperty = @{
	Name = 'LiveKD'
	TraceName = 'LiveKD'
	LogType = 'Custom'
	CommandName = "Livekd.exe"
	Providers = $Null
	LogFileName = "$global:Logfolder\$($LogPrefix)liveKdDump.dmp"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartLiveKD'
	StopFunc = 'StopLiveKD'
	PostStopFunc = $Null
	DetectionFunc = 'DetectLiveKD'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.LiveKD
	StopPriority = $StopPriority.LiveKD
	WindowStyle = $Null
}

$GPresultProperty = @{
	Name = 'GPresult'
	TraceName = 'GPresult'
	LogType = 'Custom'
	CommandName = "GPresult.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartGPresult'
	StopFunc = 'StopGPresult'
	PostStopFunc = $Null
	DetectionFunc = 'DetectGPresult'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.GPresult
	StopPriority = $StopPriority.GPresult
	WindowStyle = $Null
}

$HandleProperty = @{
	Name = 'Handle'
	TraceName = 'Handle'
	LogType = 'Custom'
	CommandName = "Handle.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartHandle'
	StopFunc = 'StopHandle'
	PostStopFunc = $Null
	DetectionFunc = 'DetectHandle'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Handle
	StopPriority = $StopPriority.Handle
	WindowStyle = $Null
}

$PoolMonProperty = @{
	Name = 'PoolMon'
	TraceName = 'PoolMon'
	LogType = 'Custom'
	CommandName = "PoolMon.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartPoolMon'
	StopFunc = 'StopPoolMon'
	PostStopFunc = $Null
	DetectionFunc = 'DetectPoolMon'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.PoolMon
	StopPriority = $StopPriority.PoolMon
	WindowStyle = $Null
}

$ProcDumpProperty = @{
	Name = 'ProcDump'
	TraceName = 'ProcDump'
	LogType = 'Custom'
	CommandName = "ProcDump.exe"
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartProcDump'
	StopFunc = 'StopProcDump'
	PostStopFunc = $Null
	DetectionFunc = 'DetectProcDump'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.ProcDump
	StopPriority = $StopPriority.ProcDump
	WindowStyle = $Null
}

$WireSharkProperty = @{
	Name = 'WireShark'
	TraceName = 'WireShark'
	LogType = 'Custom'
	CommandName = "$env:ProgramFiles\Wireshark\dumpcap.exe"
	Providers = $Null
	LogFileName = "$global:Logfolder\$($LogPrefix)WireShark-packetcapture.pcap"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartWireShark'
	StopFunc = 'StopWireshark'
	PostStopFunc = $Null
	DetectionFunc = 'DetectWireshark'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.WireShark
	StopPriority = $StopPriority.WireShark
	WindowStyle = $Null
}

# Performance Monitor log
$Script:PerfMonInterval = 10 # default 10 seconds

# PerfMon logs
$SupportedPerfCounter = @{
	'General'	= 'Basic CPU, Memory, Disk and process counters'
 	'ALL'		= 'General + SMB + NET + SQL + DC + Cluster counters'
	'BC'		= 'General + SMB + NET + BranchCache counters'
	'BIZ'		= 'General + SMB + NET + BIZ counters'
	'DC'		= 'General + SMB + NET + DomainController counters'
	'HyperV'	= 'General + HyperV counters'
	'NC'		= 'General + SMB + NET + Network Controller counters'
	'NET'		= 'General + SMB + NET counters'
	'SMB'		= 'General + SMB counters'
	'SQL'		= 'General + SMB + NET + SQL counters'
}

LogDebug " ---> Preparing supported Perfcounter list"
$ALLPODsPerfCounter = Get-Variable -Name "*_SupportedPerfCounter" -ValueOnly
ForEach($PODPerfCounter in $ALLPODsPerfCounter){
	ForEach($Key in $PODPerfCounter.keys){
		$SupportedPerfCounter.Add($Key, $PODPerfCounter[$Key])
	}
}
LogDebug " <--- Preparing supported Perfcounter list"

$PerfMonProperty = @{
	Name = 'PerfMon'
	TraceName = "PerfMon log with short interval"
	LogType = 'Perf'
	CommandName = 'logman.exe'
	Providers = $GeneralCounters
	LogFileName = "$global:LogFolder\$($LogPrefix)PerfMon_$($PerfMon)_$($PerflogInterval).blg"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	PostStopFunc = $Null
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Perf
	StopPriority = $StopPriority.Perf
}

# Performance Monitor with long interval
$Script:PerfMonLongInterval = 10 * 60 # default 10 minutes

$PerfMonLongProperty = @{
	Name = 'PerfMonLong'
	TraceName = "PerfMon log with long interval"
	LogType = 'Perf'
	CommandName = 'logman.exe'
	Providers = $GeneralCounters
	LogFileName = "$global:LogFolder\$($LogPrefix)PerfMonLong_$($PerfMonLong)_$($PerflogLongInterval).blg"
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	PostStopFunc = $Null
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.Perf
	StopPriority = $StopPriority.Perf
}

$TTDProperty = @{
	Name = 'TTD'
	TraceName = 'TTD trace'
	LogType = 'Custom'
	CommandName = $Null
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartTTD'
	StopFunc = 'StopTTD'
	PostStopFunc = $Null
	DetectionFunc = 'DetectTTD'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null # @{OS=10;Build=17763} # From RS5.
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.TTD
	StopPriority = $StopPriority.TTD
}

$CommandPropertyList = @(
	$FiddlerProperty
	$LiveKDProperty
	$NetshProperty
	$PerfMonProperty
	$PerfMonLongProperty
	$PktMonProperty
	$ProcDumpProperty
	$ProcmonProperty
	$PSRProperty
	$RASdiagProperty
	$SysMonProperty
	$TTDProperty
	$VideoProperty
	$WFPdiagProperty
	$WireSharkProperty
	$WPRProperty
	$XperfProperty
	$GPresultProperty
	$HandleProperty
	$PoolmonProperty
)

# Converting $Mini to noSwitches.
If($global:BoundParameters.ContainsKey('Mini') -and !$global:BoundParameters.ContainsKey('Status')){
	$noSwitches = @(
		'noBasicLog'
		'noPSR'
		'noSDP'
		'noVideo'
		'noXray'
		'noZip'
	)
	LogInfo "Extracting `'Mini`' switch and adding the extracted parameters to ParameterArray"
	ForEach($noSwitch in $noSwitches){
		If(!($global:BoundParameters.ContainsKey($noSwitch))){
			LogDebug "Adding $noSwitch to BoundParameters"
			$global:BoundParameters.Add($noSwitch,$True)
		}Else{
			LogDebug "$noSwitch is already contained in BoundParameters. Skipping this switch."
		}
	}
}

# Initialize $global:ParameterArray again as parameters have been updated until reaching here.
[String[]]$global:ParameterArray = $Null
ForEach($Key in $global:BoundParameters.Keys){
	$global:ParameterArray += $Key
}

Try{
	Switch($global:ParameterArray[0]){
		'CollectLog'{
			ProcessCollectLog
		}
		'Help'{
			ProcessHelp
		}
		default{
			ProcessCollectLog
		}
	}
}Finally{ 
	# Usually we reach here when user stops the script with Ctrl + C
	CleanUpandExit 
}

Write-Host ""
CleanUpandExit
#endregion MAIN


