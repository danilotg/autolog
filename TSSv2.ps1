<#
.SYNOPSIS
   Collect traces for several scenarios on Windows.

.DESCRIPTION
   Collect HIVES/EVTX/ETW/WPP traces for Windows components 
   Also Netsh(packet capture)/Procmon/PerfMon/PSR/Video/SysMon/WPR/xPerf/TTD... can be taken at the same time.
   This script supports -StartAutoLogger for ETW traces and in addition to this, BootLogging
   including BootTrace(WPR), persistent=yes(Netsh) and /BootLogging(Procmon) are also supported.
   Run 'Get-Help TSSv2.ps1 -full' for more detail.

.EXAMPLE
.\TSSv2.ps1 -CollectLog DND_CodeIntegrity,DND_PNP,DND_Servicing,DND_SETUP,DND_WinUpd,DND_WU,DND_WUlogs
#>

[CmdletBinding(DefaultParameterSetName='Start')]
Param (
	[Parameter(ParameterSetName='Start', Position=0)]
	[switch]$Start,
	[Parameter(ParameterSetName='StartAutoLogger', Position=0)]
	[switch]$StartAutoLogger,
	[Parameter(ParameterSetName='StartDiag', Position=0)]
	[String[]]$StartDiag,
	[Parameter(ParameterSetName='Start')]
	[switch]$StartNoWait,	# do not wait at stage: Press ANY-Key to stop
	[Parameter(ParameterSetName='Stop', Position=0)]
	[switch]$Stop,
	[switch]$StopAutologger, # For compatibility.
	[Parameter(ParameterSetName='RemoveAutoLogger', Position=0)]
	[switch]$RemoveAutoLogger,
	[Parameter(ParameterSetName='Find', Position=0)] # Mandatory=$true, 
	#[ValidateNotNullorEmpty()]
	[String]$Find,	# -> ProcessFindKeyword
	[Parameter(ParameterSetName='FindGUID', Position=0)]
	[String]$FindGUID,
	[Parameter(ParameterSetName='Help', Position=0)]
	[Switch]$Help,
	[Parameter(ParameterSetName='CollectLog', Position=0)]
	[String[]]$CollectLog,
	[Parameter(ParameterSetName='List', Position=0)]
	[switch]$List,
	[Parameter(ParameterSetName='ListSupportedCommands', Position=0)]
	[switch]$ListSupportedCommands,
	[Parameter(ParameterSetName='ListSupportedDiag', Position=0)]
	[switch]$ListSupportedDiag,
	[Parameter(ParameterSetName='ListSupportedLog', Position=0)]
	[switch]$ListSupportedLog,
	[Parameter(ParameterSetName='ListSupportedNetshScenario', Position=0)]
	[switch]$ListSupportedNetshScenario,
	[Parameter(ParameterSetName='ListSupportedNoOptions', Position=0)]
	[switch]$ListSupportedNoOptions,
	[Parameter(ParameterSetName='ListSupportedPerfCounter', Position=0)]
	[switch]$ListSupportedPerfCounter,
	[Parameter(ParameterSetName='ListSupportedScenarioTrace', Position=0)]
	[switch]$ListSupportedScenarioTrace,
	[Parameter(ParameterSetName='ListSupportedSDP', Position=0)]
	[switch]$ListSupportedSDP,
	[Parameter(ParameterSetName='ListSupportedTrace', Position=0)]
	[switch]$ListSupportedTrace,
	[Parameter(ParameterSetName='ListSupportedWPRScenario', Position=0)]
	[switch]$ListSupportedWPRScenario,
	[Parameter(ParameterSetName='ListSupportedXperfProfile', Position=0)]
	[switch]$ListSupportedXperfProfile,
	[Parameter(ParameterSetName='Set', Position=0)]
	[String]$Set,
	[Parameter(ParameterSetName='Unset', Position=0)]
	[String]$Unset,
	[Parameter(ParameterSetName='Status', Position=0)]
	[switch]$Status,
	[Parameter(ParameterSetName='TraceInfo', Position=0, HelpMessage='Choose one from: all|switch-name|command|scenario')]
	[ValidateNotNullOrEmpty()]
	[String]$TraceInfo,
	[Parameter(ParameterSetName='Version', Position=0)]
	[switch]$Version,  		# This will show current TSSv2 script version

#region ### Trace provider component-names

# For_Developers:addNewSubScenario_component_step_1
# Example
	#[Parameter(ParameterSetName='Start')]
	#[Parameter(ParameterSetName='StartAutoLogger')]
	#[switch]$POD_ComponentName,  #instead of POD specify 3-letter POD name

#region ----- ADS POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_Basic,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_AccountLockout,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_ESR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_Auth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_ADcore,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_ADsam,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_BadPwd,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_LDAPsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_LockOut,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_DFSR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_ADCS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_perf,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_GPedit,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_GPmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_GPsvc, 
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_PKICLIENT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_NGC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_Bio,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_LSA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_NtLmCredSSP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_Kerb,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_KDC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_Netlogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_Profile,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_SAM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_SSL,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_CryptoDPAPI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_CryptoPrimitives,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_EFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_WebAuth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_SmartCard,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_CredprovAuthui,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_NTKernelLogger,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_ShellRoaming,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_CDP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_WinHTTP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_CEPCES,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_IIS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_GPO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_TEST,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$ADS_W32Time,
#endregion ----- ADS POD providers -----

#region ----- DND POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$DND_CBS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$DND_CodeIntegrity,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$DND_PNP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$DND_Servicing,
#endregion ----- DND POD providers -----

#region ----- NET POD providers ----- 
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_TestMe,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_AfdTcpFull,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_AfdTcpBasic,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_AppLocker,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_AppV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Auth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_BFE,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_BGP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_BITS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Bluetooth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_BranchCache,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_CAPI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_COM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Container,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_CSC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_DAcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_DAmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_DAsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_DCLocator,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_DHCPcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_DHCPsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_DNScli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_DNSsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Docker,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_EFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Firewall,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_FltMgr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_FSRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_HNS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_HTTP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_HttpSys,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_HypHost,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_HypVM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_HypVmBus,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_HypVmms,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_HypVmWp,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_ICS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_IPAM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_IPhlpSvc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_IPsec,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_iSCSI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_KernelIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_LBFO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_LDAPcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_MBAM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_MBN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_MDM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_MFAext,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Miracast,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_MUX,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NCA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NCHA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NCSI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NDIS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NDISwan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NETIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Netlogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Netsetup,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NetworkUX,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NFC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NFScli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NFSsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NLB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NPS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_NTFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_OLE32,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Outlook,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_PCI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_PerfLib,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_PnP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_PortProxy,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_PowerShell,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_PrintSvc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Proxy,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_QoS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RadioManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RAmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RAS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RasMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RDMA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RNDIS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsAuth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsAuthMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsAudio,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsBroker,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsCore,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsRDclient,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsRDclientMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsH,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsHMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsPrintSpool,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsRAIL,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsRDGW,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsRDGWMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsRDMS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsRDMSMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsRDPCLIP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsRDPDR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsUsrLogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsUsrLogonMan,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsVIP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RdsWRKSPC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RDScommon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RDScli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RDSsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_RPC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_SBSL,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_SCCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_SCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_SdnNC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_SMB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_SMBcli,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_SMBsrv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_SMBcluster,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_fskm,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_fsum,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_dns,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_fr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_nbt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_tcp,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_DFSmgmt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_dfsn,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_srv,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_smbhash,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_sr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_rpcxdr,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_sec,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_SNMP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_SQLcheck,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_TAPI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_TaskSch,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_TLS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_UNChard,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_VMswitch,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_VPN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WebClient,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WebIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WFP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WinNAT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Winlogon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Winsock,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WinRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WIP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WmbClass,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WMI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WNV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WSman,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_WWAN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$NET_Workfolders,
#endregion ----- NET POD providers -----

#region ----- PRF POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$PRF_Perflib,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$PRF_RADAR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$PRF_Sysmain,
#endregion ----- PRF POD providers -----

#region ----- SHA POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_ATAPort,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_CDROM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_CSVFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_CSVspace,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_Dedup,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_FSRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_HyperV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_HypHost,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_HypVM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_ISCSI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_MPIO,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_MsCluster,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_msDSM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_NFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_ShieldedVM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_ReFS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_Storage,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_StorageReplica,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_StorageSpace,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_Storport,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_Storsvc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_USB,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_VDS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_VHDMP,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_VmConfig,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_VML,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_VMM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_VSS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$SHA_WSB,
#endregion ----- SHA POD providers -----

#region ----- UEX POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Alarm,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_AppCompat,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_AppID,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_AppV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_AppX,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Auth,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Calc,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Camera,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_CldFlt,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_ClipBoard,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_CloudSync,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_COM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_ContactSupport,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Cortana,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_CRYPT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_DeviceStore,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_DM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_DSC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_DWM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_ESENT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_EVT,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_EventLog,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Font,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_FSLogix,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_IME,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_ImmersiveUI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_LicenseManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Logon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_LSA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Media,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_MMC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_MSRA,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Nls,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Photo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Print,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_PrintEx,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_QuickAssist,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_RDS,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_RDWebRTC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_RestartManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_TSched,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_SCM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Search,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_ServerManager,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Shell,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Shutdown,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Speech,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_StartMenu,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Store,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_SystemSettings,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Task,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_UEV,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_UserDataAccess,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_VAN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_WER,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_Win32k,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_WinRM,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_WMI,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_WMIBridge,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_WPN,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_WSC,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_WVD,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$UEX_XAML,
#endregion ----- UEX POD providers -----

#region ----- DEV POD providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$DEV_TEST1,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$DEV_TEST2,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$DEV_TEST3,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$DEV_TEST4,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$DEV_TEST5,
#endregion ----- DEV POD providers -----

#region ----- CustomETL providers -----
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$WIN_CustomETL,
#endregion ----- CustomETL providers -----

#endregion ### Trace provider component-names

#region ### Command switches
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String[]]$CustomETL,
	[Parameter(ParameterSetName='Start')]
	[Switch]$Fiddler,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$GPresult,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$Handle,
	[Parameter(ParameterSetName='Start')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$LiveKD,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$Netsh,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String[]]$NetshScenario,
	[Parameter(ParameterSetName='Start')]
	[String]$PerfMon,
	[Parameter(ParameterSetName='Start')]
	[String]$PerfMonLong,
	[Parameter(ParameterSetName='Start')]
	[Switch]$PktMon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("Start", "Stop", "Both")]
	[String]$PoolMon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$Procmon,
	[Parameter(ParameterSetName='Start')]
	[switch]$PSR,
	[Parameter(ParameterSetName='Start')]
	[Switch]$RASdiag,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Parameter(Mandatory=$False,HelpMessage='Choose one technology from: Apps|Cluster|S2D|SCCM|CTS|DA|Dom|DPM|HyperV|Net|Perf|Print|RDS|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|SUVP|VSS|Mini|Nano|Remote|Repro|RFL|All')]
	[ValidateSet("Apps","Net","DA","Dom","DPM","CTS","Print","HyperV","Setup","Perf","Cluster","S2D","SCCM","RDS","Remote","SQLbase","SQLconn","SQLmsdtc","SQLsetup","SUVP","VSS","mini","nano","Repro","RFL","All")]
	[String[]]$SDP,
	[ValidateSet("noNetadapters","skipBPA","skipHang","skipNetview","skipSddc","skipTS","skipHVreplica","skipCsvSMB")]
	[Parameter(Mandatory=$False,HelpMessage='Choose technologies you want to skip from: noNetadapters|skipBPA|skipHang|skipNetview|skipSddc|skipTS|skipHVreplica|skipCsvSMB')]
	[String[]]$SkipSDPList,
	[Parameter(ParameterSetName='Start')]
	[Switch]$SysMon,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[String[]]$TTD,
	[Parameter(ParameterSetName='Start')]
	[Switch]$Video,
	[Parameter(ParameterSetName='Start')]
	[Switch]$WFPdiag,
	[Parameter(ParameterSetName='Start')]
	[Switch]$WireShark,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("BootGeneral", "General", "CPU", 'Memory', 'Registry', 'Storage', 'Wait', 'Network', 'SQL', 'Graphic', 'Xaml')]
	[String]$WPR,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[ValidateSet("General", "CPU", "Disk", 'Memory', "Network", "Pool", "PoolNPP", "Registry", "SMB2", "SBSL", "SBSLboot", "Leak")]
	[String]$Xperf,

#endregion ### Command switches

#region ### Control switches
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[switch]$BasicLog,
	[switch]$CreateBatFile,
	[Parameter(ParameterSetName='Start')]
	#[Parameter(ParameterSetName='StartAutoLogger')]
	[Array]$CustomParams,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[string]$EtlOptions,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Int]$EvtDaysBack = 30,		# used for Eventlog conversion to csv and txt
	[Parameter(ParameterSetName='Start')]
	#[Parameter(ParameterSetName='StartAutoLogger')]
	[string]$ExternalScript,
	[Parameter(ParameterSetName='Start')]
	[Int]$PerfIntervalSec,
	[Parameter(ParameterSetName='Start')]
	[Int]$PerfLongIntervalMin,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[String]$LogFolderName,
	[switch]$Mini,			# This will skip some data collections, see in Tss_NET.psm1
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[ValidateSet("Basic","Advanced","Full","Verbose","Hang","Restart","GetFarmdata","Swarm","Kube","NFSperm","traceMS")]
	[Parameter(Mandatory=$False,HelpMessage='Choose script mode from: Basic|Advanced|Full|Verbose|Hang|Restart|Swarm|Kube|GetFarmdata|NFSperm|traceMS')]
	[String]$Mode,			# Run script in Basic|Advanced|Full|Verbose|Hang|Restart|Swarm|Kube|GetFarmdata|NFSperm|traceMS data collection mode. 'Restart' will restart associated service; Swarm|Kube for NET_Container
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$ProcmonFilter,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[String]$ProcmonPath,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[switch]$Remote,		# use for TSS remote execution	
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[string[]]$Scenario,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[String]$TTDMaxFile,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[ValidateSet("Full","Ring","Onlaunch")]
	[String]$TTDMode,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[String]$TTDOptions,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='TTD')]
	[String]$TTDPath,
	[switch]$Update,
	[ValidateSet("Online","Quick","Full","Force","Lite")]
	[Parameter(Mandatory=$False,HelpMessage='Choose update mode from: Online|Quick|Full|Force|Lite')]
	[String]$UpdMode = "Online",  	# This will update current TSSv2 script version to latest from GitHub
	[Parameter(ParameterSetName='Start')]
	[String]$WaitEvent,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Switch]$Xray = $True,	# Run always (for Telemetry), unless -noXray 
	[switch]$beta = $False,	# hidden switch; set to $False = normal Production mode, $True = Testing/newFeature mode enabled
	[switch]$Assist,		# Accessibility Mode
	[switch]$noAdminChk,	# skip Admin check, which verifies elevated Admin rights
	[switch]$noAsk,			# do not ask about good/failing scenario text input before compressing data
	[switch]$noCab,			# Same as noZip. This will skip Compress phase. This switch is for having a comaptibility with TSSv1.
	[switch]$noClearCache,	# do not clear DNS,NetBios,Kerberos,DFS chaches at start
	[switch]$noCrash,		# do not run Crash after reboot again when using 'TSSv2 -stop -noCrash'
	[switch]$noEventConvert,# do not convert Eventlogs to .CSV or .TXT format
	[switch]$noFiddler,		# do not start Fiddler
	[switch]$noGPresult,	# do not run GPresult, used to override setting in preconfigured TS scenarios
	[switch]$noHandle,		# do not collect Handle.exe
	[switch]$noHang,		# do not wait forever when data collection seems to hang 
	[switch]$noLiveKD,		# do not capture LiveKD
	[switch]$noNetsh,		# do not run Netsh, used to override setting in preconfigured TS scenarios
	[switch]$noPerfMon,		# do not run PerfMon, used to override setting in preconfigured TS scenarios
	#[switch]$noPersistent,	# tbd: do not use predefined Persistent in scenarios
	[switch]$noPktMon,		# do not start PktMon
	[switch]$noPoolMon,		# do not run PoolMon at start and stop
	[switch]$noPrereqC,		# do not run PreRequisiteCheckInStage1/2() and PreRequisiteCheckForStart()
	[switch]$noProcmon,		# do not run Procmon, used to override setting in preconfigured TS scenarios
	[switch]$noRASdiag,		# do not start RASdiag
	[switch]$noRecording,	# do not ask about consent for performing PSR or Video recording, and do not start these recordings
	[switch]$noRestart,		# do not restart associated service
	[switch]$noSDP,			# do not gather SDP report, i.e. when using script in scheduled tasks
	[switch]$noSound,		# do not play attention sound
	[switch]$noSysMon,		# do not start SysMon
	[switch]$noTTD,			# do not start TTD (Time Travel Debugging)
	[switch]$noVersionChk,	# skip script Version check 
	[switch]$noWFPdiag,		# do not start WFPdiag
	[switch]$noWireShark,	# do not start WireShark
	[switch]$noWPR,			# do not run WPR, used to override setting in preconfigured TS scenarios
	[switch]$noXperf,		# do not run xPerf, used to override setting in preconfigured TS scenarios
	[switch]$noXray,		# do not start Xray troubleshooter
	[switch]$noZip,			# This will skip Compress phase
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[switch]$noUpdate,		# do not check online for latest TSS version on Github, no AutoUpdate
	[Parameter(ParameterSetName='Start')]
	[switch]$noPSR,
	[Parameter(ParameterSetName='Start')]
	[switch]$noVideo,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='NetshScenario')]
	[switch]$NoPacket,		# prevent packets from being captured (only ETW traces in the ScenarioName will be captured)
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[switch]$noBasicLog,
<#	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[String[]]$noSettingList, #>
	[switch]$DebugMode,
	[switch]$AcceptEula,
	[Switch]$AddDescription,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$NetshMaxSize,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$NetshOptions,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$WPROptions,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Int]$XperfMaxFile,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$XperfOptions,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$XperfPIDs,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[String]$XperfTag,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Switch]$SkipPdbGen,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[String]$CommonTask,
	[Switch]$EnableCOMDebug,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='StartAutoLogger')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[Switch]$NewSession,
	[Switch]$Discard,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Switch]$CollectComponentLog,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[String[]]$ProcDump,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[String]$ProcDumpInterval,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[Parameter(ParameterSetName='StartDiag')]
	[ValidateSet("Start","Stop","Both")]
	[String]$ProcDumpOption,	#="Both" #we# removed, as it would not obey setting in config.cfg
	[String]$InputlogPath,
	[Parameter(ParameterSetName='Start')]
	[Int]$StopWaitTimeInSec,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Switch]$Crash,
	[Parameter(ParameterSetName='Start')]
	[String[]]$RemoteHosts,
	[Parameter(ParameterSetName='Start')]
	[String]$RemoteLogFolder,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[switch]$CollectDump,
	[Parameter(ParameterSetName='Start')]
	[Parameter(ParameterSetName='Stop')]
	[Parameter(ParameterSetName='CollectLog')]
	[String[]]$CollectEventLog,
	[Parameter(ParameterSetName='Start')]
	[Int]$MaxEvents

#endregion ### Control switches
)

#region --- Define Variables
	# Dated version of TSSv2 script
	$global:TssVerDate = "2022.07.21.1"	# Plz. update if releasing a new POD module version TssVerDate<POD>
#endregion --- Define Variables

$TraceSwitches = [Ordered]@{

# For_Developers:addNewSubScenario_switch_Step_2
# 'POD_ComponentName' = 'Enter description'

#region ----- ADS POD description -----
	'ADS_TEST' = 'ADS TEST'
	'ADS_Basic' = 'ADS Basic (CryptoDPAPI,CryptoPrimitives,EFS,KERB,NtLmCredSSP,KDC,SSL,WebAuth,SmartCard,CredprovAuthui,NGC,Bio,LSA) tracing'
	'ADS_Auth' = 'ADS Auth (CryptoDPAPI,KERB,NtLmCredSSP,SSL,WebAuth,SmartCard,CredprovAuthui,NGC,Bio,LSA) tracing'
	'ADS_AccountLockout' = 'ADS AccountLockout, KERB,NtLmCredSSP,KDC,SSL,LSA ETL log(s), Security EventLog'
	'ADS_ESR' = 'ADS ESR (WebAuthP,ShellRoaming,CDP,WinHTTP,SSL) tracing'
	'ADS_ADcore' = 'ADcore (Active Directory core) tracing'
	'ADS_ADsam' = 'ADsam (Active Directory SAM) tracing'
	'ADS_ADCS' = 'PKI Server / Certification Authority'
	'ADS_BadPwd' = 'BadPassword tracing'
	'ADS_Bio' = 'ADS_Bio'
	'ADS_CDP' = 'ADS CDP'
	'ADS_CEPCES' = 'ADS CEPCES'
	'ADS_CredprovAuthui' = 'ADS CredprovAuthui'
	'ADS_CryptoDPAPI' = 'ADS Crypto DPAPI'
	'ADS_CryptoPrimitives' = 'ADS Crypto Primitives'
	'ADS_DFSR' = 'DFS-R (replication) tracing'
	'ADS_EFS' = 'ADS EFS'
	'ADS_GPedit' = 'ADS_ GPedit (Group Policy Editor) tracing'
	'ADS_GPmgmt' = 'ADS_ GPmgmt (Group Policy Management) tracing'
	'ADS_GPO' = 'ADS GPO'
	'ADS_GPsvc' = 'ADS_ GPsvc (Group Policy Service) tracing'
	'ADS_GroupPolicy' = 'ADS_ Group Policy tracing'
	'ADS_IIS' = 'ADS IIS'
	'ADS_KDC' = 'ADS KDC'
	'ADS_Kerb' = 'ADS KERB'
	'ADS_LDAPsrv' = 'LDAP server NTDSA tracing'
	'ADS_LockOut' = 'Account LockOut tracing'
	'ADS_LSA' = 'ADS_LSA'
	'ADS_Netlogon' = 'Netlogon tracing'
	'ADS_NGC' = 'ADS NGC traces'
	'ADS_NTKernelLogger' = 'Kernel Logger'
	'ADS_NtLmCredSSP' = 'ADS NTLM CredSSP'
	'ADS_Perf' = 'Collect ADperf Data using script tss_ADPerfDataCollection.ps1'
	'ADS_PKICLIENT' = 'PKI Client / CertEnroll / EFS Scenario '
	'ADS_Profile' = 'ADS_ Profile tracing'
	'ADS_SAM' = 'ADS SAM'
	'ADS_ShellRoaming' = 'ADS ShellRoaming'
	'ADS_SmartCard' = 'ADS SmartCard'
	'ADS_SSL' = 'ADS SSL'
	'ADS_WebAuth' = 'ADS WebAuth'
	'ADS_WinHTTP' = 'ADS WinHTTP'
	'ADS_W32Time' = 'ADS Windows Time tracing'
#endregion ----- ADS POD description -----

#region ----- NET POD description -----
	'NET_TestMe' = 'NET TestMe tracing - for Testing purpose only'
	'NET_802Dot1x' = 'NET 802Dot1x tracing'
	'NET_AfdTcpFull' = 'Afd/TcpIp/NetIO full tracing'
	'NET_AfdTcpBasic' = 'Afd/TcpIp/NetIO basic tracing'
	'NET_AppLocker' = 'AppLocker tracing'
	'NET_AppV' = 'App-V (Application Virtualization) tracing = UEX_AppV'
	'NET_Auth' = 'NET AUTH tracing (ADS_Auth providers)'
	'NET_BFE' = 'BFE (Base Filtering Engine) tracing'
	'NET_BGP' = 'BGP (Boarder Gateway Protocol) tracing'
	'NET_BITS' = 'BITS (Background Intelligent Transfer Service) tracing'
	'NET_Bluetooth' = 'Bluetooth tracing'
	'NET_BranchCache' = 'BrancheCache tracing'
 	'NET_CAPI' = 'CAPI tracing'
	'NET_COM' = 'COM/DCOM/WinRT/PRC tracing. -EnableCOMDebug will enable further debug logging'
	'NET_Container' = 'ALL_ Docker/Container tracing; -Mode <Swarm|Kube>'
	'NET_CSC' = 'CSC (Client Side Caching) tracing (see NET_SMBcli)'
	'NET_DAcli' = 'Direct Access client tracing'
	'NET_DAmgmt' = 'Direct Access management tracing'
	'NET_DAsrv' = 'Direct Access server tracing'
	'NET_DCLocator' = 'ADS_ Domain Controller Locator tracing'
#	'NET_DFScli' = 'DFS-N client tracing (please use NET_SMBcli)'
	'NET_DFSsrv' = 'DFS-N server tracing'
	'NET_DHCPcli' = 'DHCP client tracing'
	'NET_DHCPsrv' = 'DHCP server tracing'
	'NET_DNScli' = 'DNS client tracing'
	'NET_DNSsrv' = 'DNS server tracing'
	'NET_Docker' = 'ALL_ Docker/Container tracing'
	'NET_EFS' = 'ALL_ EFS (Encrypted File System) tracing'
	'NET_Firewall' = 'Firewall tracing'
	'NET_FltMgr' = 'ALL_ Filter Manager tracing'
	'NET_FSRM' = 'FSRM (File Server Resource Manager) tracing'
	'NET_FWmgr' = 'Firewall manager tracing'
	'NET_HNS' = 'ALL_ HNS (Host Networking Service) tracing'
	'NET_HTTP' = 'WinINet/WinHTTP tracing'
	'NET_HttpSys' = 'WinInet/HttpSys tracing'
	'NET_HypHost' = 'NET_ Hyper-V Host tracing'
	'NET_HypVM' = 'NET_ Hyper-V VirtualMachine tracing'
	'NET_ICS' = 'Internet Connection Sharing tracing'
	'NET_IIS' = 'ALL_ Internet Information Server tracing'
	'NET_IPAM' = 'IPAM (IP Address Management) tracing'
	'NET_IPhlpSvc' = 'IPhelper Service tracing'
	'NET_IPsec' = 'IPsec tracing'
	'NET_iSCSI' = 'SHA_ iSCSI tracing'
	'NET_KernelIO' = 'ALL_ KernelIO tracing'
	'NET_LBFO' = 'LBFO (Load Balacing/Failover) tracing'
	'NET_LDAPcli' = 'LDAP client tracing; edit tss_config to specify LDAPcliProcess'
	'NET_MBAM' = 'MBAM (Microsoft BitLocker Administration and Monitoring) tracing'
	'NET_MBN' = 'Mobile Broadband MBN tracing'
#	'NET_MDM' = 'DeviceManagement tracing'
	'NET_MFAext' = 'ALL_ MFAext tracing'
	'NET_Miracast' = 'Miracast tracing'
	'NET_MUX' = 'ALL_ MUX tracing'
	'NET_NCA' = 'NCA (Network Connectivity Assistant) tracing'
	'NET_NCHA' = 'ALL_ NCHA (Network Controller) tracing'
	'NET_NCSI' = 'NCSI (Network Connectivity Status Indicator) tracing'
	'NET_NETIO' = 'NETIO tracing'
	'NET_NDIS' = 'NDIS (Network Driver Interface Specification) tracing'
	'NET_NDISwan' = 'NDISwan tracing'
	'NET_NetworkUX' = 'ALL_ NetworkUX tracing'
	'NET_Netlogon' = 'Netlogon tracing'
	'NET_Netsetup' = 'NetSetup tracing'
	'NET_NFC' = 'NFC (Near Field Communication) tracing'
	'NET_NFScli' = 'NFS client tracing'
	'NET_NFSsrv' = 'NFS server tracing'
	'NET_NLB' = 'NLB (Network Load Balancing) server tracing'
	'NET_NPS' = 'NPS (Network Policy Server) tracing'
	'NET_NTFS' = 'ALL_ NTFS tracing'
	'NET_OLE32' = 'OLE32 tracing'
	'NET_Outlook' = 'Outlook tracing'
	'NET_PCI' = 'collect NET PCI info'
	'NET_PerfLib' = 'PRF_ PerfLib tracing'
	'NET_PnP' = 'DND_ PnP (Plug and Play) tracing'
	'NET_PortProxy' = 'PortProxy tracing'
	'NET_PowerShell' = 'UEX_ PowerShell tracing'
	'NET_PrintSvc' = 'UEX_ Print Service tracing / from PrintTrace.cmd'
	'NET_Proxy' = 'Proxy tracing (AfdTcpBasic,NCSI,NDIS,WebIO,Winsock)'
	'NET_QoS' = 'QoS (Quality of Service) tracing'
	'NET_RadioManager' = 'RadioManager tracing'
	'NET_RAmgmt' = 'RemoteAccess management tracing'
	'NET_RAS' = 'RAS (Remote Access Server) tracing'
	'NET_RasMan' = 'RasMan (Remote Access Connection Manager) tracing'
	'NET_RDMA' = 'RDMA (Remote Direct Memory Access) tracing'
	'NET_RNDIS' = 'RNDIS (remote NDIS) tracing'
	'NET_RDScli' = 'RDS Remote Desktop Service Client (RdsCommon,RdsRDclientRdsRDclientMan,RdsWRKSPC) tracing'
	'NET_RDScommon' = 'RDS common (RDSH,RdsAuth,RdsAuthMan,RdsCore) tracing'
	'NET_RDSsrv' = 'RDS Remote Desktop Service Server (RdsCommon,RdsHMan,...) tracing'
	'NET_RdsAudio' = 'RDS Rd-RDAUDIO tracing'
	'NET_RdsAuth' = 'RDS Rd-AUTH tracing'
	'NET_RdsAuthMan' = 'RDS Rd-MAN-AUTH tracing'
	'NET_RdsBroker' = 'RDS Rd-RDS_Broker tracing'
	'NET_RdsCore' = 'RDS Rd-RDPCORE tracing'
	'NET_RdsH' = 'RDS Rd-RDSH tracing'
	'NET_RdsHMan' = 'RDS Rd-MAN-RDSH tracing'
	'NET_RdsPrintSpool' = 'RDS Rd-PRNTSPOOL tracing'
	'NET_RdsRAIL' = 'RDS Rd-RAIL tracing'
	'NET_RdsRDclient' = 'RDS Rd-RDCLIENT tracing'
	'NET_RdsRDclientMan' = 'RDS Rd-MAN-RDCLIENT tracing'
	'NET_RdsRDGW' = 'RDS Rd-RDGW tracing'
	'NET_RdsRDGWMan' = 'RDS Rd-MAN-RDGW tracing'
	'NET_RdsRDMS' = 'RDS Rd-RDMS tracing'
	'NET_RdsRDMSMan' = 'RDS Rd-MAN-RDMS tracing'
	'NET_RdsRDPCLIP' = 'RDS Rd-RDPCLIP tracing'
	'NET_RdsRDPDR' = 'RDS Rd-RDPDR tracing'
	'NET_RdsUsrLogon' = 'RDS Rd-USRLOGON tracing'
	'NET_RdsUsrLogonMan' = 'RDS Rd-MAN-USRLOGON tracing'
	'NET_RdsVIP' = 'RDS Rd-VIP tracing'
	'NET_RdsWRKSPC' = 'RDS Rd-WRKSPC tracing'
	'NET_RPC' = 'RPC (Remote Procedure Call) tracing'
	'NET_SBSL' = 'Slow Boot/Slow Logon tracing'
	'NET_SCCM' = 'ALL_ SCCM (System Center Configuration Manager) logging'
	'NET_SCM' = 'ALL_ SCM (Service Control Manager) tracing'
	'NET_SdnNC' = 'ALL_ SDN Network Controller tracing'
	'NET_SMB' = 'SMB client (SMBcli) and server (SMBsrv) component tracing'
	'NET_SMBcli' = 'SMB client component (dns,fr,fskm,fsum,rpcxdr,sec,tcp) tracing'
	'NET_SMBsrv' = 'SMB server component (srv,smbhash,sr,dfsn,SMBcluster) tracing'
	'NET_SMBcluster' = 'SMB server cluster component (csvfs,csvflt,csvvbus,csvnflt) tracing'
	'NET_fskm' = 'SMB fskm (File Service Kernel-Mode) tracing'
	'NET_fsum' = 'SMB fsum (File Service User-Mode) tracing'
	'NET_dns' = 'SMB dns tracing' 
	'NET_fr' = 'SMB fr (Folder Replication) tracing' 
	'NET_nbt' = 'SMB nbt (NetBIOS over TCP) tracing' 
	'NET_tcp' = 'SMB tcp tracing'
	'NET_DFSmgmt' = 'DFSmgmt (DFS management) console tracing'
	'NET_dfsn' = 'DFS-N (namespace) tracing'
	'NET_srv' = 'SMB server (srv,srv2,srvnet,witness) tracing'
	'NET_smbhash' = 'SMB smbhash tracing'
	'NET_sr' = 'SMB sr volume replication tracing'
	'NET_rpcxdr' = 'NFS rpcxdr tracing' 
	'NET_sec' = 'SMB security tracing'
	'NET_SNMP' = 'SNMP (Simple Network Management Protocol) tracing'
	'NET_SQLcheck' = 'SQL Connectivity Settings Check (SQLchck.exe)'
	'NET_TAPI' = 'TAPI (Telephony API) tracing' 
	'NET_TaskSch' = 'UEX_ TaskScheduler tracing'
	'NET_TLS' = 'TLS (Transport Layer Security) tracing'
	'NET_UNChard' = 'UNC hardening tracing'
	'NET_VMswitch' = 'VMswitch tracing'
	'NET_VPN' = 'VPN (Virtual Private Network) tracing'
	'NET_WCM' = 'WCM (Windows Connection Manager) tracing'
	'NET_WebClient' = 'WebClient with SMBcli tracing. To restart service use -Mode Restart'
	'NET_WebIO' = 'WebIO/Winhttp/WinInet tracing'
	'NET_WFP' = 'WFP (Windows Filtering Platform) tracing' 
	'NET_WinNAT' = 'WinNAT (Windows NAT) tracing'
	'NET_Winlogon' = 'ADS_ Winlogon tracing'
	'NET_Winsock' = 'Winsock tracing'
	'NET_WinRM' = 'Windows Remote Management tracing'
	'NET_WIP' = 'Windows Information Protection tracing'
	'NET_WmbClass' = 'WWAN MBN WmbClass tracing'
	'NET_WMI' = 'UEX_ WMI (Windows Management Instrumentation) tracing' 
	'NET_WNV' = 'ALL_ WNV (Windows Network Virtualization) tracing'
	'NET_WSman' = 'WSman tracing'
	'NET_WWAN' = 'WWAN (wireless wide area network) tracing'
	'NET_Workfolders' = 'Workfolders tracing'
#endregion ----- NET POD description -----

#region ----- DND POD description -----
	'DND_CodeIntegrity' = 'CodeIntegrity tracing'
	'DND_PNP' = 'PNP tracing'
	'DND_Servicing' = 'DND servicing logs (CBS, DISM, PNP, WU) + procmon'
	'DND_SETUP' = 'DND Setup log collection'
	'DND_SETUPreport' = 'DND Setup Report log collection'
	'DND_WinUpd' = 'DND_ collect Windows Update logs'
	'DND_WU' = 'DND WU (Windows Update) tracing'
	'DND_WUlogs' = 'DND Windows Update log collection'
#endregion ----- DND POD description -----

#region ----- PRF POD description -----
	'PRF_Perflib' = 'Perflib tracing'
	'PRF_RADAR' = 'RADAR tracing'
	'PRF_Sysmain' = 'Sysmain tracing'
#endregion ----- PRF POD description -----

#region ----- SHA POD description -----
	'SHA_ATAPort' = 'ATA(IDE) Port tracing'
	'SHA_CDROM' = 'CDROM, DVD, UDFS tracing'
	'SHA_CSVFS' = 'SHA CSVFS tracing'
	'SHA_CSVspace' = 'CSVspace tracing'
	'SHA_Dedup' = 'Deduplication tracing'
	'SHA_FailoverClustering' = 'SHA MS Failover clustering tracing'
	'SHA_FSRM' = 'FSRM tracing'
	'SHA_HyperV' = 'Hyper-V tracing'
	'SHA_HypHost' = 'SHA_ Hyper-V Host tracing'
	'SHA_HypVM' = 'SHA_ Hyper-V VirtualMachine tracing'
	'SHA_HypVmBus' = 'SHA_ Hyper-V VmBus tracing'
	'SHA_HypVmms' = 'SHA_ Hyper-V Vmms tracing'
	'SHA_HypVmWp' = 'SHA_ Hyper-V VmWp tracing'
	'SHA_ISCSI' = 'ISCSI tracing'
	'SHA_MPIO' = 'MPIO (Multipath I/O) tracing'
	'SHA_msDSM' = 'msDSM (Microsoft Device Specific Module) tracing'
	'SHA_MsCluster' = 'SHA MS Failover clustering tracing'
	'SHA_NFS' = 'NFS tracing'
	'SHA_ReFS' = 'ReFS FileSystem tracing'
	'SHA_SDDC' = 'collect HA/Cluster PrivateCloud.DiagnosticInfo infos'
	'SHA_ShieldedVM' = 'SHA_ ShieldedVM tracing'
	'SHA_SMS' = 'Storage Migration Service Helper per GetSmsLogs.psm1, run it against both the Orchestrator node and the transfer destination node'
	'SHA_Storage' = 'aka SAN shotgun tracing'
	'SHA_StorageReplica' = 'Storage replica tracing'
	'SHA_StorageSpace' = 'Storage space tracing'
	'SHA_Storport' = 'Storport tracing'
	'SHA_Storsvc' = 'Storsvc tracing'
	'SHA_USB' = 'USB tracing'
	'SHA_VDS' = 'Virtual Disk Service tracing'
	'SHA_VHDMP' = 'Virtual disk and VHDMP driver tracing'
	'SHA_VmConfig' = 'SHA_ Virtual Machine Config tracing'
	'SHA_VML' = 'SHA_ Virtual Machine LiveMigration tracing; use -Mode verbose to restart the Hyper-V service and get FRUTI log'
	'SHA_VMM' = 'SHA_ VMM (Virtual Machine Manager) tracing'
	'SHA_VSS' = 'VSS tracing'
	'SHA_WSB' = 'Windows Server Backup tracing'
#endregion ----- SHA POD description -----

#region ----- UEX POD description -----
	'UEX_Alarm' = 'Alarm app tracing'
	'UEX_AppCompat' = 'AppCompat and UAC tracing'
	'UEX_AppID' = 'AppID tracing'
	'UEX_AppV' = 'App-V tracing'
	'UEX_AppX' = 'AppX tracing'
	'UEX_Auth' = 'Authentication tracing'
	'UEX_Calc' = 'Calculator app tracing'
	'UEX_Camera' = 'Camera tracing'
	'UEX_CldFlt' = 'cldflt tracing(driver for clould file)'
	'UEX_ClipBoard' = 'Clip board tracing'
	'UEX_CloudSync' = 'CloudSync tracing'
	'UEX_COM' = 'COM/DCOM/WinRT/PRC tracing. -EnableCOMDebug will enable further debug logging'
	'UEX_ContactSupport' = 'ContactSupport app tracing'
	'UEX_Cortana' = 'Cortana tracing'
	'UEX_CRYPT' = 'Crypt tracing'
	'UEX_DeviceStore' = 'Device Store tracing'
	'UEX_DM' = 'Device Management(InstallService/EnterpriseManagement/CSP) tracing'
	'UEX_DSC' = 'Collect DSC Data using script DSC-Collect.ps1'
	'UEX_DWM' = 'DWM(Desktop Window Manager) tracing'
	'UEX_ESENT' = 'ESENT tracing'
	'UEX_EventLog' = 'EventLog tracing'
	'UEX_EVT' = 'Collect EventLog Data using script Evt-Collect.ps1'
	'UEX_Font' = 'Font tracing'
	'UEX_FSLogix' = 'FSLogix tracing'
	'UEX_IME' = 'IME and input tracing'
	'UEX_ImmersiveUI' = 'ImmersiveUI tracing'
	'UEX_LicenseManager' = 'License manager tracing'
	'UEX_Logon' = 'Winlogon/LogonUI/Credential provider/LockApp/AssignedAccess tracing'
	'UEX_LSA' = 'Lsass tracing'
	'UEX_Media' = 'Media Player tracing'
	'UEX_MMC' = 'MMC tracing'
	'UEX_MSRA' = 'Remote Assistance tracing'
	'UEX_Nls' = 'NLS tracing (only CollectLog)'
	'UEX_Photo' = 'Photo app tracing'
	'UEX_Print' = 'Print tracing'
	'UEX_PrintEx' = 'Collect Print tracing using script Print-Collect.ps1'
	'UEX_QuickAssist' = 'QuickAssist app tracing'
	'UEX_RDS' = 'RDS tracing'
	'UEX_RDWebRTC' = 'RD Web RTC tracing'
	'UEX_RestartManager' = 'Restart Manager tracing'
	'UEX_Sched' = 'Task Scheduler'
	'UEX_TSched' = 'Collect Task Scheduler Data using script Sched-Collect.ps1'
	'UEX_SCM' = 'SCM tracing'
	'UEX_Search' = 'Windows search and search client(tquery.dll) tracing'
	'UEX_ServerManager' = 'Server manager(ServerManager.exe) tracing'
	'UEX_Shell' = 'Shell tracing'
	'UEX_Shutdown' = 'Shutdown tracing'
	'UEX_Speech' = 'Speech app tracing'
	'UEX_StartMenu' = 'StartMenu(ShellExperienctHost/StartMenuExperienctHost) tracing'
	'UEX_Store' = 'Store app tracing'
	'UEX_SystemSettings' = 'SystemSettings tracing'
	'UEX_Task' = 'Task schedure/UBPM tracing'
	'UEX_UEV' = 'UE-V tracing'
	'UEX_UserDataAccess' = 'UserDataAccess tracing'
	'UEX_VAN' = 'View Available Network tracing'
	'UEX_WER' = 'Windows Error Reporting tracing'
	'UEX_Win32k' = 'Win32k tracing'
	'UEX_WinRM' = 'WinRM tracing'
	'UEX_WMI' = 'WMI(winmgmt) tracing. This does not contain WMI provider trace.'
	'UEX_WMIBridge' = 'WMI Bridge provider(DMWmiBridgeProv) tracing'
	'UEX_WPN' = 'WPN(Windows Platform Notification) tracing'
	'UEX_WSC' = 'Windows Security Center tracing'
	'UEX_WVD' = 'Windows Virtual Desktop tracing'
	'UEX_XAML' = 'XAML and dcomp tracing'
#endregion ----- UEX POD description -----

#region ----- DEV POD description -----
	'DEV_TEST1' = 'DEV TEST1 component tracing'
	'DEV_TEST2' = 'DEV TEST2 component tracing'
	'DEV_TEST3' = 'DEV TEST3 component tracing'
	'DEV_TEST3Full' = 'DEV TEST3Full component tracing'
	'DEV_TEST4' = 'DEV TEST4 component tracing'
	'DEV_TEST5' = 'DEV TEST5 component tracing'
#endregion ----- DEV POD description -----

#region ----- CustomETL description -----
	'WIN_CustomETL' = 'user provided component tracing'
#endregion ----- CustomETL description -----
}

# This is used only for help message
$CommandSwitches = @{
	'Fiddler' = 'Collect Fiddler trace; requires Fiddler to be installed'
	'GPresult' = 'Run GPresult and collect auditing and security info'
	'Handle' = 'Collect SysInternals Handle output using Handle.exe'
	'LiveKD' = 'Capture SysInternals live kernel dump'
	'Netsh' = 'Netsh (Packet capture)'
	'NetshScenario' = 'Netsh client scenario trace + Packet capture'
	'PerfMon' = 'Performance Monitor with short interval'
	'PerfMonLong' = 'Performance Monitor with long interval'
	'PktMon' = 'PktMon (Packet Monitor) for RS5+'
	'PoolMon' = 'Collect pool memory usage using PoolMon.exe'
	'ProcDump' = 'Capture SysInternals user dump'
	'ProcMon' = 'Process Monitor (SysInternals Procmon.exe)'
	'PSR' = 'Problem Steps Recorder'
	'RASdiag' = 'Netsh (RAS)'
	'SDP' = 'Collect speciality Support Diagnostic Platform data'
	'SysMon' = 'System Monitor (SysInternals SysMon.exe)'
	'TTD' = 'Collect TTD (TTT/iDNA); note: TTSSv2_TTD.zip is only needed for downlevel OS prior to Win10/Server 2019'
	'Video' = 'Capture Video, use VLC Media Player for viewing; be sure that your Display settings uses a standard Display resolution'
	'WFPdiag' = 'Netsh (wfp)'
	'WPR' = 'Windows Performance Recoder (wpr.exe)'
	'WireShark' = 'WireShark (Packet capture), requires WireShark to be installed'
	'Xperf' = 'Alternate command-line tool for WPR (Windows Performance Recoder)'
	'Xray' = 'Run xray Diagnostics to scan for known issues'
}

# Type 2 Command list (Commands that take arg with "Start|Stop|Both")
$Type2CommandSwitches = @{
	'GPresult' = 'Run gpresult and collect auditing and security info'
	'Handle' = 'Collect handle info using sysinternals Handle.exe'
	'LiveKD' = 'Capture live kernel dump'
	'PoolMon' = 'Collect pool memory usage using PoolMon.exe'
}

# This list is used for LiteMode
$ExternalCommandList = @{
	'Crash' = 'NotMyfault64.exe'
	'ExecAction' = 'ExecAction.exe' #Fiddler
	'Handle' = 'Handle.exe'
	'LiveKD' = 'LiveKD.exe'
#	'PktMon' = 'PktMon.exe'
	'PoolMon' = 'PoolMon.exe'
	'ProcDump' = 'ProcDump.exe'
	'ProcMon' = 'Procmon.exe'
	'SysMon' = 'SysMon.exe'
	'TTD' = 'TTTracer.exe'
	'Video' = 'RecorderCommandLine.exe'
	'WireShark' = "$env:ProgramFiles\Wireshark\dumpcap.exe"
	'Xperf' = 'Xperf.exe'
}

# This is used only for help message
$SDPspecialties = @{
	'Apps' = 'Inbox-Apps-Diagnostic Report'
	'Net' = 'Network Report'
	'DA' = 'Direct Access Report'
	'Dom' = 'Domains/Active Directory Report'
	'DPM' = 'Data Protection Manager (DPM) Report'
	'CTS' = 'CTS Report'
	'Print' = 'Printing Report'
	'HyperV' = 'Hyper-V Report'
	'Setup' = 'Setup Report'
	'Perf' = 'Performance Report'
	'Cluster' = 'Windows Failover Cluster Diagnostic Report'
	'S2D' = 'S2D Report'
	'SCCM' = 'SCCM Report'
	'RDS' = 'Remote Desktop Services'
	'Remote' = 'Remote'
	'SQLbase' = 'SQL Basic Report'
	'SQLconn' = 'SQL Connectivity Report'
	'SQLmsdtc' = 'SQL msdtc Report'
	'SQLsetup' = 'SQL setup Report'
	'SUVP' = 'SUVP Report'
	'VSS' = 'VSS Report'
	'mini' = 'minimal SDP'
	'nano' = 'nano SDP'
	'Repro' = 'Repro (for testing)'
	'RFL' = 'Recommended Fix List (RFL)'
	'All' = 'All Technologies Report'
}
# This is used only for help message
$WPRprofiles = @{
	'BootGeneral' = 'all generic events (only GeneralProfile), may be used with -StartAutologger, you can add profiles as necessary with -WPROptions.'
	'CPU' = 'events on CPU usage (GeneralProfile+CPU)'
	'General' = 'all generic events (GeneralProfile, CPU usage, context switches for wait analysis, file and registry I/O, Network)'
	'Graphic' = 'events related to graphic (GeneralProfile+CPU+Registry+Video+GPU+DesktopComposition+Power)'
	'Memory' = 'events on memory allocation (GeneralProfile+VirtualAllocation)'
	'Network' = 'events on networking (GeneralProfile+CPU+DiskIO+FileIO+Network+Minifilter)'
	'Registry' = 'events on registry I/O such as registry access, creation and deletion (GeneralProfile+CPU+Registry)'
	'SQL' = 'events on memory allocation and networking (GeneralProfile+CPU+VirtualAllocation+Network+Minifilter)'
	'Storage' = 'events on Disk I/O (GeneralProfile+CPU+DiskIO+FileIO+Network+Minifilter)'
	'Wait' = 'events on CPU usage and context switch (GeneralProfile+CPU+DiskIO+FileIO+Network+Minifilter)'
	'Xaml' = 'events related to Xaml (GeneralProfile+CPU+XAMLActivity+XAMLAppResponsiveness+DesktopComposition+Video+GPU)'
}

# This is used only for help message
$XperfProfiles = @{
	'CPU' = "-on PROC_THREAD+Latency+LOADER+Profile+interrupt+dpc+DISPATCHER+CSwitch+Power -stackWalk CSwitch+Profile+ReadyThread <Params>"
	'Disk' = "-on PROC_THREAD+LOADER+Profile+interrupt+dpc+DISK_IO+DISK_IO_INIT+filename+FILE_IO+FILE_IO_INIT+flt_io_init+flt_io+flt_fastio+flt_io_failure -stackwalk profile+DiskReadInit+DiskWriteInit+DiskFlushInit+FileRead+FileWrite+FileCreate+FileDelete+minifilterpreopinit+minifilterpostopinit <Params>"
	'General' = "-on Base+Latency+CSwitch+PROC_THREAD+LOADER+Profile+interrupt+dpc+DISPATCHER+NETWORKTRACE+FileIO+Power+DISK_IO+DISK_IO_INIT+filename+FILE_IO+FILE_IO_INIT+flt_io_init+flt_io+flt_fastio+flt_io_failure+VIRT_ALLOC+POOL+REGISTRY+DRIVERS -stackWalk CSwitch+Profile+ReadyThread+ThreadCreate+SyscallEnter+DiskReadInit+DiskWriteInit+DiskFlushInit+FileRead+FileWrite+FileCreate+FileDelete+minifilterpreopinit+minifilterpostopinit+PoolAlloc+PoolAllocSession+PoolFree+PoolFreeSession+VirtualAlloc+VirtualFree <Params>"
	'Leak' = "-on PROC_THREAD+LOADER+VIRT_ALLOC -stackwalk VirtualAlloc+VirtualFree <Params> -start HeapSession -heap -pids <PID> -stackwalk HeapAlloc+HeapRealloc"
	'Memory' = "-on Base+CSwitch+POOL -stackwalk Profile+PoolAlloc+PoolAllocSession+PoolFree+PoolFreeSession+VirtualAlloc <Params>"
	'Network' = "-on Base+Latency+DISPATCHER+NETWORKTRACE+FileIO+DRIVERS -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile+SyscallEnter <Params>"
	'Pool' = "-on Base+CSwitch+VIRT_ALLOC+POOL -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession+VirtualAlloc -PoolTag <PoolTag> <Params>"
	'PoolNPP' = "-on Base+CSwitch+LOADER+VIRT_ALLOC+POOL+PROC_THREAD -stackwalk PoolAlloc+PoolFree+PoolAllocSession+PoolFreeSession+VirtualAlloc -PoolTag <PoolTag> <Params>"
	'Registry' = "-on Base+REGISTRY+PROC_THREAD+NETWORKTRACE -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile+SyscallEnter <Params>"
	'SBSL' = "-on Base+Latency+DISPATCHER+REGISTRY+NETWORKTRACE+FileIO -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile -BufferSize 1024 -start UserTrace -on `"Microsoft-Windows-Shell-Core+Microsoft-Windows-Wininit+Microsoft-Windows-Folder Redirection+Microsoft-Windows-User Profiles Service+Microsoft-Windows-GroupPolicy+Microsoft-Windows-Winlogon+Microsoft-Windows-Security-Kerberos+Microsoft-Windows-User Profiles General+e5ba83f6-07d0-46b1-8bc7-7e669a1d31dc+63b530f8-29c9-4880-a5b4-b8179096e7b8+2f07e2ee-15db-40f1-90ef-9d7ba282188a`" <Params>"
	'SBSLboot' = "-on Base+Latency+DISPATCHER+REGISTRY+NETWORKTRACE+FileIO -stackWalk CSwitch+ReadyThread+ThreadCreate+Profile <Params>"
	'SMB2' = "-on Base+Latency+DISPATCHER+NETWORKTRACE+FILE_IO+FILE_IO_INIT+DRIVERS <Params> -stackwalk Profile+CSwitch+ReadyThread -start SMB2 -on d3bce2d2-92c9-44c7-befe-a27a96d413e9:::'stack'"
}

$NoOPTIONS = @{
	'noAdminChk' = 'skip Admin check, which verifies elevated Admin rights'
	'noAsk' = 'do not ask about good/failing scenario text input before compressing data'
	'noBasiclog' = 'do not collect mini basic log that is collected by default'
	'noClearCache' = 'do not clear DNS,NetBios,Kerberos,DFS chaches at start'
	'noCrash' = 'do not run Crash after reboot again when using TSSv2 -stop -noCrash'
	'noEventConvert' = 'do not convert Eventlogs to .CSV or .TXT format'
	'noGPresult' = 'do not run GPresult, used to override setting in preconfigured TS scenarios'
	'noFiddler' = 'do not start Fiddler'
	'noHandle' = 'do not run Handle at start,stop or both'
	'noHang' = 'do not wait forever when data collection seems to hang '
	'noLiveKD' = 'do not capture LiveKD (live kernel dump)'
	'noNetsh' = 'do not run NetSsh, which might be preset in some TS scenarios'
	'NoPacket' = 'prevent packets from being captured, only ETW traces in the ScenarioName will be captured'
	'noPerfMon' = 'do not run PerfMon, which might be preset in some TS scenarios'
	'noPktMon' = 'do not start PktMon'
	'noPoolMon' = 'do not run PoolMon at start and stop'
	'noPrereqC' = 'do not run prerequisite check'
	'noProcmon' = 'do not run Procmon, the Procmon is an UI tool. Therefore this option is helpful if you want to prevent UI tool from showing up like a case on server core'
	'noPSR' = 'do not run PSR, like same as -noProcmon and -noVideo, this is helpful for the scenario where you dont want to show any UI tools'
	'noRASdiag' = 'do not start RASdiag'
	'noRecording' = 'do not ask about consent for performing PSR or Video recording, and do not start these recordings'
	'noRestart' = 'do not restart associated Windows service'
	'noSDP' = 'do not gather SDP report, i.e. when using script in scheduled tasks'
#	'noSettingList <comma separated no switches>'  = ' : specify multiple no switches'
	'noSound' = 'do not play attention sound'
	'noSysMon' = 'do not start SysMon'
	'noTTD' = 'do not start TTD'
	'noUpdate' = 'do not check online for latest TSS version on Github, no AutoUpdate'
	'noVersionChk' = 'skip script Version check'
	'noVideo' = 'do not run Video, like same as -noProcmon and -noPSR, this is helpful for the scenario where you dont want to show any UI tools'
	'noWFPdiag' = 'do not start WFPdiag'
	'noWireShark' = 'do not start WireShark'
	'noWPR' = 'do not run WPR, which might be preset in some TS scenarios'
	'noXperf' = 'do not run Xperf, which might be preset in some TS scenarios'
	'noXray' = 'do not start Xray troubleshooter'
	'noZip' = 'do not compress/zip trace data'
}
# Create global variables for noSwitches
$noSwitchList = ($NoOPTIONS.Keys | sort)

$ControlSwitches = @(
	'AcceptEula'
	'AddDescription'
	'Assist'
	'BasicLog'
	'beta'
	'CollectLog'
	'CollectComponentLog'
	'CommonTask'
	'Compress'
	'Crash'
	'CreateBatFile'
	'CollectDump'
	'CollectEventLog'
	'CustomETL'
	'CustomParams'
	'Delete'
	'DebugMode'
	'Discard'
	'EnableCOMDebug'
	'EtlOptions'
	'EvtDaysBack'
	'ExternalScript'
	'Help'
	'InputlogPath'
	'List'
	'ListSupportedCommands'
	'ListSupportedDiag'
	'ListSupportedLog'
	'ListSupportedNetshScenario'
	'ListSupportedNoOptions'
	'ListSupportedPerfCounter'
	'ListSupportedScenarioTrace'
	'ListSupportedSDP'
	'ListSupportedWPRScenario'
	'ListSupportedXperfProfile'
	'LogFolderName'
	'MaxEvents'
	'Mini'
	'Mode'
	'NetshOptions'
	'NetshMaxSize'
	'NewSession'
	'PerfIntervalSec'
	'PerfLongIntervalMin'
	'ProcDumpOption'
	'ProcDumpInterval'
	'ProcmonPath'
	'ProcmonFilter'
	'Remote'
	'RemoteHosts'
	'RemoteLogFolder'
	'RemoveAutoLogger'
	'Scenario'
	'SDP'
	'Set'
	'Unset'
	'SkipPdbGen'
	'SkipSDPList'
	'StartAutoLogger'
	'Start'
	'StartDiag'
	'StartNoWait'
	'Status'
	'Stop'
	'StopWaitTimeInSec'
	'TTDMode'
	'TTDMaxFile'
	'TTDOptions'
	'TTDPath'
	'Version'
	'WaitEvent'
	'WPROptions'
	'XperfMaxFile'
	'XperfOptions'
	'XperfPIDs'
	'XperfTag'
	'Xray'
)
$ControlSwitches += $noSwitchList

# Log size definition for commands(Not ETW)
# Some of data will be updated in CalculateLogSize().
$LogSizeInGB = @{
	'Fiddler' = 2
	'Perf' = 1
	'Procmon' = 5
	'Video' = 1
	'PSR' = 0
	'Netsh' = $NetshLogSize / 1024
	'NetshScenario' = ($NetshLogSize / 1024) + 4
	'WFPdiag' = 16   # 16 traces x 1GB
	'RASdiag' = 14   # 14 traces x 1GB
	'PktMon' = 2
	'SysMon' = 1
	'WPR' = 10
	'Xperf' = 10
	'TTD' = 5
	'LiveKD' = 3
	'ProcDump' = 1
	'WireShark' = 2
}

$ETWSessionCountForCommand = @{
	'Netsh' = '2'			# NetTrace-XXX-XXX x 1, NetCfgTrace x 1
	'NetshScenario' = '2'	# NetTrace-XXX-XXX x 1, NetCfgTrace x 1
	'RASdiag' = '14'		# RASdiag spawns 14 ETW sessions
	'WFPdiag' = '1'			# wfpdiag x 1
	'PktMon' = '1'			# PktMon x 1
	'ProcMon' = '1'			# PROCMON TRACE x 1
	'WPR' = '1'				# WPR_initiated_WprApp_WPR System Collector x 1, WPR_initiated_WprApp_WPR Event Collector x 1
	'xPerf' = '1'			# NT Kernel Logger x 1
}

$StartPriority = @{
	'LiveKD' = 1
	'Video' = 1
	'PSR' = 1
	'GPresult' = 2
	'Handle' = 2
	'PoolMon' = 2
	'ProcDump' = 2
	'SysMon' = 2
	'ETW' = 5
	'Perf' = 6
	'WPR' = 6
	'Xperf' = 6
	'RASdiag' = 6
	'WireShark' = 6
	'Fiddler' = 6
	'Netsh' = 7
	'PktMon' = 7
	'WFPdiag' = 8
	'Procmon' = 8
	'TTD' = 10
}

$StopPriority = @{
	'TTD' = 1
	'Procmon' = 3
	'WFPdiag' = 3
	'Netsh' = 4
	'WireShark' = 4
	'PktMon' = 4
	'Fiddler' = 4
	'RASdiag' = 5
	'WPR' = 5
	'Xperf' = 5
	'Perf' = 5
	'ETW' = 6
	'SysMon' = 9
	'ProcDump' = 9
	'GPresult' = 9
	'Handle' = 9
	'PoolMon' = 9
	'PSR' = 10
	'Video' = 10
	'LiveKD' = 10
}

# Used for -Set and -Unset
$SupportedSetOptions = [Ordered]@{
	'WER' = 'Enable WER (Windows Error Reporting) setting'
}

$LogTypes = @(
	'ETW'
	'Command'
	'Perf'
	'Custom'
)

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
		If($CallerInfo.ScriptName -notlike "*$global:ScriptName"){ # ScriptName = 'TSSv2.ps1'
			$FuncName = (((Split-path $CallerInfo.ScriptName -leaf) -replace "TSSv2_","") + ":" + $FuncName)
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

Function global:FwResolveDesktopPath{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name

	$DesktopPath = [Environment]::GetFolderPath('Desktop')
	# What we are doing here is that when the script is run from non administrative user 
	# and PowerShell prompt is launched with 'Run as Administrator', profile path of the administrator
	# is obtained. But desktop path used for log path must be under current user's desktop path.
	# So we will check explorer's owner user to know the actual user name and build log folder path using it.
	$CurrentSessionID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
	$Explorer = Get-Process -name 'Explorer' -ErrorAction Ignore | Where-Object {$_.SessionId -eq $CurrentSessionID}
	If($Explorer -eq $Null){
		LogWarn "Unable to find explorer.exe. Returning with $DesktopPath"
		return $DesktopPath
	}
	$EnvVariables = $Explorer[0].startinfo.environmentvariables
	$Owner = ($EnvVariables | Where-Object {$_.NAME -eq 'USERNAME'}).Value
	$LogonUser = ($EnvVariables | Where-Object {$_.NAME -eq 'USERDOMAIN'}).Value

	# This is case where the shell is not explorer.exe. In this case, simply use path obtained by GetFolderPath('Desktop')
	If($Owner -eq $Null){
		LogWarn "Unable to retrieve logon user info. Use `'$DesktopPath`' for desktop path."
		return $DesktopPath
	}

	# There are two possible desktop paths
	$DesktopCandidate = "C:\users\$LogonUser\Desktop"
	$DesktopCandidate2 = "C:\users\$LogonUser.$UserDomain\Desktop"

	If(Test-Path -Path $DesktopCandidate2){ # like C:\Users\ryhayash.FAREAST\desktop
		$DesktopPath = "$DesktopCandidate2"
	}ElseIf(Test-Path -Path $DesktopCandidate){ 
		$DesktopPath = "$DesktopCandidate"
	}Else{ # This is folder redirection scenario
		$DesktopPath = "C:\temp\MSLOG"
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($DesktopPath)")
	return $DesktopPath
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
			# Issue#373 - Tssv2 hang in ISE
			$Answer = FwRead-Host-YN -Message "Do you want to re-run TSSv2 from elevated PowerShell? (timeout=10s)" -Choices 'yn' -TimeOut 10
			#CHOICE /T 10 /C yn /D y /M " Do you want to re-run TSSv2 from elevated PowerShell?"
			If(!$Answer){
				LogInfoFile "=== User declined to run TSSv2 from elevated PowerShell ==="
				LogInfo "Run script from elevated command or PowerShell prompt" "Red"
				CleanUpandExit
			}
		}
		$cmdline = $Script:TSSv2Commandline.Replace($MyInvocation.InvocationName,$MyInvocation.MyCommand.Path)
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
		$tmpMsg = $tmpMsg -replace "cmd /r ", ""
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
	 FwNew-TemporaryFolder -RelativeFolder "C:\MS_DATA"
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
		#LogInfo ".. creating log folder $LogFolder" "Gray" # LogInfoFile would fail as $LogFolder does not exist
		New-Item $LogFolder -ItemType Directory -ErrorAction Stop | Out-Null
		LogDebug ".. created log folder $LogFolder" "Gray"
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

	.EXAMPLE
	Case 1: Copy a single set of files
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths.add(@("C:\Temp\*", "$LogFolderforDEV_TEST1"))
	FwCopyFiles $SourceDestinationPaths

	Case 2: Copy a single file
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths.add(@("C:\temp\test-case2.txt", "$LogFolderforDEV_TEST1"))
	FwCopyFiles $SourceDestinationPaths

	# Case 3: Copy multi sets of files
	$SourceDestinationPaths = New-Object 'System.Collections.Generic.List[Object]'
	$SourceDestinationPaths = @(
		@("C:\temp\*", "$LogFolderforDEV_TEST1"),
		@("C:\temp2\test-case3.txt", "$LogFolderforDEV_TEST1")
	)
	FwCopyFiles $SourceDestinationPaths

	.NOTES
		Date:   01.09.2021
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
	try {logman query -ets | Out-File -Append $outFile -Encoding ascii -Width 200; $TotProvCnt=$($(logman query -ets).count -5); "`nTotal # of Sessions: " + $TotProvCnt| Out-File -Append $outFile -Encoding ascii; if ($TotProvCnt -gt 55) {write-host -ForegroundColor red "[ERROR]: This data collection exceeds 55 ETL Trace Sessions, stop unnecessary ones.`nTo do so, stop current TSSv2, run 'Logman Query -ets', then: Logman stop -ets -n 'name of unrelated ETL session', then restart TSSv2"} } 
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
		} else { LogInfo "[$($MyInvocation.MyCommand.Name)] ProductType: $global:ProductType - skip NET USER on BDC or PDC" "Gray" }
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

Function global:FwExportRegKey{
	<#
	.SYNOPSIS
		Exports registry key in TXT or REG formats
	.DESCRIPTION
		global:FwExportRegKey expects 3 parameters: $RegistryKey, $ExportFile, and $ExportFormat
	.EXAMPLE
		to export key and its subkey "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" in "C:\reg exportTXT.txt" using "TXT" format call:
		global:FwExportRegKey "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" "C:\Dev\reg exportTXT.txt" "TXT"
	.EXAMPLE
		to export key and its subkey "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" in "C:\reg exportREG.reg" using "REG" format call:
		global:FwExportRegKey "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" "C:\Dev\reg exportREG.reg" "REG"
	.NOTES
		Date:   01.04.2021
	#>
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryKey,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ExportFile,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$ExportFormat
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If($ExportFormat -like "TXT"){
			$CommandLine = "reg query `"$RegistryKey`" /s > `"$ExportFile`" 2>&1 | Out-Null"
		}
	elseif($ExportFormat -like "REG"){
			$CommandLine = "reg export `"$RegistryKey`" `"$ExportFile`" /y 2>&1 | Out-Null"
		}
	else {
		LogException ("Not support export format $ExportFormant") $_ $fLogFileOnly
		return
		}
	
	LogDebug ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
	}
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
		   LogInfo "[$($MyInvocation.MyCommand.Name)] `'$ExportKey`' does not exist."
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


Function global:FwAddRegValue{
	<#
	.SYNOPSIS
		Adds new reg value to the registry key
	.DESCRIPTION
		global:FwAddRegValue expects 4 parameters: $RegistryKey, $RegistryValue, $RegistryValueType (https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types) and $RegistryValueData
	.EXAMPLE
		to create new "my test" REG_DWORD value 0x1 in "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" call:
		global:FwAddRegValue "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" "my test" "REG_DWORD" "0x1"
	.NOTES
		Date:   01.04.2021
	#>
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryKey,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryValue,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryValueType,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryValueData,
		[parameter(Mandatory=$false)]
		[Bool]$BootRequired = $False
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$CommandLine = "REG add `"$RegistryKey`" /v `"$RegistryValue`" /t $RegistryValueType /d $RegistryValueData /f 2>&1 | Out-Null"
	LogInfoFile ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
		if ($BootRequired -eq $true) { LogWarn "This key $RegistryKey will require a reboot once for proper data collection!" "Cyan" }
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwDeleteRegValue{
	<#
	.SYNOPSIS
		Deletes reg value from the registry key
	.DESCRIPTION
		global:FwDeleteRegValue expects 2 parameters: $RegistryKey and $RegistryValue
	.EXAMPLE
		to delete value "my test" from "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" call:
		global:FwDeleteRegValue "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\My Key" "my test"
	.NOTES
		Date:   01.04.2021
	#>
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryKey,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegistryValue
	)
	EnterFunc $MyInvocation.MyCommand.Name
   
	$CommandLine = "REG delete `"$RegistryKey`" /v `"$RegistryValue`" /f 2>&1 | Out-Null"
	LogInfoFile ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
	}
	EndFunc $MyInvocation.MyCommand.Name
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

<# obsolete
Function global:FwFwExportRegToOneFile{ 

	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogPrefix,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Array]$RegistryKeys,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogFile
	)

	ForEach($RegistryKey in $RegistryKeys){
		If(!(Test-Path -Path $RegistryKey)){
			LogWarnFile ("$RegistryKey does not exist.")
			Continue
		}
		LogInfo ("[$LogPrefix] Exporting $RegistryKey")
		Try{
			$Key = Get-Item $RegistryKey -ErrorAction Stop
		}Catch{
			LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
			Continue
		}
	   
		Write-Output("[" + $Key.Name + "]") | Out-File -Append $LogFile
		ForEach($Property in $Key.Property){
			Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
		}

		Try{
			$ChildKeys = Get-ChildItem $RegistryKey -Recurse -ErrorAction Stop
		}Catch{
			LogException ("Error: An exception happens in Get-ChildItem $RegistryKey.") $_ $fLogFileOnly
			Return # This is critical and return.
		}

		ForEach($ChildKey in $ChildKeys){
			Write-Output("[" + $ChildKey.Name + "]") | Out-File -Append $LogFile
			Try{
				$Key = Get-Item $ChildKey.PSPath -ErrorAction Stop
			}Catch{
				LogException ("Error: An exception happens in Get-Item $RegistryKey.") $_ $fLogFileOnly
				Continue
			}
			ForEach($Property in $Key.Property){
				Try{
					Write-Output($Property + "=" + $Key.GetValue($Property)) | Out-File -Append $LogFile
				}Catch{
					LogException ("Error: An exception happens in Write-Output $Key.") $_ $fLogFileOnly
				}
			}
		}
	}
}
#>

Function global:FwEventLogsSet{
	<#
	.SYNOPSIS
		Set Event Log parameters for a single Event Log
	.DESCRIPTION
		FwEventLogsSet expects 5 parameters: $LogName, $Enabled (true or false), $retention (true or false), $quiet (true or false) and $MaxSize in Bytes (e.g. 102400000 is 100 MB)
	.EXAMPLE
		to execute this command: wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:true /rt:false /q:true /ms:102400000
		you need to call: FwEventLogsSet "Microsoft-Windows-CAPI2/Operational" true false true 102400000
	.EXAMPLE 
		to execute this command: wevtutil.exe set-log "Microsoft-Windows-CAPI2/Operational" /enabled:false
		you need to call: FwEventLogsSet Microsoft-Windows-Kerberos/Operational", "true", "", "", ""

	.NOTES
		Date:   01.04.2021
	#>
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogName,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$Enabled,  # true or false
		[parameter(Mandatory=$false)]
		[String]$retention,  # true or false
		[parameter(Mandatory=$false)]
		[String]$quiet,  # true or false
		[parameter(Mandatory=$false)]
		[String]$MaxSize   # in Bytes, e.g. 102400000 is 100 MB
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$rt = ""
	$q = ""
	$ms = ""

	If(!([string]::IsNullOrEmpty($retention))){
		$rt= " /rt:$retention"
	}

	If(!([string]::IsNullOrEmpty($quiet))){
		$q= " /q:$quiet"
	}

	If(!([string]::IsNullOrEmpty($MaxSize))){
		$ms = " /ms:$MaxSize"
	}

	$CommandLine = "wevtutil set-log $LogName /enabled:$Enabled$rt$q$ms 2>&1 | Out-Null"
	LogDebug ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwEventLogClear{
	<#
	.SYNOPSIS
		Clears single Event Log
	.DESCRIPTION
		global:FwEventLogClear expects 1 parameter: $LogName
	.EXAMPLE
		to execute this command: wevtutil.exe clear-log "Microsoft-Windows-CAPI2/Operational"
		you need to call: global:FwEventLogsClear "Microsoft-Windows-CAPI2/Operational"
	.NOTES
		Date:   01.04.2021
	#>
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogName
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$CommandLine = "wevtutil clear-log $LogName 2>&1 | Out-Null"
	LogDebug ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwExportSingleEventLog{
	<# 
	.SYNOPSIS
		Exports single Event Log in evtx format
	.DESCRIPTION
		global:FwExportSingleEventLog expects 3 parameters: $LogName, $FileName and $Overwrite (true or false)
	.EXAMPLE
		to execute this command: wevtutil.exe export-log "Microsoft-Windows-CAPI2/Operational" "c:\Capi2_Oper.evtx" /overwrite:true
		you need to call: global:FwExportSingleEventLog "Microsoft-Windows-CAPI2/Operational" "c:\Capi2_Oper.evtx" "true"
	.NOTES
		Date:   01.04.2021
	#>
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$LogName,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$FileName,
		[parameter(Mandatory=$false)]
		[String]$Overwrite
	)
	EnterFunc $MyInvocation.MyCommand.Name
	If([string]::IsNullOrEmpty($Overwrite)){
		$CommandLine = "wevtutil export-log $LogName $FileName 2>&1 | Out-Null"
	}
	else
	{
		$CommandLine = "wevtutil export-log $LogName $FileName /overwrite:$Overwrite 2>&1 | Out-Null" 
	}
	LogDebug ("Running $CommandLine")
	Try{
		Invoke-Expression $CommandLine
	}Catch{
		LogException ("An error happened in $CommandLine") $_ $fLogFileOnly
		Continue
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
		$DaysBack = $EvtDaysBack 
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
			LogInfo "[EventLog] $env:computerName-$EventLogFileName.evtx already exist. Skipping exporting the event log." "Gray"
			Continue
		}
		$Commands =@(
			"wevtutil epl `"$EventLog`" `"$ExportFolder\$env:computerName-$EventLogFileName.evtx`"",
			"wevtutil al `"$ExportFolder\$env:computerName-$EventLogFileName.evtx`" /l:en-us"
		)
		LogInfo "[EventLog] Exporting $EventLog"
		RunCommands "FwExportEventLog" $Commands -ThrowException:$False -ShowMessage:$False -ShowError:$True
		If(!$NoExportWithText){
			If(!($global:BoundParameters.ContainsKey('noEventConvert'))){
				if (($EventLog -ne "Security") -and ($DaysBack -ne 0)) {	# part1 of issue #510, skipping Security Eventlog as it takes usually a very long time
					# Export event log with text format
					FwExportEventLogWithTXTFormat $EventLog $ExportFolder -DaysBack $DaysBack
				}
			}
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
		global:FwExportEventLogWithTXTFormat "Microsoft-Windows-TWinUI/Operational" "C:\MS_DATA\XXX"
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

	# By default, use $EvtDaysBack(script parameter). But if $DaysBack is passed, respect the passed $DaysBack and use it.
	If($DaysBack -eq 0){
		$DaysBack = $EvtDaysBack 
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
			If(!(Test-Path "$global:TSSv2RegKey\EventLog")){
				RunCommands "FwSetEventLog" "New-Item -Path `"$global:TSSv2RegKey\EventLog`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
			}
			
			If(Test-Path -PathType Container "HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$EventLogName"){
				RunCommands "FwSetEventLog" "Copy-Item -Path `"HKLM:\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\$EventLogName`" -Destination `"$global:TSSv2RegKey\EventLog`" -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
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
		FwSetEventLog() saves previous event log setting to under "HKCU:\Software\Microsoft\TSSv2\EventLog" registry.
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
			$regKey = Get-Item "$global:TSSv2RegKey\EventLog\$EventLogName" -ErrorAction Stop 
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
				Remove-Item -Path "$global:TSSv2RegKey\EventLog\$EventLogName" -Recurse -ErrorAction Ignore | Out-Null 
			}Catch{
				$ErrorMessage = '[ResetEventLog] ERROR: Encountered an error during restoring event log. Eventlog=' + $EventLogName + ' Command=' + $_.CategoryInfo.Activity + ' HResult=0x' + [Convert]::ToString($_.Exception.HResult,16) + ' Exception=' + $_.CategoryInfo.Reason
				LogException $ErrorMessage $_ $fLogFileOnly
				Throw($ErrorMessage)
			}
		}Else{
			LogInfo "[FwResetEventLog] $EventLogName will be reset to Enabled=$Enabled and MaxSize=$MaxLogSize later"
		}
	}
	# If there is no entries under 'EventLog' registry, delete the top 'TSSv2' registry
	If((get-childitem "$global:TSSv2RegKey\EventLog") -eq $Null){
		Remove-Item -Path "$global:TSSv2RegKey\EventLog" -Recurse -ErrorAction Ignore | Out-Null #we# commented in order to keep EulaAccepted, but now EULA is in "HKCU:Software\Microsoft\CESDiagnosticTools"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwResetAllEventLogs{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Getting list of event logs to reset."
	$EventLogNames = Get-ChildItem "$global:TSSv2RegKey\EventLog" -ErrorAction Ignore
	If($EventLogNames.count -eq 0){
		LogDebug "No event log in $global:TSSv2RegKey"
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
	<# 
	.SYNOPSIS 
		Bulk collecting Eventlogs at Collect Phase
	.DESCRIPTION
		You can add Eventlogs to this list using function FWaddEvtLog
	.EXAMPLE
		FWgetEvtLogList _Stop_
	#>
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
		LogInfo "[$($MyInvocation.MyCommand.Name)] Please run command '$DirScript\TSSv2 -stop -noCrash' after reboot and collect $env:SystemRoot\memory.dmp." "Magenta"
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
		"$Sys32\certutil.exe -v -silent -store root | Out-File -Append $global:LogFolder\$($LogPrefix)Cert_Machine-Root-Registry-store.txt"
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

function global:FwGetGPresultAS { 
	# - GPresult, Auditing and Security
	param(
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if ($global:noGPresult -ne $true) {
		LogInfo "[$($MyInvocation.MyCommand.Name)] running 'GPresult', 'AuditPol', 'SecEdit' at $TssPhase"
		$Commands = @(
			"AuditPol.exe /get /category:* | Out-File -Append $global:LogFolder\$($LogPrefix)AuditPol$TssPhase.txt"
			"SecEdit /export /cfg $global:LogFolder\$($LogPrefix)SecEdit$TssPhase.txt"
			"GPresult.exe /h $global:LogFolder\$($LogPrefix)GPresult-H$TssPhase.htm /f"
			"GPresult.exe /v | Out-File $global:LogFolder\$($LogPrefix)GPresult-V_$env:username`_$TssPhase.txt"
		)
		RunCommands $LogPrefix $Commands -ThrowException:$False -ShowMessage:$False
		LogInfo " *** [Hint] GPO lookup: https://gpsearch.azurewebsites.net/" "Cyan"
	}
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
			LogInfo ".. starting msinfo32.exe $ArgumentList"
			$global:msinfo32TXT = Start-Process -FilePath 'msinfo32' -ArgumentList $ArgumentList -PassThru
		}
		if ($Format -match "nfo"){
			$ArgumentList = " /nfo `"$outFile`""
			LogInfo ".. starting msinfo32.exe $ArgumentList"
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
#	   [Parameter(Mandatory=$False)]
#	   [String]$HiveList,
		[Parameter(Mandatory=$False)]
		[String]$TssPhase = $global:TssPhase,				# _Start_ or _Stop_
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc ($MyInvocation.MyCommand.Name + " at $TssPhase")
	if (-not (Test-Path "$PrefixCn`RegHive_Software.hiv")) {
		LogInfoFile "___ FwGetRegHives at $TssPhase"
		$Commands = @(
			"REG SAVE HKLM\SOFTWARE $PrefixCn`RegHive_Software.hiv /Y"
			"REG SAVE HKLM\SYSTEM $PrefixCn`RegHive_System.hiv /Y"
			"REG SAVE HKCU\SOFTWARE $PrefixCn`RegHive_Software_User.hiv /Y"
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

Function global:FwGet-SummaryVbsLog{
	param(
		[String]$Stage=$Null,	# "Before-Repro|After-Repro"
		[switch]$FullBasic,		# select -FullBasic to collect Full Basic data
		[Parameter(Mandatory=$False)]
		[String]$Subfolder
	)
	EnterFunc $MyInvocation.MyCommand.Name
	if (!$global:IsLiteMode) { 
		if ([string]::IsNullOrEmpty($Subfolder)) { $DestFolder = $BasicLogFolder} else { $DestFolder = $global:LogFolder + "\"  + $Subfolder}
		If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
		$LogPrefix = $B_mode + "BasicLog-SummaryVbsLog"
		If (Test-Path -Path "$Scriptfolder\psSDP\Diag\global\SummaryReliability.vbs") {
			Try {
				LogInfo "[$LogPrefix] .. running SummaryReliability.vbs"
				Push-Location -Path $DestFolder
				$CommandToExecute = "cscript.exe //e:vbscript $Scriptfolder\psSDP\Diag\global\SummaryReliability.vbs /sdp"
				Invoke-Expression -Command $CommandToExecute | Out-Null
			} Catch {
				LogException "An Exception happend in SummaryReliability.vbs" $_
			}
			Pop-Location
			#cd "$PSScriptRoot"
		}Else{ LogInfo "[$LogPrefix] SummaryReliability.vbs not found - skipping"}
	}else{ LogInfo "Skipping FwGet-SummaryVbsLog in Lite mode"}
	EndFunc $MyInvocation.MyCommand.Name
}

Function global:FwGet-OSversion-Build{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[BasicLog] Obtaining OS version with build number" # Note: #!# LogInfoFile would fail at this stage as $LogFolder does not exist
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
	If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
	$LogPrefix = $B_mode + "BasicLog-System"

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
	# MSinfo32
	if ($FullBasic) {
		FwGetMsInfo32 "nfo" -Subfolder $BasicSubFolder
	}
	# Basic registry keys
	LogInfo "[$LogPrefix] Exporting registry hives"
	FwGetRegHives _Stop_
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
		#we# if ($FullBasic -or $BasicEvtLogs -contains $EventLog.LogName){	#we# issue#405
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
	If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
	$LogPrefix = $B_mode + "BasicLog-Setup"

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
	If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
	$LogPrefix = $B_mode + "BasicLog-NET"
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
	If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
	$LogPrefix = $B_mode + "BasicLog-UEX"
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
	If($FullBasic){ $B_mode="Full-" }else{$B_mode="Mini-"}
	$LogPrefix = $B_mode + "BasicLog-SHA"
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
	LogInfo "[$LogPrefix] .. running Full BasicLog" "Gray"
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
	FwGet-SummaryVbsLog -FullBasic
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
	LogDebug "[$LogPrefix] .. running Mini BasicLog" "Gray"
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
	FwGet-SummaryVbsLog
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
		LogDebug "[FwExportFileVerToCsv] Getting file version of $Env:Windir\$WindirSubFolder\*.$FileExt" "Gray"
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
		LogInfoFile "[FwExportFileVerToCsv] ... finished for $WindirSubFolder\*.$FileExt" "Gray"
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
	#LogInfo "InvalidOperationException happened in Add-Type for FindServicePID but this is ignorable and continue." "Gray"
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
		  # For -Start, retrieve ProcDumpInterval from BoundParameters[] or config.cfg. For -Stop, $ProcDumpInterval are set in ReadParameterFromTSSv2Reg().
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

function ShowEULAPopup($mode)
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

function ShowEULAIfNeeded($toolName, $mode)
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
	}Else{ # Search TTD shipped with TSSv2. If not exist, try to search built-in TTD.
		If($Global:ProcArch -eq 'x64'){
			If($global:OSVersion.Build -le 9600){
				$TTDFullPath = Join-Path -Path ".\BINx64\downlevel" "TTTracer.exe"
			}Else{
				$TTDFullPath = Join-Path -Path ".\BINx64" "TTTracer.exe"  # !!! the relative path might need to be updated once partner package is included in TSSv2 and actual TTD path is determined.
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
		if ($ShowMsg) { LogInfo "Stopping transcript" }
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
	$TSSv2Job = Get-Job -Name "TSSv2-*"
	If($TSSv2Job -ne $Null){
		$TSSv2Job | Remove-Job
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
		StopTSSClock
	}

	# Stop console logging.
	Close-Transcript
	If($global:LogFolder -ne $Null -and ($Error.Count -ne 0 -and (Test-Path -Path $global:LogFolder))){
		$Error | Out-File -FilePath $global:ErrorVariableFile
	}
	EndFunc $MyInvocation.MyCommand.Name
	LogDebug "Exiting script..." "Gray"
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

	$TraceName = $ScenarioTraceName -replace ".*Scenario_",""  # TSSv2_NET_BITSScenario_NET_BITSTrace => NET_BITSTrace
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

Function SaveToTSSv2Reg{
	Param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]$RegValue,
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[Object]$RegData
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If(!(Test-Path $global:TSSv2ParamRegKey)){
		LogInfo "Saving all parameters to $global:TSSv2ParamRegKey" "Gray"
		RunCommands "SaveToTSSv2Reg" "New-Item -Path `"$global:TSSv2ParamRegKey`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
	}

	$TSSv2Reg = Get-ItemProperty -Path  $global:TSSv2ParamRegKey
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

	LogInfoFile "Saving $RegValue($RegData) type=$($RegData.GetType()) to $($global:TSSv2ParamRegKey)"
	LogDebug "Saving -Name $RegValue -Value $RegData"
	If($TSSv2Reg.$RegValue -ne $Null){ # Overwrite the value
		Set-ItemProperty -Path $global:TSSv2ParamRegKey -Name $RegValue -Value $RegData
	}Else{
		New-ItemProperty -Path $global:TSSv2ParamRegKey -Name $RegValue -Value $RegData -PropertyType $PropertyType | Out-Null
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
	  Function will display a PopUp window with [OK] button for duration of N seconds with title "TSSv2 PowerShell ..." and closes after N seconds, then TSSv2 script continues and requests input from user
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
	$PopUpWin = $newobject.popup("$Topic - Click OK and then Please answer TSS question ",$Timer ," TSSv2 PowerShell window has a question for you! ($Timer sec display) ",0)
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
	If($NumExecutable -lt 20){
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

Function AddTraceToLogCollector{
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
		$tmpObject = $LogCollector | Where-Object{$_.TraceName -eq $TraceObject.TraceName}
		If($tmpObject -ne $Null){
			LogInfo "ERROR: Tried to start trace for $($TraceObject.TraceName) twice. Usually this happens when a scenario trace and a normal trace that is contained in the scenario are started at the same time. Please check what traces are contained in the scenario with below command." "Red"
			LogInfo "=> .\$ScriptName -TraceInfo <ScenarioName>" "Yellow"
			CleanUpandExit
		}
		LogDebug "Adding $($TraceObject.TraceName) to trace list"
		$LogCollector.Add($TraceObject)
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
						$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
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
			# Example: $ScenarioName="ADS_AUTH" $FullTraceName="TSSv2_ADS_AUTHScenario_ADS_XXXTrace" $TraceName=ADS_XXXTrace
			$ScenarioToken = $Token[0] -Split 'Scenario_' # TSSv2_ADS_AUTHScenario_ADS_XXXTrace => TSSv2_ADS_AUTH , ADS_XXXTrace
			$ScenarioName = $ScenarioToken[0] -replace (($ScriptPrefix + '_'),'') # TSSv2_ADS_AUTH => ADS_Auth
			$FullTraceName = $Token[0] -replace ("Trace.*","Trace") # TSSv2_ADS_AUTHScenario_ADS_XXXTraceXXX => TSSv2_ADS_AUTHScenario_ADS_XXXTrace
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
4. After that, search normal ETW trace with '$ScriptPrifix_' which is currently 'TSSv2_'.
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
	$tmpTraceName = $ScenarioTraceName -replace (".*Scenario_","") # TSSv2_testScenario_DEV_TEST1Trace => DEV_TEST1Trace
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
	$tmpTraceName = $MultiETLTraceName -replace ".*METL_","TSSv2_" # TSSv2_METL_NET_TEST3_CertCliTrace => TSSv2_NET_TEST3_CertCliTrace
	$Token = $tmpTraceName -split "_"
	For($i=0; $i -lt $Token.Length-1; $i++){
		If($i -ne 0){
			$TraceName = $TraceName + '_'
		}
		$TraceName = $TraceName + $Token[$i]  # TSSv2_NET_TEST3_CertCliTrace => TSSv2_NET_TEST3
	}
	$TraceName = $TraceName + 'Trace'  # TSSv2_NET_TEST3 => TSSv2_NET_TEST3Trace(Original trace name)

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
		
		# For -PerfMon, but not -noPerfMon
		If($global:BoundParameters.ContainsKey('PerfMon')){
			If(!($global:BoundParameters.ContainsKey('noPerfMon'))){
				LogInfo "Setting up PerfMon($($global:BoundParameters['PerfMon'])) parameters."
				FixUpPerfProperty 'PerfMon'
			} else {
				LogInfoFile "skip Setting up PerfMon, because of -noPerfmon switch"
			}
		}
		# For -PerfMonLong
		If($global:BoundParameters.ContainsKey('PerfMonLong')){
			If(!($global:BoundParameters.ContainsKey('noPerfMon'))){
				LogInfo "Setting up PerfMonLong($($global:BoundParameters['PerfMonLong'])) parameters."
				FixUpPerfProperty 'PerfMonLong'
			} else {
				LogInfoFile "skip Setting up PerfMonLong, because of -noPerfmon switch"
			}
		}
		
		# For -WPR
		If($global:ParameterArray -Contains 'WPR'){
			If($global:ParameterArray -notcontains 'noWPR'){
				LogInfo "Setting up WPR parameters."
				FixUpWPRProperty
			} else {
				LogInfoFile "skip Setting up WPR, because of -noWPR switch"
			}
		}
		
<#		# For PSR
		If($global:ParameterArray -Contains 'PSR'){
			If($global:ParameterArray -notcontains 'noPSR'){
				LogInfo "Setting up PSR parameters."
				FixUpPSRProperty
			} else {
			LogInfoFile "skip Setting up PSR, because of -noPSR or -noRecording switch"
			}
		}
#>		
		
		# For -Xperf
		If($global:ParameterArray -Contains 'Xperf'){
			If($global:ParameterArray -notcontains 'noXperf'){
				LogInfo "Setting up Xperf parameters."
				FixUpXperfProperty
			} else {
				LogInfoFile "skip Setting up Xperf, because of -noXperf switch"
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
	5. Check argmuents and pick up TraceObjects specified in command line parameter and add them to $LogCollector(Generic.List)
	6. StartTraces() starts all traces in $LogCollector(not $GlobalTraceCatalog). 
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
		StartTSSClock
	}

	# List used for multi etl file trace
	$CreatedMETLTraceList = New-Object 'System.Collections.Generic.List[PSObject]'
	$RemoveTraceList = New-Object 'System.Collections.Generic.List[PSObject]'

	ForEach($TraceObject in $LogCollector)
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

								# Create trace object and add it to LogCollector
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
			LogDebug "Adding $($METLTraceObject.TraceName) to LogCollector" Yellow
			$LogCollector.Add($METLTraceObject)
		}
	}
	If($RemoveTraceList.Count -ne 0){
		ForEach($RemoveTraceObject in $RemoveTraceList){
			LogDebug "Removing $($RemoveTraceObject.TraceName) from LogCollector" Yellow
			$LogCollector.Remove($RemoveTraceObject) | Out-Null
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

Function StopTraces{
	param(
		[parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[PSObject]]$TraceCollection
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$global:TssPhase = "_Stop_"
	# Change execution order based on 'StopPriority' in trace object
	$SortedLogCollector = $TraceCollection | Sort-Object -Property StopPriority
	
	# Remove and add trace object to original $TraceCollection with sorted order.
	ForEach($TraceObject in $SortedLogCollector){
		$TraceCollection.Remove($TraceObject) | Out-Null
		$TraceCollection.Add($TraceObject)
	}

	LogInfo "Stopping traces with below order:"
	$i=1
	ForEach($TraceObject in $TraceCollection){
		Write-Host ([String]::Format("  {0,-2} {1}", $i, $($TraceObject.TraceName)))
		$i++
	}
	Write-Host ""

	# Get running ETW sessions
	$ETWSessionList = logman -ets | Out-String

	# Get running Scenario traces
	$Script:RunningScenarioObjectList = GetRunningScenarioTrace
	If($DebugMode.IsPresent){
		LogDebug ("Below traces will be stopped")
		LogDebug ("================	 RUNNING SCENARIOS AND TRACES	 ================")
		ForEach($TraceObject in $TraceCollection){
			#If(!($TraceObject.TraceName -like "*Scenario_*")){
				LogDebug ("  - " + $TraceObject.TraceName)
			#}
		}
		LogDebug ("=======================================================================")
		DumpCollection $TraceCollection
		Read-Host ("[DBG - hit ENTER to continue] [Before stopping traces] ==>")
	}

	# Get all processes running on current user session.
	$CurrentSessinID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
	$Processes = Get-Process | Where-Object{$_.SessionID -eq $CurrentSessinID}

	# Run pre-stop function for scenario trace.
	ForEach($ScenarioName in $Scenario){
		$ScenarioPreStopFunc = $ScenarioName + 'ScenarioPreStop'
		Try{
			RunFunction $ScenarioPreStopFunc -ThrowException:$True
		}Catch{
			LogException "An error happened in $ScenarioPreStopFunc but this is not critical and continue to stop traces." $_ $fLogFileOnly
		}
	}

	ForEach($TraceObject in $TraceCollection){

		# Run pre-stop function for a component.
		$ComponentPreStopFunc = $TraceObject.Name + 'PreStop'
		Try{
			RunFunction $ComponentPreStopFunc -ThrowException:$True
		}Catch{
			LogWarn "[$($TraceObject.Name)] Error happens in pre-stop function($ComponentPreStopFunc). Skipping this trace."
			LogException ("An error happened in " + $ComponentPreStopFunc) $_ $fLogFileOnly
			Continue
		}

		Switch($TraceObject.LogType) {
			'ETW' {
				LogDebug "[ETW] Stopping $($TraceObject.TraceName)."
				Try{
					RunCommands "ETW" "logman stop $($TraceObject.TraceName) -ets" -ThrowException:$True -ShowMessage:$True -ShowError:$True
				}Catch{
					$ErrorInStoppingTrace = $True
				}

				# Retry stopping trace.
				If($ErrorInStoppingTrace){
					# Make sure the trace is really still running.
					$IsTraceRunning = $True
					Try{
						# If the trace is not running, 'logman <TraceName> -ets' throws an exception. In this case, we regard the trace stopped successfully.
						RunCommands "ETW" "logman $($TraceObject.TraceName) -ets" -ThrowException:$True -ShowMessage:$False -ShowError:$False
					}Catch{
						LogInfo "[ETW] $($TraceObject.TraceName) has already stopped."
						$IsTraceRunning = $False # Looks like the trace is already stopped somehow. Set the flag to $False.
					}

					If($IsTraceRunning){
						# It is possible that the logman fails with some reason and trying the stop command might work. So sleep 3 seconds and try it again.
						LogWarn "Retrying to stop $($TraceObject.TraceName)"
						Start-Sleep -Seconds 3
						Try{
							RunCommands "ETW-2" "logman stop $($TraceObject.TraceName) -ets" -ThrowException:$True -ShowMessage:$True -ShowError:$True
						}Catch{
							LogException ("An error happened in `'logman stop $($TraceObject.TraceName)`'") $_
							$TraceObject.Status = $TraceStatus.ErrorInStop
							Continue
						}
						LogInfo "`'$($TraceObject.TraceName) `' was stopped successfully!" "Cyan"
					}
				}

				# Remove extension of .001(XXX-AutoLogger.etl.001 -> XXX-AutoLogger.etl
				If($script:StopAutologger){
					$001Files = Get-ChildItem $global:LogFolder | Where-Object {$_.Name -like "*-AutoLogger.etl.001" }
					ForEach($001File in $001Files){
						$NewName = $001File.FullName -Replace "\.etl\.001",".etl"
						LogDebug "Renaming $001File.Name to $NewName"
						Rename-Item $001File.FullName $NewName -ErrorAction Ignore
					}
				}

				# When we reach here, it means 'logman stop' was successful.
				$StoppedTraceList.Add($TraceObject)
				$TraceObject.Status = $TraceStatus.Stopped
				Break
			}
			'Command' {
				If($TraceObject.SupportedOSVersion -ne $Null){
					If(!(FwIsSupportedOSVersion $TraceObject.SupportedOSVersion)){
						LogInfo ($TraceObject.Name + ' is not supported on this OS. Supported Version is [Windows ' + $TraceObject.SupportedOSVersion.OS + ' Build ' + $TraceObject.SupportedOSVersion.Build + ']')
						$TraceObject.Status = $TraceStatus.NotSupported
						Break
					}
				}
				LogDebug ('Enter [Command] section in StopTraces. Stopping ' + $TraceObject.Name)
				Try{
					Get-Command $TraceObject.CommandName -ErrorAction Stop | Out-Null
				}Catch{
					If($TraceObject.Name -eq 'Procmon' -and $TraceObject.AutoLogger.AutoLoggerEnabled -eq $True){
						LogDebug ('[Procmon] setting $fDonotDeleteProcmonReg to $True.')
						$script:fDonotDeleteProcmonReg = $True
					}
					LogError ($TraceObject.CommandName + ' not found. Please stop ' + $TraceObject.Name + ' manually.')
					$TraceObject.Status = $TraceStatus.ErrorInStop
					Break
				}

				$fFoundExistingSession = $False
				Switch($TraceObject.Name) {
					'WPR' {
						LogDebug ('Searching ' + $WPRSessionName + ' in CimInstances')
						ForEach($Line in ($ETWSessionList -split "`r`n")){
							$Token = $Line -Split '\s+'
							If($Token[0] -eq 'WPR_initiated_WprApp_WPR' -or $Token[0] -eq 'WPR_initiated_WprApp_boottr_WPR'){
								LogDebug "Found existing $($TraceObject.Name) session." "Yellow"
								$fFoundExistingSession = $True
								Break
							}
						}
					}
					'Xperf' {
						# We use a log file for xperf to see if the xperf is actively running.
						$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
						$LogFolderInReg = $RegValue.LogFolder
						If(![String]::IsNullOrEmpty($LogFolderInReg)){
							$XperfFileName = "$LogFolderInReg\xperf.etl"
							If(Test-Path -Path $XperfFileName){
								LogDebug ("[xperf] Found existing $($TraceObject.Name) session.")
								$fFoundExistingSession = $True
								Break
							}
						}
					}
				   'Netsh' {
						$NetshSessionName = 'NetTrace'
						ForEach($Line in ($ETWSessionList -split "`r`n")){
							$Token = $Line -Split '\s+'
							If($Token[0].Contains($NetshSessionName)){
								$fFoundExistingSession = $True
								LogDebug ('[Netsh] Found existing ' + $Token[0] + ' session.')
								Break
							}
						}
					}
					'Procmon' {
						$Prcmon = $Processes | Where-Object{$_.Name.ToLower() -like 'Procmon*'}
						If($Prcmon.Count -ne 0){
							$fFoundExistingSession = $True
							LogDebug "[Procmon] Procmon is running as active session."
							Break
						}
						If($script:StopAutologger){
							If(Test-Path -Path $TraceObject.AutoLogger.AutoLoggerKey){
								Try{
									$Value = Get-Itemproperty -name 'Start' -path $TraceObject.AutoLogger.AutoLoggerKey -ErrorAction Ignore
								}Catch{
									LogDebug ('[Procmon] Start registry for Procmon does not exist. Skipping Procmon.')
									$fFoundExistingSession = $False 
									Break
								}
								# Start = 3 means this is first boot after BootLogging.
								If($Value.Start -ne $NULL -and ($Value.Start -eq 3 -or $Value.Start -eq 0)){
									LogDebug ('[Procmon] BootLogging detected.')
									$fFoundExistingSession = $True 
								}Else{
									LogDebug ('[Procmon] Start registry = ' + $Value.Start)
								}
							}
						}
					}
					'PSR' {
						$PSRProcess = $Processes | Where-Object{$_.Name.ToLower() -eq 'psr'}
						If($PSRProcess.Count -ne 0){
							$fFoundExistingSession = $True
							LogDebug ('[PSR] Found existing ' + $TraceObject.Name + ' session.')
						}
					}
					'Video' {
						$VideoProcess = $Processes | Where-Object{$_.Name.ToLower() -eq 'recordercommandline'}
						If($VideoProcess.Count -ne 0){
							$fFoundExistingSession = $True
							LogDebug ('[Video] Found existing ' + $TraceObject.Name + ' session.')
						}
					}
				}

				If(!$fFoundExistingSession){
					LogDebug ('Skipping stopping ' + $TraceObject.Name + ' as it is not running')
					Continue
				}

				# Normal case. Perform actual stop function here.
				If(!$script:StopAutologger){
					LogInfo "Stopping job $($TraceObject.Name)."
					LogInfo "[$($TraceObject.Name)] Running $($TraceObject.CommandName) $($TraceObject.StopOption)"
					Start-Job -Name ("TSSv2-" + $TraceObject.Name) -ScriptBlock {
						Start-Process -FilePath $Using:TraceObject.CommandName -ArgumentList $Using:TraceObject.StopOption -PassThru -wait
					} | Out-File -FilePath $global:ErrorLogFile -Append #we#| Out-Null
				# AutoLogger case.
				}Else{ 
					LogInfo ('[' + $TraceObject.Name + '] Running ' + $TraceObject.CommandName + ' ' + $TraceObject.AutoLogger.AutoLoggerStopOption)
					Start-Job -Name ("TSSv2-" + $TraceObject.Name) -ScriptBlock {
						Start-Process -FilePath $Using:TraceObject.CommandName -ArgumentList $Using:TraceObject.AutoLogger.AutoLoggerStopOption -PassThru -wait
					} | Out-Null

					If($TargetObject.Name -eq 'Procmon' -and $script:StopAutologger){
						Try{
							LogDebug ('Deleting Procmon registry keys')
							Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Start' -ErrorAction Ignore
							Remove-ItemProperty -Path $TraceObject.AutoLogger.AutoLoggerKey -Name 'Type'  -ErrorAction Ignore
						}Catch{
							# Do Nothing.
							LogWarn ('Failed to delete Procmon registry keys for ' + $TraceObject.AutoLogger.AutoLoggerKey)
						}
					}
				}
				$TraceObject.Status = $TraceStatus.Stopped
				$StoppedTraceList.Add($TraceObject)
			}
			'Perf' {
				LogDebug ('Enter [Perf] section in StopTraces. Name = ' + $TraceObject.Name)
				$datacollectorset = new-object -COM Pla.DataCollectorSet
				Try{
					$datacollectorset.Query($TraceObject.Name, $env:computername)
				}Catch{
					LogInfo ('Skipping stopping ' + $TraceObject.Name + ' as it is not running')
					Break
				}

				#Status ReturnCodes: 0=stopped 1=running 2=compiling 3=queued (legacy OS) 4=unknown (usually AutoLogger)
				If($datacollectorset.Status -ne 1){
					LogDebug ('Skipping stopping ' + $TraceObject.Name + ' as it is not running')
					Break
				}
				LogInfo ('[' + $TraceObject.Name + '] Running logman stop ' + $TraceObject.Name)
				logman stop $TraceObject.Name | Out-Null
				If($LASTEXITCODE -ne 0){
					LogError ('[' + $TraceObject.Name + '] Failed to stop PerformanceMonitor log.')
					$TraceObject.Status = $TraceStatus.ErrorInStop
				}
				LogInfo ('[' + $TraceObject.Name + '] Running logman delete ' + $TraceObject.Name)
				logman delete $TraceObject.Name | Out-Null
				If($LASTEXITCODE -ne 0){
					LogError ('[' + $TraceObject.Name + '] Failed to delete Performance Monitor log.')
					$TraceObject.Status = $TraceStatus.ErrorInStop
				}Else{
					LogDebug ('[Perf] PerfMon was successfully stopped.')
					$TraceObject.Status = $TraceStatus.Stopped
					$StoppedTraceList.Add($TraceObject)
				}
			}
			'Custom' {
				LogDebug ('Enter [Custom] section in StopTraces. Name = ' + $TraceObject.Name)
				If($TraceObject.SupportedOSVersion -ne $Null){
					If(!(FwIsSupportedOSVersion $TraceObject.SupportedOSVersion)){
						LogDebug "$($TraceObject.Name) is not supported on this OS. Supported Version is [Windows $($TraceObject.SupportedOSVersion.OS) Build $($TraceObject.SupportedOSVersion.Build)]."
						$TraceObject.Status = $TraceStatus.NotSupported
						Break
					}
				}
				# Check if the trace has pre-start function. If so, just call it.
				Try{
					If($TraceObject.StopFunc -ne $Null){
						Try{
							$CustomStopFunc = $TraceObject.StopFunc
							RunFunction $CustomStopFunc -ThrowException:$True
							$fCustomStopFuncStarted = $True
						}Catch{
							LogWarn "Error happens in $CustomStopFunc. See error file $global:ErrorLogFile for detail."
							LogException ("An error happened in " + $CustomStopFunc) $_ $fLogFileOnly
						}
					}Else{
						$TraceObject.Status = $TraceStatus.NoStopFunction
					}
				}Catch{
					LogException ('[' + $TraceObject.Name + '] An error happened in stop function(' + $TraceObject.StopFunc + ').') $_
					$TraceObject.Status = $TraceStatus.ErrorInStop
					Continue
				}
				If($fCustomStopFuncStarted){
					$TraceObject.Status = $TraceStatus.Stopped
					$StoppedTraceList.Add($TraceObject)
				}
			}
			Default {
				LogError ('Unknown log type ' + $TraceObject.LogType)
			}
		}

		# For multiple etl trace, a post-stop function is associated with multiple etl traces 
		# and this causes the post-stop function to be run before stopping all associated METL traces.
		# To prevent this, we remember the metl traces and run a post-stop function for them later.
		If($TraceObject.TraceName -like "*_METL_*"){
			$TraceName = $DelayedExecutionList | Where-Object {$_ -eq $TraceObject.Name}
			If($TraceName -eq $Null){
				LogDebug "Adding $($TraceObject.Name) to DelayedExecutionList"
				$Script:DelayedExecutionList.Add($TraceObject.Name)
			}
			Continue
		}

		# Run post-stop function for a component. For Command type, stop process is executed asynchronously using PSJob. So we don't run post-stop function for command type at this point.
		If($TraceObject.LogType -ne 'Command'){
			$ComponentPostStopFunc = $TraceObject.Name + 'PostStop'
			Try{
				If(!$global:BoundParameters.ContainsKey('Discard')){
					RunFunction $ComponentPostStopFunc -ThrowException:$True
				}
			}Catch{
				LogWarn "Error happens in $ComponentPostStopFunc. See error file $global:ErrorLogFile for detail."
				LogException ("An error happened in " + $ComponentPostStopFunc) $_ $fLogFileOnly
			}
		}
	}

	If(!$global:BoundParameters.ContainsKey('Discard')){
		# Run post-stop function for type2(multiple etl) trace.
		ForEach($METLTraceName in $DelayedExecutionList){
			$ComponentPostStopFunc = $METLTraceName + 'PostStop'
			Try{
				RunFunction $ComponentPostStopFunc -ThrowException:$True
			}Catch{
				LogWarn "Error happens in $ComponentPostStopFunc. See error file $global:ErrorLogFile for detail."
				LogException ("An error happened in " + $ComponentPostStopFunc) $_ $fLogFileOnly
			}
		}

		# Run post-stop function for scenario trace that does have command type trace.
		ForEach($ScenarioName in $Scenario){ # When -StartNoWait, $Scenario is set in ReadParameterFromTSSv2Reg().
			# Fix(#222)
			# If the scenario has command type trace like WPR and Netsh, the post-stop function for the scenario will be run after stopping all commands. #we# comment: this must not delay time-critical Post-Stop actions! better run your POD action in Collect...Log()
			If((HasScenarioCommandTypeTrace $ScenarioName)){
				If($DelayedExecutionListForScenario -notcontains $ScenarioName){
					LogInfo "Post-stop function for $ScenarioName will be run after stopping all command type traces." "Gray"
					$Script:DelayedExecutionListForScenario.Add($ScenarioName)
				}
				Break
			}
			$ScenarioPostStopFunc = $ScenarioName + 'ScenarioPostStop'
			Try{
				RunFunction $ScenarioPostStopFunc -ThrowException:$True
			}Catch{
				LogWarn "Error happens in $ComponentPostStopFunc. See error file $global:ErrorLogFile for detail."
				LogException ("An error happened in " + $ScenarioPostStopFunc) $_ $fLogFileOnly
			}
			# create Zip file suffix based on scenario selcected #we#
			$script:LogZipFileSuffixScn += -join ($ScenarioName , "_")
		}
	}

	# Won't collect basic logs if we are in recovery process.
	If(!$Script:fInRecovery){
		#_# moved ----- begin _Stop_common_task block down after: data collection function for scenario. #161 /WalterE

		# We call component collect function in case of below conditions.
		# 1) There is a running scenario trace but -CollectComponentLog is specified
		# 2) There is no scenario trace
		If(!$global:BoundParameters.ContainsKey('Discard')){
			If(([String]::IsNullOrEmpty($Scenario)) -or (![String]::IsNullOrEmpty($Scenario) -and $global:BoundParameters['CollectComponentLog'] -ne $Null)){
				# Now call component specific log function
				# The naming convention of the function is 'Collect' + $TraceObject.Name + 'Log'(ex. CollectRDSLog)
				ForEach($StoppedTrace in $StoppedTraceList){
				
					# Calling component callback function
					$ComponentSpecificFunc = 'Collect' + $StoppedTrace.Name + 'Log'
					Try{
							RunFunction $ComponentSpecificFunc -ThrowException:$True
					}Catch{
						LogWarn "Error happens in $ComponentSpecificFunc."
						LogException ("[$StoppedTrace] An error happened in " + $ComponentSpecificFunc) $_ $fLogFileOnly
					}
				
					# Diag function
					$ComponentDidagFunc = 'Run' + $StoppedTrace.Name + 'Diag'
					Try{
						RunFunction $ComponentDidagFunc -ThrowException:$True
					}Catch{
						LogWarn "Error happens in $ComponentDidagFunc."
						LogException ("An error happened in " + $ComponentDidagFunc) $_ $fLogFileOnly
					}
				}
			}

			# Run data collection function for scenario.
			ForEach($ScenarioName in $Scenario){
				LogDebug "Searching data collection function for $ScenarioName scenario."
				$ScenarioDataCollectionFunc = 'Collect' + $ScenarioName + 'ScenarioLog'
				Try{
					RunFunction $ScenarioDataCollectionFunc -ThrowException:$True
				}Catch{
					LogWarn "Error happens in $ScenarioDataCollectionFunc."
					LogException ("An error happened in " + $ScenarioDataCollectionFunc) $_ $fLogFileOnly
				}

				# Run diag function for scenario.
				$ScenarioDiagFunc = 'Run' + $ScenarioName + 'ScenarioDiag'
				Try{
					RunFunction $ScenarioDiagFunc -ThrowException:$True
				}Catch{
					LogWarn "Error happens in $ScenarioDiagFunc."
					LogException ("An error happened in " + $ScenarioDiagFunc) $_ $fLogFileOnly
				}
			}
		 
			# Call common STOP tasks
			If(($Scenario.Count -ne 0) -and [string]::IsNullOrEmpty($CommonTask)){
				[Bool]$Script:IsCommonTaskAlreadyRun = $False

				# In this case, we don't know what scenario of common task to call. Therefore retrieve the scenario name from running trace name.
				ForEach($ScenarioName in $Scenario){
					$ScenarioTraceSetName = "$($ScenarioName)_ETWTracingSwitchesStatus"
					$Scenario_ETWTracingSwitchesStatus = Get-Variable $ScenarioTraceSetName -ValueOnly -ErrorAction Ignore
					ForEach($Key in $Scenario_ETWTracingSwitchesStatus.Keys){
						$Token = $Null
						If($Key.contains('CommonTask')){
							$Token = $Key -split ' '
							LogDebug "Setting `'$($Token[1])`' to TaskType"
							$TaskType = $Token[1]
							Switch($TaskType){
								# For Full and Mini, add -RunOnce:$False as its possible the collect func is called previously on start.
								'Full'{
									RunFunction "FwCollect_BasicLog" -Stage  "After-Repro" -RunOnce:$False -ThrowException:$False
								}
								'Mini'{
									RunFunction "FwCollect_MiniBasicLog" -Stage "After-Repro" -RunOnce:$False -ThrowException:$False
								}
								Default {
									$PODCommonStopFunc = $TaskType + "_Stop_Common_Tasks"
									RunFunction $PODCommonStopFunc -ThrowException:$False
									[Bool]$Script:IsCommonTaskAlreadyRun = $True
								}
							}
						}
					}
				}
			}ElseIf(![string]::IsNullOrEmpty($CommonTask)){ # -Stop + -CommonTask case
				Switch($CommonTask){
					# For Full and Mini, add -RunOnce:$False as its possible the collect func is called previously on start.
					'Full'{
						RunFunction "FwCollect_BasicLog" -Stage  "After-Repro" -RunOnce:$False -ThrowException:$False 
					}
					'Mini'{
						RunFunction "FwCollect_MiniBasicLog" -Stage "After-Repro" -RunOnce:$False -ThrowException:$False
					}
					Default {
						$PODCommonStopFunc = $CommonTask + "_Stop_Common_Tasks"
						RunFunction $PODCommonStopFunc -ThrowException:$False
						[Bool]$Script:IsCommonTaskAlreadyRun = $True
					}
				}
			}
			if (!$Script:IsCommonTaskAlreadyRun){
				# We call full basic log only when -Basiclog is specified. Otherwise mini basic log(FwCollect_MiniBasicLog) is called.
				# It is possible FwCollect_BasicLog/FwCollect_MiniBasicLog will be run twice as it might be run as an above common task.
				# But RunFunction() can recognize if it has been already run or not. So the below basic log is run only when the common task is not Mini or Full.
				ProcessBasicLog $Script:IsCommonTaskAlreadyRun
			}
			#_#----- end _Stop_common_task

			# Run xray Diagnostics to scan for known issues (no need to show EULA again)
			#_# If($global:ParameterArray -Contains 'Xray' -and !$noXray.IsPresent){
			If($Xray.IsPresent -and (-not $noXray)){ #we#
				ProcessXray
			}
		}else{ LogInfo " Skip data-collection .. early exit because of -Discard switch" "Magenta"}
	}

	$Jobs = Get-Job -Name "TSSv2-*"
	If($Jobs.Count -ne 0){
		LogInfo "Waiting for all running commands below to be stopped."
		ForEach($Job in $Jobs){
			LogInfo "  - $($Job.Name)"
		}
	}

	# Start wating for jobs to be completed.
	$LoopCount = 0
	$CheckIntervalInSec = 1
	While($Jobs.Count -ne 0){
		$LoopCount++
		$Jobs = Get-Job -Name "TSSv2-*"
		If($Jobs -eq $Null){ # All job are finished and get out of while loop.
			Break
		}
		Write-Host '.' -NoNewline
		$IsDotDisplayed = $True
		Start-Sleep $CheckIntervalInSec

		ForEach($Job in $Jobs){
			$CommandName = $Job.Name -replace ("TSSv2-","")
			$TraceObject = $TraceCollection | Where-Object {$_.Name -eq $CommandName}
			$JobFinished = $False

			Switch($Job.State){
				'Completed'{
					If($IsDotDisplayed -eq $True){
						Write-Host ""
					}
					LogInfo "Job $($Job.Name) is completed."
					Remove-Job $Job
					$TraceObject.Status = $TraceStatus.Stopped
					$JobFinished = $True
				}
				'Failed'{
					LogError ($Job.Name + ' failed.' + "`n" + $job.ChildJobs[0].JobStateInfo.Reason.Message)
					Remove-Job $Job
					$TraceObject.Status = $TraceStatus.ErrorInStop
					$JobFinished = $True
				}
				'Running'{
					# Get time out value from its property.
					If(![string]::IsNullOrEmpty($TraceObject.StopTimeoutInSec)){
						$JobTimeOutInSec = $TraceObject.StopTimeoutInSec
					}Else{
						$JobTimeOutInSec = 1800 # 30 minutes
					}

					# Calclate current elapsed time.
					$ElapsedTime = $LoopCount * $CheckIntervalInSec

					# Check if it is timed out.
					If($ElapsedTime -ge $JobTimeOutInSec){
						LogError "Time out(Elapased time=$ElapsedTime TimeOut=$JobTimeOutInSec) happened. Unable to stop $($TraceObject.CommandName)."
						Stop-Job $Job
						Remove-Job $Job
						$TraceObject.Status = $TraceStatus.ErrorInStop
						$JobFinished = $True
					}
				}
				Default {
					LogWarn "$($Job.Name) is in $($Job.State). This is not normal and removing the job."
					Stop-Job $Job
					Remove-Job $Job
				}
			}
			$IsDotDisplayed = $False
			# If the job is finished regardless of the status(sucess or error), we call post-stop function for this object.
			If($JobFinished){
				 $CommandPostStopFunc = $TraceObject.Name + "PostStop"
				 Try{
					 RunFunction $CommandPostStopFunc -ThrowException:$True
				 }Catch{ # Show only warning message and log detail to error file.
					 LogWarn "An exception happens in $CommandPostStopFunc. See error file $global:ErrorLogFile for detail."
					 LogException ("An exception happened in " + $CommandPostStopFunc) $_ $fLogFileOnly
				 }
			}
		}
	}

	# Fix(#222)
	# Run post-stop function for the scenario that has command type trace.
	If($DelayedExecutionListForScenario.Count -ne 0){
		ForEach($ScenarioName in $DelayedExecutionListForScenario){
			$ScenarioPostStopFunc = $ScenarioName + 'ScenarioPostStop'
			Try{
				If(!$global:BoundParameters.ContainsKey('Discard')){
					RunFunction $ScenarioPostStopFunc -ThrowException:$True
				}
			}Catch{
				LogWarn "Error happens in $ScenarioPostStopFunc. See error file $global:ErrorLogFile for detail."
				LogException ("An error happened in " + $ScenarioPostStopFunc) $_ $fLogFileOnly
			}
		}
	}ElseIf($Scenario.Count -ne 0){
		ForEach($ScenarioName in $Scenario){
			$ScenarioPostStopFunc = $ScenarioName + 'ScenarioPostStop'
			Try{
				If(!$global:BoundParameters.ContainsKey('Discard')){
					RunFunction $ScenarioPostStopFunc -ThrowException:$True
				}
			}Catch{
				LogWarn "Error happens in $ScenarioPostStopFunc. See error file $global:ErrorLogFile for detail."
				LogException ("An error happened in " + $ScenarioPostStopFunc) $_ $fLogFileOnly
			}
			$script:LogZipFileSuffixScn += -join ($ScenarioName , "_")
		}
	}

	# Collect eventlogs(#564)
	If($global:BoundParameters.ContainsKey('CollectEventLog')){
		ProcessCollectEventLog
	}

	# Copy memory.dmp if -Crash is specifed in previous run and memory.dmp exists.(#518)
	If($global:BoundParameters.ContainsKey('CollectDump')){
		FwCopyMemoryDump
	}

	If($global:BoundParameters.ContainsKey('ETLOptions') -and !($global:BoundParameters.ContainsKey('StartAutologger'))){ # allow -EtlOption circular:<EtlMaxSize> for autologger (#671)
		UnRegisterPurgeTask
	}

	# Remove script parameters in TSSv2RegKey.
	If(!$Script:IsCrashInProgress){
		RemoveParameterFromTSSv2Reg
	}

	# Run psSDP here.
	If(!$Script:fInRecovery -and ($global:ParameterArray -Contains 'SDP' -and !($global:ParameterArray -Contains 'noSDP')) -and (!$global:BoundParameters.ContainsKey('Discard')) ){
		processSDP
	}

	$Script:DataCollectionCompleted = $True
	# Originally enabled debug/analytic log is re-enabled here.
	FwResetAllEventLogs

	# Trigger crash if -Crash is specified.
	If($global:BoundParameters.ContainsKey('Crash') -and !$global:BoundParameters.ContainsKey('noCrash')){
		FwDoCrash
	}

	Write-Host ""
	#LogInfo ($StoppedTraceList.Count.ToString() + ' trace(s) are stopped.')
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

	# Remove script parameters in TSSv2 registry as no longer needed.
	RemoveParameterFromTSSv2Reg

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
				#$Token = $Scenario -split ','
				#ForEach($ScenarioName in $Token){
				#	$script:LogZipFileSuffix = $ScenarioName + '_'
				#}
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
		LogInfoFile "=========== End of TSSv2 Data collection: $TimeUTC UTC ==========="
		Close-Transcript -ShowMsg

		# 6. Records all errors in $Error variable.
		If($Error.Count -ne 0){
			$Error | Out-File -FilePath $global:ErrorVariableFile
		}

		If(!$global:BoundParameters.ContainsKey('Discard')){
			# 7. Finally, compress log folder here.
			If(!$Script:StopInError){
				$ZipFileName = [System.IO.Path]::GetFileName($zipDestinationPath)
				LogInfo "Compressing $global:LogFolder folder(zip=$ZipFileName). This might take a while."
				Start-Sleep -s 5 #give some time for logging to complete before starting zip
				Try{
					Add-Type -Assembly 'System.IO.Compression.FileSystem'
					[System.IO.Compression.ZipFile]::CreateFromDirectory($global:LogFolder, $zipDestinationPath)
				}Catch{
					$ErrorMessage = 'An exception happened during compressing log folder' + "`n" + $_.Exception.Message
					LogWarn $ErrorMessage
					LogInfo "Please compress $global:LogFolder manually and send it to MS workspace upload site."
					LogException $ErrorMessage $_ $fLogFileOnly
					Return # Return here to prevent the deletion of source folder that is performed later.
				}
			}Else{
				LogInfo "Skipping compressing folder as an error happened in stop."
			}

			# 8. In case of Remoting, copy zip file to file share.
			If((IsStart) -and $global:IsRemoting -and $global:BoundParameters.ContainsKey('RemoteLogFolder')){
				$RemoteLogFolder = $global:BoundParameters['RemoteLogFolder']
				LogInfo "Copying $zipDestinationPath to $RemoteLogFolder"
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
					Write-Host "==> Please send $zipDestinationPath to our upload site." -ForegroundColor Cyan
				}
			}ElseIf($Script:StopInError){
				LogWarn "ERROR(s) happened during stopping traces."
				LogInfo "==> Please send below log files to our upload site." "Cyan"
				LogInfo "	- All log files in $global:LogFolder"
				LogInfo "	- $global:TranscriptLogFile"
				LogInfo "	- $global:ErrorLogFile"
			}Else{
				LogInfo "==> Please send $zipDestinationPath to our MS upload site." "Cyan"
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
	}Else{
		If(!$global:BoundParameters.ContainsKey('Discard')){
			LogInfo "Logs were stored in $global:LogFolder"
			LogInfo "Please compress $global:LogFolder manually and send it to MS workspace upload site." "Cyan"
		}
		$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
		LogInfoFile "=========== End of TSSv2 Data collection: $TimeUTC UTC ==========="
	}
	Write-Host ""
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
	$i=0

	# Run data collection and diag function for normal trace switch
	ForEach($RequestedLog in $RequestedLogs){

		$ComponentLogCollectionFunc = 'Collect' + $RequestedLog + 'Log'
		$Commandobj = Get-Command $ComponentLogCollectionFunc -CommandType Function -ErrorAction Ignore # Ignore exception

		If($Commandobj -ne $Null){
			Try{
				$i++
				If(!$global:BoundParameters.ContainsKey('Discard')){
					LogInfo ("Calling log collection function($ComponentLogCollectionFunc)") "green"
					& $ComponentLogCollectionFunc
				}
			}Catch{
				LogWarn ("Exception happened in $ComponentLogCollectionFunc.")
				LogException ("An error happened in $ComponentLogCollectionFunc") $_ $fLogFileOnly
				Continue
			}
		}Else{
			Continue
		}

		$ComponentDidagFunc = 'Run' + $RequestedLog + 'Diag'
		$Commandobj = Get-Command $ComponentDidagFunc -ErrorAction Ignore
		If($Commandobj -ne $Null){
			Try{

				# Call a function for diagnosis
				LogInfo ("Calling diag function($ComponentDidagFunc)") "green"
				& $ComponentDidagFunc
			}Catch{
				LogWarn ("Exception happened in $ComponentDidagFunc.")
				LogException ("An error happened in $ComponentDidagFunc") $_ $fLogFileOnly
				Continue
			}
		}Else{
			Continue
		}
	LogInfoFile "======================== End of Collect =========================="
	}

	# Run data collection and diag function for scenario trace
	ForEach($RequestedLog in $RequestedLogs){

		$ScenarioDataCollectionFunc = 'Collect' + $RequestedLog + 'ScenarioLog'
		$Commandobj = Get-Command $ScenarioDataCollectionFunc -CommandType Function -ErrorAction Ignore # Ignore exception

		If($Commandobj -ne $Null){
			Try{
				$i++
				If(!$global:BoundParameters.ContainsKey('Discard')){
					LogInfo ("Calling log collection function($ScenarioDataCollectionFunc)") "green"
					& $ScenarioDataCollectionFunc
				}
			}Catch{
				LogWarn ("Exception happened in $ScenarioDataCollectionFunc.")
				LogException ("An error happened in $ScenarioDataCollectionFunc") $_ $fLogFileOnly
				Continue
			}
		}Else{
			Continue
		}

		$ScenarioDiagFunc = 'Run' + $RequestedLog + 'ScenarioDiag'
		$Commandobj = Get-Command $ScenarioDiagFunc -ErrorAction Ignore
		If($Commandobj -ne $Null){
			Try{
				# Call a function for diagnosis
				LogInfo ("Calling diag function($ScenarioDiagFunc)") "green"
				& $ScenarioDiagFunc
			}Catch{
				LogWarn ("Exception happened in $ScenarioDiagFunc.")
				LogException ("An error happened in $ScenarioDiagFunc") $_ $fLogFileOnly
				Continue
			}
		}Else{
			Continue
		}
	}

	ProcessBasicLog $Script:IsCommonTaskAlreadyRun
	
	# Collect additional eventlogs if -CollectEventLog.
	If($global:BoundParameters.ContainsKey('CollectEventLog')){
		ProcessCollectEventLog
	}

	# Run Xray #_# (always , as now [switch]$Xray = $True)
	#_# If($global:ParameterArray -contains 'Xray' -and $global:ParameterArray -notcontains 'noXray'){
	If($Xray.IsPresent -and (-not $noXray)){ #we#
		ProcessXray
	}

	# Run psSDP
	If($global:ParameterArray -contains 'SDP' -and $global:ParameterArray -notcontains 'noSDP'){
		ProcessSDP
	}

	If($i -eq 0){
		Write-Host ('Usage:')
		Write-Host ("  .\$ScriptName -CollectLog [ComponentName,ComponentName,...]")
		Write-Host ("  Example: .\$ScriptName -CollectLog UEX_AppX,UEX_Logon")
		Write-Host ""
		Write-Host ("Run .\$ScriptName -ListSupportedLog to see supported log name")
	}
	CompressLogIfNeededAndShow
	CleanUpandExit
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStartDiag{
	EnterFunc $MyInvocation.MyCommand.Name
	If([String]::IsNullOrEmpty($global:TssPhase)) { $global:TssPhase = "_Diag_" }
	LogInfoFile "======================== Start of Diag ========================"
	$Count = 0
	ForEach($RequestedComponent in $StartDiag){
		$FuncName = 'Run' + $RequestedComponent + 'Diag'
		$CommandObj = Get-Command $FuncName -ErrorAction Ignore
		If($CommandObj -ne $Null){
			Try{
				LogInfo ("Calling diag function($FuncName)") "green"
				& $FuncName  # Calling function for log collection.
				$Count++
			}Catch{
				LogException ("Exception happened in $FuncName.") $_
				Return
			}
		}Else{
			LogDebug ("Diag function for $RequestedComponent($FuncName) is not implemented yet.")
		}

		# Diag for scenario
		$FuncName = 'Run' + $RequestedComponent + 'ScenarioDiag'
		$CommandObj = Get-Command $FuncName -ErrorAction Ignore
		If($CommandObj -ne $Null){
			Try{
				LogInfo ("Calling diag function for scenario($FuncName)") "green"
				& $FuncName  # Calling function for log collection.
				$Count++
			}Catch{
				LogException ("Exception happened in $FuncName.") $_
				Return
			}
		}Else{
			LogDebug ("Diag function for $RequestedComponent($FuncName) is not implemented yet.")
		}
	}

	If($Count -eq 0){
		Write-Host ("Please check component name you want to diagnose by running with -ListSupportedDiag. Then Run '.\$ScriptName -StartDiag <ComponentName>' again.")
		Write-Host ("Example:")
		Write-Host ("PS> .\$ScriptName -ListSupportedDiag => Supported component name is listed.")
		Write-Host ("PS> .\$ScriptName -StartDiag <ComponentName>")
	}Else{
		#If($Xray.IsPresent -and !$noXray.IsPresent){ 
		If($Xray.IsPresent -and (-not $noXray)){ #we#
			ProcessXray
		}
		If($global:ParameterArray -contains 'SDP' -and $global:ParameterArray -notcontains 'noSDP'){
			ProcessSDP
		}
		CompressLogIfNeededAndShow
	}
	LogInfoFile "======================== End of Diag =========================="
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessTraceInfo{
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		RunPreparation # This creates global trace catalog
	}Catch{
		LogException "[ProcessTraceInfo] An exception happened in RunPreparation." $_
		CleanUpandExit
	}
	$TraceObjects = $Null
	Switch($TraceInfo){
		'all'{
			$TraceObjects = $GlobalTraceCatalog
		}
		'Command'{
			$TraceObjects = $GlobalTraceCatalog | Where-Object {$_.LogType -ne 'ETW'}
		}
		Default {
			# First, check if it is scenario name.
			$TracesInScenario = Get-Variable "$($TraceInfo)_ETWTracingSwitchesStatus" -ValueOnly -ErrorAction Ignore
			If($TracesInScenario -ne $Null){
				Write-Host "Scenario name:  $TraceInfo"
				Write-Host "  Trace switches:"
				ForEach($Key in $TracesInScenario.keys){
					Write-Host "	- $Key"
				}
				return
			}Else{
				$TraceObjects = $GlobalTraceCatalog | Where-Object {$_.Name -eq $TraceInfo}
			}
		}
	}
	If($TraceObjects -ne $Null){
		DumpTraceObject $TraceObjects
	}Else{
		Write-Host "Unable to find trace for `'$TraceInfo`'"
		Write-Host "Usage:"
		Write-Host "  .\$ScriptName -TraceInfo <ComponentName>|<ScenarioName>|all"
		Write-Host "   => Example: .\$ScriptName -TraceInfo ADS_BIO"
		Write-Host ""
		Write-Host "  .\$ScriptName -TraceInfo all	           // Show all trace info"
		Write-Host "  .\$ScriptName -TraceInfo <command>       // Show all trace info for Command, i.e. ProcDump"
		Write-Host "  .\$ScriptName -TraceInfo <ScenarioName>  // Show definition of scenario"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessFindKeyword{
	# calling ProcessHelp() with <keyword> or 0-9. Numbers 0-9 will invoke the corresponding Help-Menue items
	# It also works with regular expressions like "reg.*path"
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		ProcessHelp -SkipMenu -Ans $Find # This creates help-text files

	}Catch{
		LogException "[ProcessFindKeyword] An exception happened in ProcessHelp." $_
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessFindGUID{
	EnterFunc $MyInvocation.MyCommand.Name
	Try{
		RunPreparation # This creates global trace catalog
	}Catch{
		LogException "[ProcessFindGUID] An exception happened in RunPreparation." $_
		CleanUpandExit
	}
	$TraceObjectList = New-Object 'System.Collections.Generic.List[PSObject]'

	ForEach($TraceObject in $GlobalTraceCatalog){
		If($TraceObject.Providers -eq $Null){
			continue
		}
		ForEach($Provider in $TraceObject.Providers){
			If($Provider -match ".*$FindGUID.*"){
				$TraceObjectList.Add($TraceObject)
			}
		}
	}
	If($TraceObjectList.Count -ne 0){
		Write-Host "Below trace(s) contain `'$FindGUID`'."
		ForEach($TraceObject in $TraceObjectList){
			Write-Host "	- $($TraceObject.Name)"
		}
	}Else{
		Write-Host "No trace contains `'$FindGUID`'."
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
Function CheckVersion ($verCurrent){	
  if (( -Not $noVersionChk.IsPresent) -or ($global:ParameterArray -notcontains 'noVersionChk')){
	# automated version checking. When launched, the script will warn if a newer version is available online and recommend to download it. 
	# Internet access is required and the repository to be reachable, for the version check to be successful. It will not automatically download the new version; this will be up to the user to do.
	EnterFunc $MyInvocation.MyCommand.Name
	$TssReleaseServer = "cesdiagtools.blob.core.windows.net"
	Try{
		$checkConn = FwTestConnWebSite $TssReleaseServer # FwTestConnWebSite could throw an exception
	}Catch{
		$checkConn = $False
	}
	if ( $checkConn -eq "True") {
		try
			{
				$WebClient = New-Object System.Net.WebClient
				[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
				$verNew = $WebClient.DownloadString('https://cesdiagtools.blob.core.windows.net/windows/TSSv2.ver')
				$verNew = $verNew.TrimEnd([char]0x0a, [char]0x0d)
				[long] $lNew = VersionInt($verNew)
				[long] $lCur = VersionInt($verCurrent)
				if($lNew -gt $lCur) {
					LogWarn (" A newer version is available: v"+$verNew+" (you are currently on v"+$verCurrent+"). For best results, download and use the latest version from https://aka.ms/getTSS")
					$Script:fUpToDate = $False
					$Script:TssVerOnline = $lNew 
				}
				else {
					LogInfo  ("You are running the latest version (v"+$verCurrent+")") "green"
					$Script:fUpToDate = $True
				}
			}
		catch
			{
				LogWarn ("Unable to check TSSv2 script version online... (local version: v"+$verCurrent+")" + $_)
				LogInfo "For best results, always use the latest version from https://aka.ms/getTSS"
			}
	}
	Else{
		LogWarn ("Unable to contact MS tools store: $TssReleaseServer (local version: v" +$verCurrent+ ")")
		LogInfo "For best results, always use the latest version from https://aka.ms/getTSS"
	}
	EndFunc $MyInvocation.MyCommand.Name
  }
}

Function CreateStartCommandforBatch{
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateNotNullOrEmpty()]
		[System.Collections.Generic.List[PSObject]]$TraceObjectList
	)
	EnterFunc $MyInvocation.MyCommand.Name

	If($TraceObjectList -eq $Null){
		LogError"There is no trace in LogCollector."
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
		LogInfo "TSSv2 is running on Server Core and adjusting netsh parameters"
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

Function FixUpWPRProperty{
	EnterFunc $MyInvocation.MyCommand.Name

	#If($OperatingSystemInfo.OSVersion -eq 6){ #we# fails on Srv2012*

	If($OSBuild -lt 17763){ #we# OS -ge 17763 (RS5) has built in WPR. -skipPdbGen is supported with OS -ge 19041 (2004+); \BIN\wpr.exe is supported with OS -ge 9600 (2012-R2)

		$WPRProperty.CommandName = "$PSScriptRoot\BIN\wpr.exe"
		If(!(Test-path -path $WPRProperty.CommandName)){
			LogError "$($WPRProperty.CommandName) not found. Exiting script."
			CleanUpAndExit
		}
	}

	$WPR = $global:BoundParameters['WPR']
	$WPROptions = $global:BoundParameters['WPROptions']
	$WPRLogFile = "$global:LogFolder\$($LogPrefix)WPR_$WPR.etl"
	$WPRProperty.LogFileName = "`"$WPRLogFile`""

	LogDebug "Updating WPR option with `'$WPR`' profile"
	Switch($WPR) {
		'BootGeneral' {
			$WPRProperty.StartOption = "-start GeneralProfile -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -filemode -recordTempTo $global:LogFolder"
		}
		'general' {
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start DiskIO -start FileIO -Start Minifilter -Start Registry -start Network -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot DiskIO -addboot FileIO -addboot Minifilter -addboot Registry -addboot Network -filemode -recordTempTo $global:LogFolder"
		}
		'graphic' {
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -Start Registry -start Video -start GPU -Start DesktopComposition -start Power -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot Registry -addboot Video -addboot GPU -addboot DesktopComposition -addboot Power -filemode -recordTempTo $global:LogFolder"
		}
		'xaml' {
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start XAMLActivity -start XAMLAppResponsiveness -Start DesktopComposition -start Video -start GPU -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot XAMLActivity -addboot XAMLAppResponsiveness -addboot DesktopComposition -addboot Video -addboot GPU -filemode -recordTempTo $global:LogFolder"
		}
		'CPU' {
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -FileMode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -filemode -recordTempTo $global:LogFolder"
		}
		'memory' { 
			$WPRProperty.StartOption = "-start GeneralProfile -start VirtualAllocation -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot VirtualAllocation -filemode -recordTempTo $global:LogFolder"
		}
		'Registry' { 
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start Registry -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot Registry -filemode -recordTempTo $global:LogFolder"
		}
		'Storage' { 
			$WPRProperty.StartOption = "-start GeneralProfile  -start CPU -start DiskIO -start FileIO -start Minifilter -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot DiskIO -addboot FileIO -addboot Minifilter -filemode -recordTempTo $global:LogFolder"
		}
		'Wait' { 
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start DiskIO -start FileIO -start Network -start Minifilter -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot DiskIO -addboot FileIO -addboot Network -addboot Minifilter -filemode -recordTempTo $global:LogFolder"
		}
		'Network' { 
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start DiskIO -start FileIO -start Network -start Minifilter -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot DiskIO -addboot FileIO -addboot Network -addboot Minifilter -filemode -recordTempTo $global:LogFolder"
		}
		'SQL' { 
			$WPRProperty.StartOption = "-start GeneralProfile -start CPU -start VirtualAllocation -start Network -start Minifilter -filemode -recordTempTo $global:LogFolder"
			$WPRProperty.AutoLogger.AutoLoggerStartOption = "-BootTrace -addboot GeneralProfile -addboot CPU -addboot VirtualAllocation -addboot Network -addboot Minifilter -filemode -recordTempTo $global:LogFolder"
		}
		Default {
			ProcessListSupportedWPRScenario
			CleanUpandExit
		}
	}

	# If WPROptions is available, Just append option in $WPROptions to the tail end.
	If(![string]::IsNullOrEmpty($WPROptions)){ # Option from commmand line
		$WPRProperty.StartOption = $WPRProperty.StartOption + " " + $WPROptions
		$WPRProperty.AutoLogger.AutoLoggerStartOption = $WPRProperty.AutoLogger.AutoLoggerStartOption + " " + $WPROptions
	}

	If($global:ParameterArray -contains 'SkipPdbGen'){
		If($OSBuild -ge 19041){ # SkipPdbGen supports from Win10 2004
			$WPRProperty.StopOption = "-stop `"$WPRLogFile`" -skipPdbGen"
		}Else{
			LogInfo "-SkipPdbGen was specified but current OS does not support the option."
		}
	}Else{
		$WPRProperty.StopOption = "-stop `"$WPRLogFile`""
	}
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
		LogErrorFile "Procmon.exe not found."  # Procmon will be removed from LogCollector later. So just log it to log file.
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
		FwGetRegHives _Stop_
		LogInfo "=> Please check $global:ErrorLogFile" "Magenta"
		LogInfo "`nTo avoid this error, run TSSv2 again with appended switch -noPerfmon" "Cyan"
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

Function ProcessStart{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")

	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation # This creates GlobalTraceCatalog
		}Catch{
			LogException "[ProcessStart] An exception happened in RunPreparation" $_
			CleanUpandExit
		}
	}

	# At first we check if there are already running traces started by this script.
	$RunningTraces = $Null
	$RunningTraces = GetExistingTraceSession
	If($RunningTraces){
		LogWarn "Detected below existing trace(s)."
		ForEach($TraceObject in $RunningTraces){
			Write-Host "  - $($TraceObject.TraceName)"
		}
		Write-Host ""
		LogInfo "ERROR: Please stop above existing trace(s) with below command and then run again." "Red"
		Write-Host "=> .\$ScriptName -Stop -noBasiclog -noXray" -ForegroundColor "Yellow"
		CleanUpandExit

		#FwPlaySound
		#$Answer = FwRead-Host-YN -Message "Do you want to continue to start trace anyway?" -Choices "yn"
		#If(!$Answer){
		#	Write-Host "Stop existing traces with below command and then run again."
		#	Write-Host "=> .\$ScriptName -Stop" -ForegroundColor Yellow
		#	CleanUpandExit
		#}
	}

	# Checking trace and command switches and add them to LogCollector.
	ForEach($RequestedTraceName in $global:BoundParameters.Keys){
		If($ControlSwitches -Contains $RequestedTraceName){  # additional params, like EtlOptions should be added to $ControlSwitches
			Continue # This is not switch for trace.
		}

		If($RequestedTraceName -eq 'NetshScenario'){
			$RequestedTraceName = 'Netsh' # NetshScenario uses Netsh object. So replace the name.
		}
		If($StartAutoLogger.IsPresent){
			# Only AutoLogger supported traces are added to LogCollector
			If($RequestedTraceName.Contains('Scenario')){
				$TraceName = ConvertScenarioTraceNametoTraceName $RequestedTraceName
				If($TraceName -ne $Null){
					$AutoLoggerTraceObject = $GlobalTraceCatalog | Where-Object{($_.AutoLogger -ne $Null) -and ($TraceName -eq $_.Name)}
					If($AutoLoggerTraceObject -ne $Null){
						AddTraceToLogCollector $RequestedTraceName
					}
				}Else{
					LogError "Unable to convert to a trace from `'$RequestedTraceName`'"
					CleanUpandExit
				}
			}Else{ # Normal Trace
				$AutoLoggerTraceObject =  $GlobalTraceCatalog | Where-Object{$_.AutoLogger -ne $Null -and ($RequestedTraceName -eq $_.Name)}
				If($AutoLoggerTraceObject -ne $Null){ # This trace has AutoLogger
					AddTraceToLogCollector $RequestedTraceName
				}Else{
					LogDebug "Skipping adding $RequestedTraceName to LogCollector"
				}
			}
		}Else{
			# If not AutoLogger, just add all traces which are specified in option.
			AddTraceToLogCollector $RequestedTraceName
		}
	}

	# Change execution order based on 'Priority' in trace object
	$SortedLogCollector = $LogCollector | Sort-Object -Property StartPriority
	
	# Remove and add trace object to original $LogCollector with sorted order.
	ForEach($TraceObject in $SortedLogCollector){
		$LogCollector.Remove($TraceObject) | Out-Null
		$LogCollector.Add($TraceObject)
	}

	# Now we have $LogCollector and check if it meets the requirements
	If($global:ParameterArray -notcontains 'noPrereqC'){
		PreRequisiteCheckForStart
	}Else{
		LogInfo "Skipping PreRequisiteCheckForStart() as -noPrereqC was specified." "Gray"
	}

	# Store scenario name to TSSv2 registry in case of -StartNoWait/-StartAutoLogger
	If(($global:ParameterArray -contains 'StartNoWait' -or $global:ParameterArray -contains 'StartAutoLogger') -and ($Scenario.Count -ne 0)){
		ForEach($ScenarioName in $Scenario){
			$ScenarioString = $ScenarioName + ','
		}
		$ScenarioString = $ScenarioString -replace ",$",""

		If(!(Test-Path $global:TSSv2ParamRegKey)){
			RunCommands "ProcessStart" "New-Item -Path `"$global:TSSv2ParamRegKey`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$True  -ShowError:$True
		}
		$ValueName = 'Scenario'
		$RegValues = Get-ItemProperty -Path  $global:TSSv2ParamRegKey
		LogInfo "Saving scenario name(Scenario) to $global:TSSv2ParamRegKey\$ValueName"
		If($RegValues.$ValueName -ne $Null){ # Overwrite the value
			Set-ItemProperty -Path $global:TSSv2ParamRegKey -Name $ValueName -Value $ScenarioString
		}Else{
			New-ItemProperty -Path $global:TSSv2ParamRegKey -Name $ValueName -PropertyType String  -Value $ScenarioString | Out-Null
		}
	}

	If($DebugMode.IsPresent){
		LogDebug ("Pri TraceName")
		LogDebug ("--- -------------------------")
		ForEach($TraceObject in $LogCollector){
			LogDebug (" $($TraceObject.StartPriority)  $($TraceObject.TraceName)")
		}
		LogDebug ("--- -------------------------")
	}

	Write-Host "Processing below traces:"
	ForEach($TraceObject in $LogCollector){
		If($StartAutoLogger.IsPresent -and $TraceObject.LogType -eq 'ETW'){
			Write-Host ('	- ' + $TraceObject.AutoLogger.AutoLoggerSessionName + ' with ' + $TraceObject.Providers.Count + ' providers')
		}ElseIf($TraceObject.LogType -eq 'ETW'){	 
			Write-Host ('	- ' + $TraceObject.TraceName + ' with ' + $TraceObject.Providers.Count + ' providers')
		}ElseIf($TraceObject.Name -eq 'WPR'){
			Write-Host "	- $($TraceObject.TraceName)($($global:BoundParameters['WPR']))"
		}ElseIf($TraceObject.Name -eq 'PerfMon'){
			Write-Host "	- $($TraceObject.Name)($($global:BoundParameters['Perfmon']))"
		}ElseIf($TraceObject.Name -eq 'PerfMonLong'){
			Write-Host "	- $($TraceObject.Name)($($global:BoundParameters['PerfmonLong']))"
		}ElseIf($TraceObject.Name -eq 'Netsh'){
			If($global:ParameterArray -contains 'NetshScenario'){
				Write-Host "	- NetshScenario($($global:BoundParameters['NetshScenario']))"
			}Else{
				Write-Host "	- Netsh(Packet capture)"
			}
		}ElseIf($TraceObject.Name -eq 'Xperf'){
			Write-Host "	- $($TraceObject.Name)($($global:BoundParameters['Xperf']))"
		}Else{
			Write-Host ('	- ' + $TraceObject.TraceName)
		}
	}
	Write-Host ""
	If($DebugMode.IsPresent){
		DumpCollection $LogCollector
		Read-Host ("[DBG - hit ENTER to continue] (Before StartTraces) ==>")
	}

	Try{
		FwCreateLogFolder $global:LogFolder
	}Catch{
		LogException ("Unable to create $global:LogFolder.") $_
		CleanUpandExit
	}

	### 
	### Finally we can start tracing here
	### 
	Try{
		StartTraces
	}Catch{
		$Script:fInRecovery = $True
		LogException ('An error happened in StartTraces') $_
		LogWarn ('Starting recovery process...')

		# As some of detection functions rely on TSSv2 registry, we save script parameters to TSSv2 reg 
		# before running the detection functions called from GetExistingTraceSession.
		SaveParameterToTSSv2Reg

		$RunningTraces = GetExistingTraceSession
		If($RunningTraces.Count -ne 0){
			StopTraces $RunningTraces
			If($StartAutoLogger.IsPresent){
				Write-Host ('Deleting AutoLogger settings if exists...')
				RemoveAutoLogger
			}
		}Else{
			LogInfo "There are no running traces. Exiting.."
		}
		DisplayDataUploadRequestInError "An error(s) happened during starting traces."
		#If((!$Remote.IsPresent) -or !($global:IsServerCore)){ Explorer.exe $global:logfolder }
		CleanUpandExit
	}

	# In case of -EtlOptions, register tss_Purgelog.ps1 to task scheduler.
	If($global:BoundParameters.ContainsKey('EtlOptions') -and !($global:BoundParameters.ContainsKey('StartAutologger'))){ # allow -EtlOption circular:<EtlMaxSize> for autologger (#671)
		$Mode = ($EtlOptions -split ":")[0]
		If($Mode -eq 'newfile'){
			Try{
				RegisterPurgeTask
			}Catch{
				LogError "An error happend during registring purge task to task scheduler. ETL files will not be purged but continue to be captured."
				LogException "Error in RegisterPurgeTask" $_ $True
			}
		}
	}
	# -StartAutoLogger
	If($StartAutoLogger.IsPresent){
		ShowTraceResult $LogCollector 'Start' -fAutoLogger:$True
		LogInfo "The trace will be started from next boot. Run `'Restart-Computer`' to take the change effect."
		LogInfo "To stop datacollection after boot, run .\TSSv2.ps1 -Stop" "Cyan"
		If($ProcmonPath -ne $Null -and $ProcmonPath -ne ''){
			Write-Host ("==> Run `'" + ".\$ScriptName -Stop -ProcmonPath $ProcmonPath" + "`' to stop AutoLogger after next boot.") -ForegroundColor Yellow
		}
		SaveParameterToTSSv2Reg
		CleanUpandExit
	# -Start and -StartNoWait
	}ElseIf($StartNoWait.IsPresent){
		If($global:BoundParameters.ContainsKey('Crash') -and !$global:BoundParameters.ContainsKey('noCrash')) {LogWarn "** Will Force Crash at stop: see KB969028 https://support.microsoft.com/en-US/help/969028" "Cyan" }
		Write-Host ""
		Write-Host -ForegroundColor Cyan "Tracing has been started. You can now reproduce the issue and stop the trace by using -Stop switch."
		$StopMessage = "=> .\$ScriptName -Stop"
		If(![string]::IsNullOrEmpty($CommonTask)){
			$StopMessage = $StopMessage + " -CommonTask $CommonTask"
		}
		Write-Host $StopMessage -ForegroundColor Yellow
		# At the last, saving script parameters to TSSv2 registry
		SaveParameterToTSSv2Reg
		CleanUpandExit
	}
	# -Start
	Else{
		SaveParameterToTSSv2Reg
		If(!([string]::IsNullOrEmpty($WaitEvent)) -or $FwIsMonitoringEnabledByConfigFile){
			Try{
				WaitForMultipleEvents
				If($script:FWRuleArray.Count -ne 0){
					ForEach($FWRule in $script:FWRuleArray){
						LogInfo "Disabling Firewall rule($($FWRule.Displayname)) setting as TSSv2 enabled it temporary."
						$FWRule | Set-NetFirewallRule -Enabled False
					}
					$script:FWRuleArray = $Null
				}
				If($global:BoundParameters.ContainsKey('Crash') -and !$global:BoundParameters.ContainsKey('noCrash')){
					FwDoCrash
				}
			}Catch{
				$Script:fInRecovery = $True
				LogError 'An error happened in WaitForMultipleEvents'
				LogExceptionFile 'An error happened in WaitForMultipleEvents' $_
				LogWarn "Starting recovery process..."
				$RunningTraces = GetExistingTraceSession
				If($RunningTraces.Count -ne 0){
					StopTraces $RunningTraces
					If($StartAutoLogger.IsPresent){
						Write-Host ('Deleting AutoLogger settings if exists...')
						RemoveAutoLogger
					}
				}Else{
					LogInfo "There are no running traces. Exiting.."
				}
				DisplayDataUploadRequestInError "An exception happened during waiting for event to be signaled."
				#If((!$Remote.IsPresent) -or !($global:IsServerCore)){ Explorer.exe $global:Logfolder }
				CleanUpandExit
			}
		}Else{
			Write-Host ""
			FwPlaySound
			$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
			LogInfoFile "============= Start of Repro: $TimeUTC UTC ============"
			If($global:BoundParameters.ContainsKey('Crash') -and !$global:BoundParameters.ContainsKey('noCrash')) {LogWarn "** Will Force Crash at stop: see KB969028 https://support.microsoft.com/en-US/help/969028" "Cyan" }
			LogInfo	    "============= Start of Repro: $TimeUTC UTC ============" "Green"
			# Issue#373 - Tssv2 hang in ISE
			FwRead-Host-YN -Message "Reproduce the issue and enter 'Y' key AFTER finishing the repro (with window focus here)" -Choices 'y' | Out-Null  # no interest in answer
			#Read-Host('Reproduce the issue and enter RETURN key AFTER finishing the repro (with window focus here)')
			#CHOICE /C "y" /M "Reproduce the issue and enter 'Y' key AFTER finishing the repro (with window focus here) " 
			$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
			LogInfoFile "============= End of Repro:   $TimeUTC UTC ============"
			LogInfo	    "============= End of Repro:   $TimeUTC UTC ============" "Green"
		}
		StopTraces $LogCollector
		ShowTraceResult $LogCollector 'Stop' -fAutoLogger:$False
		CompressLogIfNeededAndShow
		CleanUpandExit
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStopAutoLogger{
	EnterFunc $MyInvocation.MyCommand.Name
	$script:StopAutologger = $True
	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")
	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation
		}Catch{
			LogException "[ProcessStopAutoLogger] An exception happened in RunPreparation" $_
			CleanUpandExit
		}
	}

	Try{
		FwCreateLogFolder $global:LogFolder
	}Catch{
		Write-Host ("Unable to create $global:Logfolder." + $_.Exception.Message)
		CleanUpandExit
	}

	Try{
		$RunningTraces = GetExistingTraceSession
		If($RunningTraces -eq $Null -or $RunningTraces.Count -eq 0){
			LogInfo "There are no running traces."
		}Else{
			StopTraces $RunningTraces
		}
		LogInfo "Deleting AutoLogger settings."
		RemoveAutoLogger
	}Catch{
		Write-Host ('ERROR: An exception happens in StopTraces: ' + $_.Exception.Message)
	}

	ProcessBasicLog $Script:IsCommonTaskAlreadyRun

	# Copy memory.dmp if -Crash is specifed in previous run and memory.dmp exists.(#518)
	If($global:BoundParameters.ContainsKey('CollectDump')){
		FwCopyMemoryDump
	}ElseIf($global:BoundParameters.ContainsKey('Crash')){
		FwCopyMemoryDump -DaysBack 2
	}

	# This the case where -StartAutoLogger is performed but -Stop is run without restart system. 
	# In this case, we don't show any result and simply exit.
	If($StoppedTraceList.Count -eq 0){
		CleanUpandExit 
	}

	ShowTraceResult $RunningTraces 'Stop' $True
	CompressLogIfNeededAndShow
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessBasicLog {
	param(
		[Parameter(Mandatory=$False)]
		$Script:IsCommonTaskAlreadyRun = $False
	)
	EnterFunc $MyInvocation.MyCommand.Name
	# Collect BasicLog or MiniBasicLog
	If($BasicLog.IsPresent){ 
		RunFunction "FwCollect_BasicLog" -ThrowException:$False
	}Else{ # This is default behavior. Will call mini basic log.
		If($global:ParameterArray -notcontains "noBasiclog" -and !$Script:IsCommonTaskAlreadyRun){ #we# fix for #457
			RunFunction "FwCollect_MiniBasicLog" -ThrowException:$False
		}Else{
			LogInfo "Collecting basic log is skipped as -NoBasicLog was specified or common task is already run." "Gray"
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessStop{
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug ("fPreparationCompleted is $script:fPreparationCompleted")
	If(!$script:fPreparationCompleted){
		Try{
			RunPreparation
		}Catch{
			LogException "[ProcessStop] An exception happened in RunPreparation" $_
			CleanUpandExit
		}
	}

	$EnabledAutoLoggerSessions = GetEnabledAutoLoggerSession
	If($EnabledAutoLoggerSessions -ne $Null){
		LogInfo "The following existing AutoLogger session was found:"
		ForEach($TraceObject in $EnabledAutoLoggerSessions){
			Write-Host ('	- ' + $TraceObject.AutoLogger.AutoLoggerSessionName)
		}
		Write-Host ""
		LogInfo "Stopping all autologger sessions."
		ProcessStopAutoLogger
		CleanUpandExit
	}

	$RunningTraces = GetExistingTraceSession
	If(($RunningTraces -ne $Null) -and ($RunningTraces.GetType()).Name -eq 'PSCustomObject'){
		$IsTraceObject = $True  # Case for $RunningTraces contaning single trace object
	}Else{
		$IsTraceObject = $False # Case for $RunningTraces contaning multiple trace objects
	}

	# Adding type 2 command manually since it is not a trace and cannot be detected. So add it manually.
	ForEach($Type2CommandSwitch in $Type2CommandSwitches){
		$Type2Command = $global:BoundParameters[$Type2CommandSwitch]
		If(![String]::IsNullOrEmpty($Type2Command) -and ($Type2Command -eq 'Both' -or $Type2Command -eq 'Stop')){
			$Type2CommandObject = $RunningTraces | Where-Object{$_.Name -eq $Type2CommandSwitch}
			If($Type2CommandObject -eq $Null){
				LogInfo "Adding $Type2CommandSwitch to list of running trace."
				$CommandObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq $Type2CommandSwitch}
				If($RunningTraces -eq $Null -or $IsTraceObject){
					$TraceObject = $RunningTraces
					$RunningTraces = New-Object 'System.Collections.Generic.List[Object]'
					If($IsTraceObject){
						$RunningTraces.Add($TraceObject)
					}
				}
				$RunningTraces.add($CommandObject)
			}
		}
	}

	If(($RunningTraces -ne $Null) -and ($RunningTraces.GetType()).Name -eq 'PSCustomObject'){
		$IsTraceObject = $True  # Case for $RunningTraces contaning single trace object
	}Else{
		$IsTraceObject = $False # Case for $RunningTraces contaning multiple trace objects
	}
	# Adding ProcDump manually since in case of ProcDump=stop + -StartNoWait, we cannot detect ProcDump and add it manually.
	If(![String]::IsNullOrEmpty($ProcDump) -and ($ProcDumpOption -eq 'Both' -or $ProcDumpOption -eq 'Stop')){
		$ProcDumpObject = $RunningTraces | Where-Object{$_.Name -eq 'ProcDump'}
		If($ProcDumpObject -eq $Null){
			LogInfo "Adding ProcDump to list of running trace."
			$ProcDumpObject = $GlobalTraceCatalog | Where-Object{$_.Name -eq 'ProcDump'}

			If($RunningTraces -eq $Null -or $IsTraceObject){
				$TraceObject = $RunningTraces
				$RunningTraces = New-Object 'System.Collections.Generic.List[Object]'
				If($IsTraceObject){
					$RunningTraces.Add($TraceObject)
				}
			}
			$RunningTraces.add($ProcDumpObject)
		}
	}

	If($RunningTraces -eq $Null){
		LogInfo "No traces are running. Exiting."
		# Copy memory.dmp if -Crash is specifed in previous run and memory.dmp exists.(#518)
		If($global:BoundParameters.ContainsKey('CollectDump')){
			FwCopyMemoryDump
			CompressLogIfNeededAndShow
		}ElseIf($global:BoundParameters.ContainsKey('Crash')){
			FwCopyMemoryDump -DaysBack 2
			CompressLogIfNeededAndShow
		}
		RemoveParameterFromTSSv2Reg
		CleanUpandExit
	}

	Try{
		FwCreateLogFolder $global:LogFolder
	}Catch{
		Write-Host ("Unable to create $global:Logfolder." + $_.Exception.Message)
		CleanUpandExit
	}

	Try{
		StopTraces $RunningTraces
	}Catch{
		LogError ('ERROR: An exception happened during stopping traces: ' + $_.Exception.Message)
	}
	ShowTraceResult $RunningTraces 'Stop' $False
	CompressLogIfNeededAndShow
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
			Write-Host ('	o .\TSSv2.ps1 -Set ' + $Key + '   /// ' + $SupportedSetOptions[$Key])
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
	LogDebug ("Calling $SetFuncName")
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
			Write-Host ('	o .\TSSv2.ps1 -Unset ' + $Key)
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
	LogDebug ("Calling $UnsetFuncName")
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
	# Checking trace and command switches and add them to LogCollector.
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
			# Only AutoLogger supported traces are added to LogCollector
			$AllAutoLoggerSupportedTraces =  $GlobalTraceCatalog | Where-Object{$_.AutoLogger -ne $Null}
			If($AllAutoLoggerSupportedTraces -eq $Null){
				Continue
			}
			$AutoLoggerSupportedTrace = $AllAutoLoggerSupportedTraces | Where-Object{$_.Name -eq $RequestedTraceName}
			If($AutoLoggerSupportedTrace -ne $Null){ # This trace has AutoLogger
				AddTraceToLogCollector $RequestedTraceName
			}
		}Else{
			# If not AutoLogger, just add all traces which are specified in option.
			AddTraceToLogCollector $RequestedTraceName
		}
	}
	
	# Check collection
	If($LogCollector.Count -eq 0){
		LogError ('LogCollector is null.')
		CleanUpandExit
	}

	CreateStartCommandforBatch $LogCollector
	CreateStopCommandforBatch $LogCollector
	LogInfo ("Batch file was created on $BatFileName.")
	If(!$StartAutoLogger.IsPresent){
		#If((!$Remote.IsPresent) -or !($global:IsServerCore)){ Explorer.exe $global:LogFolder }
	}Else{
		#If((!$Remote.IsPresent) -or !($global:IsServerCore)){ Explorer.exe $AutoLoggerLogFolder }
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedCommands{
	EnterFunc $MyInvocation.MyCommand.Name
	Write-Host "`nSUPPORTED COMMANDS"
	Write-Host "=============================="
	Write-Host 'The following COMMANDS are supported:'
	ForEach($Key in ($CommandSwitches.Keys | Sort -Unique)){
		 $HelpForCOMMANDS += ([String]::Format("[Commands]  -{0,-20}{1}`n", $Key, $CommandSwitches[$Key]))
	}
	If(!$noMore.IsPresent){
		Write-Output $HelpForCOMMANDS | more
	}Else{
		Write-Host $HelpForCOMMANDS
	}
	Write-Host "Please use '.\TSSv2.ps1 -Find <CommandName>' for a quick overview of each individual command."  -ForegroundColor "Yellow"
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedTrace{
	Param(
		[parameter(Mandatory=$False)]
		[String]$PODName="ALL",
		[Switch]$noMore
	)
	EnterFunc $MyInvocation.MyCommand.Name

$Section1 = @"

SUPPORTED COMPONENT TRACE
=========================
The following component traces are supported:`n
"@
	ForEach($Key in ($TraceSwitches.Keys | Sort)){
		If([String]::IsNullorEmpty($PODName) -or $PODName -eq "ALL"){
			$HelpForTrace += ([String]::Format("[Component]  -{0,-25}{1}`n", $Key, $TraceSwitches[$Key]))
		}Else{
			If($Key -like ($PODName + "_*")){
				$HelpForTrace += ([String]::Format("  -{0,-25}{1}`n", $Key, $TraceSwitches[$Key]))
			}
		}
	}
	# Show list of supported traces with paging by using native more command.
	$HelpForTrace = $Section1 + $HelpForTrace
	If(!$noMore.IsPresent){
		Write-Output $HelpForTrace | more
	}Else{
		Write-Host $HelpForTrace
	}

	#Write-Host ""
	Write-Host ('Usage:')
	Write-Host ('  .\TSSv2.ps1 -<ComponentName> -<ComponentName>...]')
	Write-Host ('  Example: .\TSSv2.ps1 -UEX_AppX -UEX_Logon') -ForegroundColor "Yellow"
	Write-Host ""
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedLog{
	Param(
		[parameter(Mandatory=$False)]
		[String]$PODName="ALL"
	)
	EnterFunc $MyInvocation.MyCommand.Name
	Write-Host "`nSUPPORTED COMPONENT LOG COLLECTION"
	Write-Host "=================================="
	Write-Host ("The following component Logs are supported for data collection:")
	$ScenarioCollectFunctions = @()
	$CollectFunctions = Get-Command "Collect*Log" -ErrorAction Ignore
	ForEach($CollectFunction in $CollectFunctions){
		$IsScenarioCollectFunction = $False
		If($PODName -ne "ALL"){
			If(!($CollectFunction.Name -like "Collect$PODName*")){
				Continue
			}
		}
		$ComponentName = $CollectFunction.Name -replace "^Collect",""
		$ComponentName = $ComponentName -replace "Log$",""
		If($ComponentName -like "*Scenario"){
			$ScenarioCollectFunctions += $ComponentName
			$IsScenarioCollectFunction = $True
		}Else{
			If($TraceSwitches.Contains($ComponentName)){
				Write-Host ([String]::Format("[-CollectLog]  {0,-25}- {1}", $ComponentName, $TraceSwitches[$ComponentName]))
			}Else{
				Write-Host ([String]::Format("[-CollectLog]  {0,-25}- no description", $ComponentName))
			}
		}
	}

	If($ScenarioCollectFunctions.Count -ne 0){
		Write-Host ("`nThe following scenarios are supported for data collection:")
		ForEach($ScenarioCollectFunction in $ScenarioCollectFunctions){
			$ScenarioCollectFunction = $ScenarioCollectFunction -replace "Scenario$",""
			Write-Host ([String]::Format("[-CollectLog]  {0,-25}- log for {0} scenario",$ScenarioCollectFunction))
		}
	}

	Write-Host ""
	Write-Host ('Usage:')
	Write-Host ('  .\TSSv2.ps1 -CollectLog [ComponentName,ComponentName,...]')
	Write-Host ('  Example: .\TSSv2.ps1 -CollectLog UEX_AppX,UEX_Logon') -ForegroundColor "Yellow"
	Write-Host ""
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedNetshScenario{
	EnterFunc $MyInvocation.MyCommand.Name
	# dbg/wpp scenarios:
	$SupportedNetshScenarios = Get-ChildItem 'HKLM:System\CurrentControlSet\Control\NetDiagFx\Microsoft\HostDLLs\WPPTrace\HelperClasses'
	# normal scenarios: #we# [waltere] added
	$SupportedNetshScenarios += Get-ChildItem 'HKLM:System\CurrentControlSet\Control\NetTrace\Scenarios'
	Write-Host "`nSUPPORTED NETSH SCENARIO TRACE"
	Write-Host "=============================="
	Write-Host "Supported scenarios for -NetshScnario are:"
	ForEach($SupportedNetshScenario in $SupportedNetshScenarios){
		Write-Host ("  - " + $SupportedNetshScenario.PSChildName)
	}
	Write-Host ""
	Write-Host "Usage:"
	Write-Host "  .\$ScriptName -NetshScenario <ScenarioName>"
	Write-Host "  Example: .\$ScriptName -NetshScenario InternetClient_dbg" -ForegroundColor "Yellow"
	Write-Host ""
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedNoOptions{
	EnterFunc $MyInvocation.MyCommand.Name
	Write-Host "`nSUPPORTED NoOPTIONS"
	Write-Host "==================="
	Write-Host "The following NoOPTIONS are supported:"
	ForEach($Key in ($NoOPTIONS.Keys | Sort)){
		 $HelpForNoOptions += ([String]::Format("[NoOptions]  -{0,-20}{1}`n", $Key, $NoOPTIONS[$Key]))
	}
	Write-Host $HelpForNoOptions
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedPerfCounter{
	param(
		[Parameter(Mandatory=$False)]
		[Switch]$AnswerYes	# True for building Help-Message
	)
	EnterFunc $MyInvocation.MyCommand.Name
	Write-Host "`nSUPPORTED PERFORMANCE MONITOR COUNTER"
	Write-Host "====================================="
	Write-Host "The following Performance counter set names are supported:"
	ForEach($key in ($SupportedPerfCounter.keys | Sort)){
		#we# Write-Host ("  - " + $key + ": " + $SupportedPerfCounter[$key])
		$HelpForPerfCounter += ([String]::Format("[PerfMon]  {0,-20}{1}`n", $Key, $SupportedPerfCounter[$Key]))
	}
	Write-Host $HelpForPerfCounter
	#Write-Host ""
	Write-Host ('Usage:')
	Write-Host ("  .\$ScriptName -PerfMon <CounterSetName>")
	Write-Host ("  Ex1: Start Performance Monitor with general counters (CPU, Memory, Disk and etc) with 5 seconds interval")
	Write-Host ("	   .\$ScriptName -PerfMon General -PerfIntervalSec 5") -ForegroundColor Yellow
	Write-Host ("  Ex2: Start Performance Monitor (Long) with SMB counters (SMB counters + general counters) with 11 minutes interval")
	Write-Host ("	   .\$ScriptName -PerfMonLong SMB -PerfLongIntervalMin 11") -ForegroundColor Yellow
	Write-Host ""

	if (!$AnswerYes){
		LogInfo "Do you want to see a detailed performance counter list for each counter set?" "Cyan"
		$Answer = FwRead-Host-YN -Message "Press Y for Yes, N for No (timeout=10s)" -Choices 'yn' -TimeOut 10 -Default N
		If($Answer){
			# Show detailed PerfMon counters only when -ListSupportedPerfCounter is specified.
			If($global:ParameterArray -contains "ListSupportedPerfCounter"){
				Write-Host ("Here is detailed performance counters for each counter set:")
				Write-Host ""
				ForEach($key in $SupportedPerfCounter.keys){
					Write-Host ("$key")
					Write-Host ("------------------------------")
					$PerfCounters = Get-Variable -Name ($key + "Counters") -ValueOnly
					ForEach($PerfCounter in $PerfCounters){
						Write-Host ($PerfCounter)
					}
					Write-Host ""
					Write-Host ""
				}
			}
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedDiag{
	Param(
		[parameter(Mandatory=$False)]
		[String]$PODName="ALL"
	)
	EnterFunc $MyInvocation.MyCommand.Name
	$ScenarioDiagFunctions = @()
	Write-Host "`nSUPPORTED COMPONENT TO DIAGNOSE"
	Write-Host "==============================="
	Write-Host ("Diag function for below components are supported:")
	$DiagFunctions = Get-Command "Run*Diag" -ErrorAction Ignore
	ForEach($DiagFunction in $DiagFunctions){
		If($PODName -ne "ALL"){
			If(!($DiagFunction.Name -like "Run$PODName*")){
				Continue
			}
		}
		$DiagFunctionName = $DiagFunction.Name -replace "^Run",""
		$DiagFunctionName = $DiagFunctionName -replace "Diag$",""
		If($DiagFunctionName -like "*Scenario"){
			$ScenarioDiagFunctions += $DiagFunctionName
		}Else{
			Write-Host ([String]::Format("[-StartDiag]   {0,-25}- Diagnostic module", $DiagFunctionName))
		}
	}

	If($ScenarioDiagFunctions.Count -ne 0){
		Write-Host ""
		Write-Host "Supported diag function for scenario trace:"
		ForEach($ScenarioDiagFunction in $ScenarioDiagFunctions){
			$ScenarioDiagFunction = $ScenarioDiagFunction -replace "Scenario$",""
			Write-Host ("	- $ScenarioDiagFunction")
		}
	}
	Write-Host ""
	Write-Host ('Usage:')
	Write-Host ("  .\$ScriptName -StartDiag [ComponentName,ComponentName,...]")
	Write-Host ("  Example: .\$ScriptName -StartDiag UEX_WinRM") -ForegroundColor "Yellow"
	Write-Host ""
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedScenarioTrace{
	Param(
		[parameter(Mandatory=$False)]
		[String]$PODName="ALL",
		[Switch]$noMore
	)
	EnterFunc $MyInvocation.MyCommand.Name
$Section1 = @"

SUPPORTED SCENARIO TRACE
========================
The following ScenarioNames are supported:`n
"@

	# 1. Gather all scenario traces.
	If([String]::IsNullorEmpty($PODName) -or $PODName -eq "ALL"){
		$ScenarioTraceArray = Get-Variable "*_ETWTracingSwitchesStatus" -ErrorAction Ignore
	}Else{
		$ScenarioTraceArray = Get-Variable ($PODName + "*_ETWTracingSwitchesStatus") -ErrorAction Ignore
	}

	# 2. If there is a decription for the scenario trace, display it. If not, dynamicall load list of traces and show them.
	$ScenarioDescription = $Null
	ForEach($ScenarioTrace in $ScenarioTraceArray){
		# Get a POD name and scenario name
		$Token = $ScenarioTrace.Name -split '_'
		$POD = $Token[0]
		$ScenarioName = ($ScenarioTrace.Name).replace("_ETWTracingSwitchesStatus","")

		# Check if the description for the scenario trace exists in POD scenario trace list(<POD>_ScenarioTraceList).
		$PODScenarioTraceList = Get-Variable ($POD + "_ScenarioTraceList") -ErrorAction Ignore
		If($PODScenarioTraceList -ne $Null){ # This a case <POD>_ScenarioTraceList exists.
			If(($PODScenarioTraceList.Value).Contains($ScenarioName)){
				#Write-Host "  $ScenarioName`t- collects $($PODScenarioTraceList.Value[$ScenarioName])."
				$ScenarioDescription = ($ScenarioDescription + ([String]::Format("  {0,-18} - collects {1}`n", $ScenarioName, $($PODScenarioTraceList.Value[$ScenarioName])))) 
				}
		}Else{ # This is a case <POD>_ScenarioTraceList does not exist. In this case, we show the description by using the scenario definition(XXX_ETWTracingSwitchesStatus).
			$TracesInScenario = $ScenarioTrace.Value  # This is hashtable.
			$OutputString = $Null
			ForEach($TraceInScenario in $TracesInScenario.keys){
				$OutputString = $OutputString + $TraceInScenario + ', '
			}
			$OutputString = $OutputString -replace ", $","" # Remove ', ' at the end of string.
			#we# $ScenarioDescription = $ScenarioDescription + "  $ScenarioName`t- collects $OutputString`n"
			$ScenarioDescription = $ScenarioDescription + ([String]::Format("  {0,-18} - collects {1}`n", $ScenarioName, $OutputString))
		}
	}
	$HelpForScenarioTrace = $Section1 + $ScenarioDescription
	If(!$noMore.IsPresent){
		Write-Output $HelpForScenarioTrace | more
	}Else{
		Write-Host $HelpForScenarioTrace
	}
	Write-Host "Usage:"
	Write-Host "  .\$ScriptName -Scenario <ScenarioName>"
	Write-Host "  Example: .\$ScriptName -Scenario ADS_Auth" -ForegroundColor Yellow
	Write-Host ""
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedSDP{
	EnterFunc $MyInvocation.MyCommand.Name
	Write-Host "`nSUPPORTED SDP (MSDT) report Options"
	Write-Host "==================================="
	Write-Host "Usage:"
	Write-Host "  .\$ScriptName -SDP <specialty> -SkipSDPList <comma-separated-params> "
	Write-Host "  Example: .\$ScriptName -SDP NET -SkipSDPList skipBPA,skipTS" -ForegroundColor Yellow
	Write-Host "   you can avoid some steps by using -SkipSDPList parameters (noNetadapters,skipBPA,skipHang,skipNetview,skipSddc,skipTS,skipHVreplica,skipCsvSMB)"
	Write-Host "   use a comma-separated list to combine more SDP reports.`n"

	Write-Host "The following SDP reports are supported:"
	ForEach($Key in ($SDPspecialties.Keys | sort)){
		 $HelpForSDPspec += ([String]::Format("[SDP]  -SDP {0,-20}{1}`n", $Key, $SDPspecialties[$Key]))
	}
	Write-Host $HelpForSDPspec
	Write-Host ""
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedWPRScenario{
	EnterFunc $MyInvocation.MyCommand.Name
	Write-Host "`nSUPPORTED WPR Options"
	Write-Host "====================="
	Write-Host "Usage:"
	Write-Host "  .\$ScriptName -WPR <WPRprofile> [-WPROptions <Option string> -SkipPdbGen]"
	Write-Host "  Example: .\$ScriptName -WPR General`n" -ForegroundColor Yellow
	
	Write-Host "The following WPR profiles are supported:"
	ForEach($Key in ($WPRprofiles.Keys | sort)){
		 $HelpForWPRprofiles += ([String]::Format("[WPR]  -WPR {0,-18} captures {1}`n", $Key, $WPRprofiles[$Key]))
	}
	Write-Host $HelpForWPRprofiles
	Write-Host ""
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessListSupportedXperfProfile{
	EnterFunc $MyInvocation.MyCommand.Name
	Write-Host "`nSUPPORTED Xperf Profile Options"
	Write-Host "==============================="
	Write-Host "Usage:"
	Write-Host "  .\$ScriptName -Xperf <Profile> [-XperfMaxFile <Size> -XperfOptions <Option string> -XperfPIDs <PID> -XperfTag <Pool Tag>]"
	Write-Host "  Example: .\$ScriptName -Xperf CPU`n" -ForegroundColor Yellow
	
	Write-Host "The following Xperf profiles are supported:"
	ForEach($Key in ($XperfProfiles.Keys | sort)){
		 $HelpForXperfProfiles += ([String]::Format("[Xperf]  -Xperf {0,-10} : {1}`n", $Key, $XperfProfiles[$Key]))
	}
	Write-Host $HelpForXperfProfiles
	Write-Host ""
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

Function ProcessSDP{
	EnterFunc $MyInvocation.MyCommand.Name

	$SkipSDPList = $global:BoundParameters['SkipSDPList']
	$SDP = $global:BoundParameters['SDP'] # $SDP is string array

	If(![String]::IsNullOrEmpty($SkipSDPList)){
		ForEach($SkipOption in $SkipSDPList){
			$SkipOptionSwitchs = $SkipOptionSwitchs + '-' + $SkipOption + ' '
		}
		LogInfo "SkipOptionSwitchs = $SkipOptionSwitchs"
	}

	If([String]::IsNullOrEmpty($SDP)){
		LogWarn "SDP tech was not passed to ProcessSDP(). Returning."
		Return
	}

	If(Test-Path -Path "$Scriptfolder\psSDP\Get-psSDP.ps1"){
		Try{
			If($EvtDaysBack -ne 0) {$EvtDaysSwitch="-EvtDaysBack $EvtDaysBack"} else {$EvtDaysSwitch=""}
			Write-Debug "____EvtDaysBack $EvtDaysBack - EvtDaysSwitch: $EvtDaysSwitch"
			ForEach($SDPtech in $SDP){
				LogInfo "[psSDP] SDP($SDPtech) starting..."
				If($Script:XrayCompleted -or $noXray.IsPresent){
					$psSDPcmd = ".\Get-psSDP.ps1 $SDPtech -skipXray -SkipEULA -skipQEdit -savePath $global:LogFolder $SkipOptionSwitchs $EvtDaysSwitch"
				}Else{
					$psSDPcmd = ".\Get-psSDP.ps1 $SDPtech -SkipEULA -skipQEdit -savePath $global:LogFolder $SkipOptionSwitchs $EvtDaysSwitch"
				}
				LogInfo "[psSDP] Running $psSDPcmd"
				Push-Location -Path "$Scriptfolder\psSDP"
				Invoke-Expression -Command $psSDPcmd
				Pop-Location 
			}
		}Catch{
			LogException "An Exception happend in Get-psSDP.ps1" $_
		}
		LogInfo "[psSDP] end of SDP data collection" "Gray"
		# Somehow after running psSDP, working directory is changed to log folder. So back to script root.
		cd $PSScriptRoot
	}Else{
		LogWarn "[psSDP] unable to find Get-psSDP.ps1. Skipping psSDP." "Gray"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function ProcessXray{
	EnterFunc $MyInvocation.MyCommand.Name
	If(Test-Path -Path "$Scriptfolder\xray\xray.ps1"){
		LogInfo "[xray] xray Diagnostics starting..."
		Push-Location -Path "$Scriptfolder\xray"
		Try{
			LogInfo "[xray] Running xray.ps1 -Area * -DataPath $global:LogFolder -AcceptEULA"
			.\xray.ps1 -Area * -DataPath $global:LogFolder -AcceptEULA
		}Catch{
			LogException "Exception happened in xray.ps1" $_
		}
		Pop-Location 
		LogInfo "[xray] xray Diagnostics completed"
		$Script:XrayCompleted = $True
	}Else{
		LogWarn "[xray] unable to find xray.ps1. Skipping xray." "Gray"
	}
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
		LogInfo "[update] TSSv2 update starting..." green
		Push-Location -Path ".\scripts"
		Try{
			.\tss_update-script.ps1 -tss_action update -UpdMode $UpdMode -verOnline $Script:TssVerOnline
		}Catch{
			LogException "Exception happened in tss_update-script.ps1" $_
		}
		Pop-Location 
		LogInfo "[update] TSSv2 update procedure completed." green
	}Else{
		LogWarn "[update] unable to find tss_update-script.ps1" "Gray"
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
		LogInfo "Config file (tss_config.cfg) exists but no parameter is configured." "Gray"
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

Function ReadParameterFromTSSv2Reg{
	EnterFunc $MyInvocation.MyCommand.Name
	If(!(Test-Path "$global:TSSv2ParamRegKey")){
		LogInfoFile "There are no parameter settings in TSSv2 registry."
		Return $Null
	}Else{
		If(!$Status.IsPresent){ # In case of -Status, we don't want to show this message to make console log simple.
			LogInfo "Reading parameters from TSSv2 registry."
		}
		
		$ParamArray = Get-Item "$global:TSSv2ParamRegKey" | Select-Object -ExpandProperty Property -ErrorAction Ignore
		$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
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

Function SaveParameterToTSSv2Reg{
	EnterFunc $MyInvocation.MyCommand.Name

	# Save parameter to TSSv2 registry
	ForEach($Key in $global:BoundParameters.Keys){
		If($Key -ne 'Start' -and $Key -ne 'StartAutoLogger' -and $Key -ne 'StartNoWait' -and  $Key -ne 'NewSession' -and $Key -ne 'DebugMode'){
			SaveToTSSv2Reg $Key $global:BoundParameters[$Key]
		}
	}
	SaveToTSSv2Reg 'LogFolder' $global:LogFolder
	EndFunc $MyInvocation.MyCommand.Name
}

Function RemoveParameterFromTSSv2Reg{
	EnterFunc $MyInvocation.MyCommand.Name

	# Delete parameters saved in TSSv2 registry
	If(Test-Path -Path $global:TSSv2ParamRegKey){
		LogInfo "Removing $global:TSSv2ParamRegKey" "Gray"
		Remove-Item $global:TSSv2ParamRegKey -Force
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
	EnterFunc "$($MyInvocation.MyCommand.Name) with $FuncName"

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

		LogInfo "Calling $FuncName $ParamString" "Green"
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

	# Issue#331 - Disallow starting more than one TSSv2 instance at the same time.
	If($global:ParameterArray -contains 'Start' -or $global:ParameterArray -contains 'StartAutoLogger' -or $global:ParameterArray -contains 'Stop' -or $global:ParameterArray -contains 'CollectLog' -or $global:ParameterArray -contains 'StartDiag'){
		$TSSv2Processes = Get-CimInstance Win32_Process | Where-Object {$_.Commandline -like "*TSSv2.ps1*-NewSession*"}
		If($TSSv2Processes -ne $Null){
			$MyPID = $PID  # $PID is built-in env value that has PID of this instance of PowerShell.exe.
			ForEach($TSSv2Process in $TSSv2Processes){
				If($MyPID -ne $TSSv2Process.ProcessId){
					LogInfo "ERROR: Currently another instance of TSSv2 is running with PID $($TSSv2Process.ProcessId)." "Red"
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
			LogError "TSSv2 script is outdated more than 30 days. Please -Update or download latest version: 'https://aka.ms/getTSS' or 'https://cesdiagtools.blob.core.windows.net/windows/TSSv2.zip'"
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
	 Make sure $LogCollector is not empty and number of traces to be started does not exceed system limitation which is currently 56 sessions.
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
			LogError "Setting log folder to under profile($LogFolderName) is not supported in case of -StartAutoLogger. Please specify somewhere other than profile(ex. -LogFolderName D:\MS_DATA)."
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

	# Running TSSv2 on x64 system with x86 powershell.exe may fail later.(#591)
	If (![Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem){
		LogError "Windows PowerShell Workflow is not supported in a Windows PowerShell x86-based console. Open a Windows PowerShell x64-based console, and then try again."
		CleanUpandExit
	}

	If($global:ParameterArray -contains 'PSR' -or $global:ParameterArray -contains 'Video' -and $global:ParameterArray -notcontains 'noRecording'){
		FwPlaySound
		LogInfo "Note for this step: If you do not agree on Recording, the solution for your issue might be delayed a lot, because MS support engineer needs to match the time (hh:mm:ss) of your problem (error message) exactly with the time stamps in debug data." "Magenta"
		LogInfo "[Action-Privacy] We need your consent to allow Problem Step Recording and-or Screen-Video recording, please answer Y or N" "Cyan"
		# Issue#373 - Tssv2 hang in ISE
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
			LogInfo "Removing -Video from parameter list and will continue without recording video." "Gray"
			$global:ParameterArray = RemoveItemFromArray $global:ParameterArray "Video"
			$TraceObject = $LogCollector | Where-Object {$_.Name -eq 'Video'}
			If($TraceObject -ne $Null){
				$LogCollector.Remove($TraceObject) | Out-Null
			}
		}
	}

	# See if external commands exist. If not, remove the command from LogCollector.
	$RemovedExternalCommandList = New-Object 'System.Collections.Generic.List[Object]'
	ForEach($ExternalCommand in $ExternalCommandList.Keys){
		If($global:BoundParameters.ContainsKey($ExternalCommand)){
			$Command = Get-Command $ExternalCommandList[$ExternalCommand] -ErrorAction Ignore
			If($Command -eq $Null){
				$global:ParameterArray = RemoveItemFromArray $global:ParameterArray $ExternalCommand
				$global:BoundParameters.Remove($ExternalCommand) | Out-Null
				$TraceObject = $LogCollector | Where-Object {$_.Name -eq $ExternalCommand}
				If($TraceObject -ne $Null){
					$LogCollector.Remove($TraceObject) | Out-Null
					$RemovedExternalCommandList.Add($ExternalCommand)
				}
			}
		}
	}

	If($RemovedExternalCommandList.count -gt 0){
		If($global:IsLiteMode){
			LogInfo "You are using Lite version of TSSv2. Below log(s) will be not collected." "Magenta"
			LogInfo "Please download full version of TSSv2 from 'https://aka.ms/getTSS' to collect all logs." "Magenta"
		}Else{
			LogInfo "Below command(s) does not exist. TSSv2 will not collect the log." "Magenta"
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
					LogInfo "Ex.: .\TSSv2.ps1 -Xperf Pool -XperfTag TcpE+AleE+AfdE+AfdX" "Yellow"
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

		# To see if sysmon was enabled by TSSv2, we check if 'Sysmon' service is running and also the 'sysmon' is stored in TSSv2 reg.
		$SysMonService = Get-Service -Name "SysMon" -ErrorAction Ignore

		If($SysMonService -ne $Null){
			$RegValues = Get-ItemProperty -Path  $global:TSSv2ParamRegKey -ErrorAction Ignore
			If($RegValues.SysMon -eq $Null){
				LogWarn "Detected running SysMon started from outside of TSSv2. TSSv2 will NOT restart and stop the running SysMon."
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
				# Remove SysMon from $LogCollector which is the list of traces to be collected.
				$TraceObject = $LogCollector | Where-Object {$_.Name -eq 'SysMon'}
				If($TraceObject -ne $Null){
					$LogCollector.Remove($TraceObject) | Out-Null
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
				Write-EventLog -ComputerName $RemoteHost -LogName 'System' -EntryType Info -Source "Eventlog" -EventId 1 -Message "Test event from TSSv2" -Category 1 -ErrorAction Stop
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

	# Check 1: Make sure $LogCollector is not empty.
	If($LogCollector.Count -eq 0){
		If($StartAutoLogger.IsPresent){
			LogInfo "ERROR: There are no traces that support AutoLogger in specified switch or scenario. Exiting." "Red"
		}Else{
			LogInfo 'ERROR: There are no traces to start. Please check switches you specified or scenario. Exiting.' "Red"
		}
		CleanUpandExit
	}

	# Check 2: Validate $LogCollector
	Try{
		ValidateCollection $LogCollector
	}Catch{
		LogException "An exception happened in ValidateCollection" $_
		CleanUpandExit
	}

	# Check 3: trace count. If it is more than 56 sessions, stop unnecessary sessions 
	#		  and see it gets less than 56. It is still over 56, show error and exit.
	If($LogCollector.count -ne 0){
		$ETWTracesObjectList = $LogCollector | Where-Object {$_.LogType -eq 'ETW'}
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

		$TSSv2TraceCount = $TraceList.Count

		# Add ETW session count for commands
		ForEach($Key in $ETWSessionCountForCommand.Keys){
			$CommandTraceObject = $Null
			$CommandTraceObject = $LogCollector | Where-Object {$_.Name -eq $Key}
			If($CommandTraceObject -ne $Null){
				LogDebug "3: Adding $Key with trace count ($($ETWSessionCountForCommand[$Key])) to TSSv2TraceCount"
				$TSSv2TraceCount += $ETWSessionCountForCommand[$Key]
			}
		}

		# Get number of existing trace sessions
		$MaxETWSessionCount = 56	#we# system wide max number of sessions 
		$RunningSessionList = $Null
		$RunningSessionList = GetETWSessionByLogman
		$SessionCount = $RunningSessionList.Count
		$TotalExpectedTraceCount = $SessionCount + $TSSv2TraceCount + 3	#we# +3, as Network scenarios often fail with error 1450 = ERROR_NO_SYSTEM_RESOURCES, as i.e. netsh needs an additional session
		LogInfoFile "No. of TSSv2 trace session=$TSSv2TraceCount / Existing sessions=$SessionCount"
		If($TotalExpectedTraceCount -gt $MaxETWSessionCount){
			LogInfo "Number of trace session ($TSSv2TraceCount for TSSv2 plus $SessionCount for existing sessions) will exceed system wide max number of session ($MaxETWSessionCount). Trying to stop unnessessary running ETW sessions."
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
			LogWarn "$DeletedTraceCount traces has been stopped to create room to run TSSv2. See `'Stopped-ETWSessionList.txt`' in $global:LogFolder to see stopped traces."

			# Double check if we have enough space to run etw trace by TSSv2.
			$RunningSessionList = $Null
			$RunningSessionList = GetETWSessionByLogman
			$SessionCount = $RunningSessionList.Count
			$TotalExpectedTraceCount = $SessionCount + $TSSv2TraceCount
			# If total number of session is still larger than $MaxETWSessionCount, show error message and exit.
			If($TotalExpectedTraceCount -gt $MaxETWSessionCount){
				LogError "Number of trace session($TSSv2TraceCount for TSSv2 and $SessionCount for existing sessions) will be $TotalExpectedTraceCount and it exceeds system total maximum number of session($MaxETWSessionCount)."
				Write-Host "Please try manually run $global:LogFolder\LogManStop.cmd from elevated commpand prompt to reduce running ETW sessions. And then run TSSv2 again."
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
					LogInfo ("Example: .\$ScriptName -Start -<TraceSwitch> -LogFolderName D:\MS_DATA") "Cyan"
					FwPlaySound
					# Issue#373 - Tssv2 hang in ISE
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
		LogDebug "Logcollector is empty."
		Return
	}

	# Check 5: Validate script folder name
	#if (($global:ScriptFolder -match '\s' ) -or ($global:ScriptFolder -match '[()]') ) {
	#	write-host -ForegroundColor red "TSS script path contains spaces or brackets or exclamation mark. Please rename/correct the TSS path: '$ScriptFolder'"
	#	CleanUpAndExit
	#}
	EndFunc $MyInvocation.MyCommand.Name
}

Function CalculateLogSize{
	[OutputType([Int])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name

	If($LogCollector.Count -eq 0){
		LogError "$LogCollector has not been initialized yet."
		Return $Null
	}

	# WPR
	If($global:BoundParameters.ContainsKey('WPR')){
		LogInfo "WARNING: WPR might consume large amount of free disk space if you run for long term. Use -Xperf instead in case you need to limit disk usage." "Magenta"
		LogInfo "Ex) .\TSSv2.ps1 -Xperf General -XperfMaxSize 10240  # Limit log size to 10GB"

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
	If($LogCollector.Count -ne 0){
		# 1. We caluculate size of all ETW traces. It is caluculated with 2GB per a trace.
		$ETWTraceObjects = $LogCollector | Where-Object {$_.LogType -eq 'ETW'}
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

Function ProcessHelp{
	Param(
		[parameter(Mandatory=$False)]
		[String]$Ans,		# passed by ProcessFindKeyword
		[Switch]$SkipMenu	# skip display Help/Menue - for switch -Find <keyword>
	)
	EnterFunc $MyInvocation.MyCommand.Name
$HelpMessage = @'

[Help] Starting traces (-Start)
-------------------------------
[Help] Public KB: https://docs.microsoft.com/en-us/troubleshoot/windows-client/windows-troubleshooters/introduction-to-troubleshootingscript-toolset-tssv2
[Help] The verb -Start will start ETW component trace(s) or support tools such as -WPR. 
[Help] The verb [-Start] is optional, but it could be replaced by complementary start options.
[Help] Complementary start verbs are: -StartAutoLogger, -StartDiag, -StartNoWait, -CollectLog
[Help] Logs related to the traces are also automatically collected when stopping the data collection.

[Help] => ETW trace components + Support tools + Data collection + Diag system

[Syntax] Syntax in this help:
-----------------------------
[Syntax]  <placeholder>	means the string in <angle brackets> for placeholder needs to be substituted with an actual ScenarioName, trace-component, command or value
[Syntax]  [optional]	the keyword/value in [square brackets] is optional, i.e. [module:int] means the module and interval are optional, default values are used if [<xx>:<yy>] are omitted.
[Syntax]  '|'           means 'or', choose one of the available options
[Syntax]  ':'           is the separator character between two values
[Syntax]   example:  -PerfMon [General:10] means PerfMon CounterSetName= 'General' and Interval= '10' seconds, when omitted, the defaults kick in, so -PerfMon has same effects as -PerfMon General -PerfIntervalSec 10
[Syntax]   example:  [-StopWaitTimeInSec <N>] means that the argument StopWaitTimeInSec is optional, but if specified then a value for <N> ='number of seconds' is mandatory

[ETW] ETW trace:
----------------
[ETW]       1. Enabling a scenario trace:
[ETW]         PS> .\TSSv2.ps1 -Scenario <ScenarioName>
[ETW]         * supported <ScenarioName>s are listed with 'TSSv2.ps1 -ListSupportedScenarioTrace'

[ETW]       2. Enabling component traces:
[ETW]         PS> .\TSSv2.ps1 <-ComponentName> <-ComponentName> ...
[ETW]         * supported <-ComponentName>s is listed with 'TSSv2.ps1 -ListSupportedTrace'

[ETW]       3. Starting traces with no wait mode (-Start -StartNoWait + -Stop):
[ETW]         [-Start]
[ETW]          PS> .\TSSv2.ps1 -StartNoWait -Scenario <ScenarioName> 
[ETW]          Note: prompt returns immediately so you can log off
[ETW]         [-Stop]
[ETW]          PS> .\TSSv2.ps1 -Stop

[Tools] Support tools:
----------------------
[Tools] Starting support tools/commands (ProcMon, ProcDump, netsh, Performance Monitor (PerfMon), WPR, etc.)
[Tools] PS> .\TSSv2.ps -WPR <WPRprofile> -Procmon -Netsh|-NetshScenario <NetshScenario> -PerfMon <CounterSetName> -ProcDump <PID> -PktMon -SysMon -SDP <specialty> -Xray -PSR -Video -TTD <PID[]|ProcessName[]|ServiceName[]>

[Commands] COMMANDS
-------------------
[Commands]  -Fiddler                    - collect Fiddler trace 
[Fiddler]	  Enable the traffic decryption option by clicking Tools > Options > Tab: HTTPS > and ticking the [x] 'Decrypt HTTPS Traffic' box.
[Commands]  -GPresult <Start|Stop|Both> - Collect gpresult, auditing and security info on start, stop or both.
[Commands]  -Handle <Start|Stop|Both>   - Collect SysInternals Handle.exe output on phase start, stop or both.
[Commands]  -LiveKD <Start|Stop|Both>   - start SysInternals LiveKD -ml (live kernel dump). Start: the dump is taken on start. Stop: the dump is taken on stop. Both: the dump is taken on both start and stop.
[Commands]  -Netsh                      - start network packet capturing
[Netsh]	      + -NetshOptions '<Option string>' - specify additional options for Netsh, i.e. 'capturetype=both captureMultilayer=yes provider=Microsoft-Windows-PrimaryNetworkIcon provider={1701C7DC-045C-45C0-8CD6-4D42E3BBF387}'
[Netsh]       + -NetshMaxSize           - max log size for netsh in MB (Ex.: -NetshMaxSize 4096), default=2048
[Commands]  -NetshScenario <ScenarioName[]>  - start netsh scenario trace. Supported <ScenarioName>s are listed with -ListSupportedNetshScenario
[NetshScenario] + -NoPacket             - prevent packets from being captured (only ETW traces in the ScenarioName will be captured)
[NetshScenario]	+ -NetshOptions '<Option string>' - specify additional options for NetshScenario, i.e. 'capturetype=both captureMultilayer=yes provider=Microsoft-Windows-PrimaryNetworkIcon provider={1701C7DC-045C-45C0-8CD6-4D42E3BBF387}'
[NetshScenario] + -NetshMaxSize         - max log size for netsh in MB (Ex.: -NetshMaxSize 4096), default=2048
[Commands]  -PerfMon <CounterSetName> [-PerfIntervalSec N] - start Performance Monitor log, (default PerfIntervalSec=10). <CounterSetName>s can be listed with -ListSupportedPerfCounter
[PerfMon]     + -PerfIntervalSec <Interval in sec> - set interval for the PerfMon log(default is 10 seconds)
[Commands]  -PerfMonLong <CounterSetName> [-PerfLongIntervalMin N] - start Performance Monitor log, (default PerfLongIntervalMin=10). <CounterSetName>s can be listed with -ListSupportedPerfCounter
[PerfMon]     + -PerfLongIntervalMin <Interval in min> - set interval for the PerfMonLong log(default is 10 minutes)
[Commands]  -PktMon                     - collect Packet Monitoring data (on RS5+ / Srv2019), PktMon:Drop will collect only dropped packets
[Commands]  -PoolMon <Start|Stop|Both>  - Collect PoolMon on start, stop or both.
[Commands]  -ProcDump <PID[]|ProcessName[]|ServiceName[]> - capture user dump(s) of single item or comma separated list of items using SysInternals ProcDump.exe. By default, the dump is taken on start and stop. Enter ProcessName(s) with .exe extension; 
[ProcDump]    you can change the timing and interval by specifying below -ProcDumpOption and -ProcDumpInterval
[ProcDump]    + -ProcDumpOption <Start|Stop|Both>  - Start: the dump is taken on start. Stop: the dump is taken on stop. Both (default): the dump is taken on both start and stop.
[ProcDump]    + -ProcDumpInterval <N>:<Interval in sec> - Use this option when the dump needs to be captured repeatedly. N: =number of dumps, Int: =Interval in seconds; default=3:10
[ProcDump]     Example: -ProcDump mstsc.exe,4321,TokenBroker,TermService -ProcDumpOption Stop -ProcDumpInterval 5:60
[Commands]  -ProcMon                    - start SysInternals Procmon.exe
[Procmon]     + -ProcmonPath <folder path to Procmon.exe> - specify a path to Procmon.exe(by default, TSSv2 uses built-in Procmon)
[Procmon]     + -ProcmonFilter <filter file> - specify a config file for Procmon(ex. ProcmonConfiguration.pmc) located in \config folder
[Commands]  -PSR- start PSR(Problem Steps Recorder)
[Commands]  -RASDiag                    - collect trace: Netsh Ras diagnostics set trace enable
[Commands]  -SDP <SpecialityName[]>     - collect SDP(Support Diagnostic Package) for the specified speciality
[SDP]         + -SkipSDPList "<xxx>","<yyy>" - comma separated list of skipping modul names for SDP
[SDP]          => <SpecialityName>: "Apps","CTS","Cluster","DA","Dom","DPM","HyperV","Net","Perf","Print","RDS","S2D","SCCM","Setup","SQLbase","SQLconn","SQLmsdtc","SQLsetup","SUVP","VSS","mini","nano","Repro","RFL","All"
[SDP]          => Skip List: "noNetadapters","skipBPA","skipHang","skipNetview","skipSddc","skipTS","skipHVreplica","skipCsvSMB"
[Commands]  -SysMon                     - collect SysInternals System Monitor (SysMon) log [def: sysmonConfig.xml in 'config' folder]
[Commands]  -TTD <PID[]|ProcessName[]|ServiceName[]> - start TTD (TTT/iDNA) with default= -Full mode; Enter ProcessName(s) with .exe
[TTD]         Note: downlevel OS before Win10 RS2 will require the TSSv2_TTD.zip package
[TTD]         + -TTDPath <Folder path to tttracer.exe> - specify folder path containing tttracer.exe (PartnerTTD)
[TTD]         + -TTDMode <Full|Ring|onLaunch> - Full = -dumpfull, Ring = ring buffer mode, onLaunch = -onLaunch; default if omitted = -Full
[TTD]         + -TTDMaxFile <size in MB> - Max log file size
[TTD]         + -TTDOptions <String of TTD options> - use this option if you want to put any additional options for TTD (TTT/iDNA)
[Commands]  -Video                      - start video capturing (requires .NET 3.5 installed)
[Commands]  -WFPDiag                    - collect trace: netsh Wfp capture
[Commands]  -WireShark                  - start WireShark. Below parameters are configurable through tss_config.cfg file.
[WireShark]    WS_IF:                   Used for -i; Specify interface number (ex. _WS_IF=1)
[WireShark]    WS_Filter:               Used for -f; Filter for the interface (ex. _WS_Filter="port 443")
[WireShark]    WS_Snaplen:              Used for -s; Limit the amount of data for each frame. This is better performance and helpful for high load situation. (ex. _WS_Snaplen=128)
[WireShark]    WS_TraceBufferSizeInMB:  Used for -b FileSize (multiplied by 1024); Switch to next file after NUM MB. (ex. _WS_TraceBufferSizeInMB=512; default=512MB)
[WireShark]    WS_PurgeNrFilesToKeep:   Used for -b files; Replace after NUM files. (ex. _WS_PurgeNrFilesToKeep=20)
[WireShark]    WS_Options:              Any other options for -i; (ex. _WS_Options="-P")
[WireShark]   Example: for collecting WireShark on interface 15 and 11, input when TSSv2 prompts for a interface number: 15 -i 11 
[WireShark]   By default Wireshark starts dumpcap.exe  -i <all NICs> -B 1024 -n -t -w _WireShark-packetcapture.pcap -b files:10 -b filesize:524288
[Commands]  -WPR <WPRprofile>           - start a WPR profile trace. <WPRprofile> is one of 'BootGeneral|General|CPU|Memory|Registry|Storage|Wait|Network|SQL|Graphic|Xaml'
[WPR]         + -SkipPdbGen             - Skip generating symbol files(PDB files)
[WPR]         + -WPROptions <Option string> - specify options for WPR.exe, i.e.: -WPROptions '-onoffproblemdescription "test description"'
[WPR]           Ex1: .\TSSv2.ps1 -StartAutoLogger -WPR BootGeneral -WPROptions '-addboot CPU' - will cature WPR boot trace with profile General+CPU
[WPR]           Ex2: .\TSSv2.ps1 -WPR BootGeneral -WPROptions '-Start CPU -start Network -start Minifilter' - will combine profile General+CPU+Network+Minifilter
[Commands]  -Xperf <Profile>            - start Xperf. <Profile> is one of 'CPU|General|Disk|Memory|Network|Pool|PoolNPP|Registry|SMB2|SBSL|SBSLboot|Leak'
[Xperf]       + -XperfMaxFile <Size>    - Specify max log size in MB(default 2048MB)
[Xperf]       + -XperfTag <Pool Tag>    - Specify PoolTag to be logged. This is used with 'Pool' or 'PoolNPP' profile. (ex. -Xperf Pool -XperfTag TcpE+AleE+AfdE+AfdX)
[Xperf]       + -XperfPIDs <PID>        - Specify ProcessID. This is used with 'Leak' profile. (ex. -Xperf Leak -XperfPIDs <PID>)
[Xperf]       + -XperfOptions <Option string> - Specify other option string for Xperf
[Commands]  -Xray                       - start Xray to diagnose a system for known issues

[Controls] CONTROLS
-------------------
[Controls]  -AcceptEula     - do not ask at first run to accept Disclaimer (useful for -Remote execution)
[Controls]  -AddDescription <description> - add a brief description of the issue to zip file name
[Controls]  -BasicLog       - collect full basic log (by default mini basic log is always collected)
[Controls]  -CollectComponentLog - use with -Scenario. By default, component collect functions are not called in case of scenario trace. This switch enables the collect functions to be called.
[Controls]  -CollectDump    - collect a system dump after stopping all traces. -CollectDump can be used with -Start and -Stop.
[Controls]  -CollectEventLog <Eventlog[]>    - collect specified event logs. Wild card can be used for the event log name.
[CollectEventLog] Ex.: -CollectEventLog Security,*Cred*"  # collect security and all event logs that matches *Cred* like 'Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational'
[Controls]  -CommonTask <<POD>|Full|Mini> - run common tasks before starting and after stopping trace
[CommonTask]     <POD> : currently only 'NET' is available, is collected before starting and after stopping trace
[CommonTask]     Full  : full basic log is collected after stopping trace
[CommonTask]     Mini  : mini basic log is collected after stopping trace
[Controls]  -Crash          - trigger system crash on stop, or after all events are signaled in case used with -WaitEvent, Caution: this switch will force a memory.dump, open files won't save.
[Controls]  -CustomETL      - add custom ETL trace provider(s), ex: .\TSSv2.ps1 -WIN_CustomETL -CustomETL '{CBDA4DBF-8D5D-4F69-9578-BE14AA540D22}','Microsoft-Windows-PrimaryNetworkIcon' (comma separated list of single quoted '{GUID}' and/or 'Provider-Name')
[Controls]  -DebugMode      - run with debug mode for a developer
[Controls]  -Discard        - used to discard a dataset at phase -Stop. *Stop- or *Collect-functions will not run. Xray and psSDP will be skipped.
[Controls]  -EnableCOMDebug - used by UEX module to turn on COM debug mode
[Controls]  -ETLOptions circular|newfile:<ETLMaxSize>:<ETLNumberToKeep>  - set options passed to logman command, default for circular ETLMaxSize=1024, default for newfile ETLMaxSize=512, -StartAutologger only supports -ETLOptions circular:<ETLMaxSize>
[ETLOptions]  Ex.1: -ETLOptions newfile:2048:5  # run newfile logs with size of 2048 MB, keep only last 5 *.etl files; defaults for circular mode: circular:1024, for newfile mode: newfile:512:10 
[ETLOptions]  Ex.2: -StartAutologger  -ETLOptions circular:4096 (Autologger will not obey :<ETLNumberToKeep> and it only accepts mode circular)
[Controls]  -EvtDaysBack <N> - Convert Eventlogs only for last N days; default: 30 days; also applies to SDP report; Note: Security Eventlog will be skipped
[Controls]  -ExternalScript <path to external PS file> - run the specified PowerShell script before starting trace
[Controls]  -LogFolderName <Drive:\path to log folder> - use the log folder instead of default location (C:\MS_DATA)
[Controls]  -Mini           - collect only minimal data, skip noPSR, noSDP, noVideo, noXray, noZip, noBasicLog
[Controls]  -Mode <Basic|Advanced|Full|Verbose|Hang|Restart|Swarm|Kube|GetFarmdata|NFSperm|traceMS>  - [for data collection] run script in Basic, Advanced, Full or Verbose mode. Restart will restart associated service.
[Controls]  -Remote         - use when TSS is being executed on a remote host, i.e. via psExec or in PS Azure Serial Console; this will inhibit PSR and Video recording, starting TssClock and opening Explorer with final results. In such case also consider -AcceptEula
[Controls]  -StartNoWait    - do not wait and prompt will return immediately, this is useful for the scenario where a user needs to log off
[Controls]  -WaitEvent      - monitor for the specified event/stop-trigger and if it is signaled, traces will be stopped automatically
[WaitEvent]   run '.\TSSv2.ps1 -Find Monitoring' to see the usage
[Controls]  -Update         - update TSSv2, can be used together with -UpdMode Online|Quick|Full|Force|Lite
[Update]      + -UpdMode <Online|Quick|Full|Force|Lite>  - 'Online' (=default) or 'Full' will download full package, 'Quick' will do a differential update, 'Force' will force update even latest version seems installed

[NoOptions] NoOPTIONs:
----------------------
[NoOptions]  Any given Command in predefined scenarios can be suppressed by specifying a corresponding no* option
[NoOptions]  To list all no* Options, run .\TSSv2.ps1 -ListSupportedNoOptions

[CollectLog] Starting a data collection (-CollectLog)
=====================================================
[CollectLog] If there is no need to capture Component traces and only data collection and/or system diagnosis need to be performed, use this option (-CollectLog).
[CollectLog] => Run data collection + system diagnostics

[CollectLog] PS> .\TSSv2.ps1 -CollectLog <ComponentName[]>
[CollectLog] * supported <ComponentName>s are listed with 'TSSv2.ps1 -ListSupportedLog'

[CollectLog] CONTROLS accepted:
[CollectLog]   -AcceptEula  - do not ask at first run to accept Disclaimer
[CollectLog]   -LogFolderName <Drive:\path to log folder>  - use the log folder instead of default location (C:\MS_DATA)
[CollectLog]   -DebugMode   - run with debug mode for a developer
[CollectLog]   -CollectEventLog <EventLog[]>   - collect event log. Run '.\TSSV2.ps1 -Find CollectEventLog' for detail.

[CollectEventLog] Starting event log collection (-CollectEventLog)
==================================================================
[CollectEventLog] Collect specified event log. Wild card can be used for the event log name.

[CollectEventLog] PS> .\TSSv2.ps1 -CollectEventLog <EventLog[]>
[CollectEventLog] Ex.: -CollectEventLog Security   # collect only security log
[CollectEventLog] Ex.: -CollectEventLog Security,*Cred*"  # collect security and all event logs that matches *Cred* like 'Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational'

[CollectEventLog] CONTROLS accepted:
[CollectEventLog]   -AcceptEula  - do not ask at first run to accept Disclaimer
[CollectEventLog]   -LogFolderName <Drive:\path to log folder>  - use the log folder instead of default location (C:\MS_DATA)
[CollectEventLog]   -DebugMode   - run with debug mode for a developer

[SDP] Starting SDP (-SDP)
=========================
[SDP] If there is no need to capture Component traces and only SDP needs to be run, use this option (-SDP). 
[SDP] -SDP can also be used with -Start, -CollectLog and -StartDiag.

[SDP] 1. Starting SDP
[SDP]    PS> .\TSSv2.ps1 -SDP <SpecialityName[]>
[SDP]    ex1) .\TSSv2.ps1 -SDP RDS
[SDP]    ex2) .\TSSv2.ps1 -SDP RDS,Setup
[SDP]    => SDP SpecialityName: Apps|CTS|Cluster|DA|Dom|DPM|HyperV|Net|Perf|Print|RDS|S2D|SCCM|Setup|SQLbase|SQLconn|SQLmsdtc|SQLsetup|SUVP|VSS|mini|nano|Repro|RFL|All

[SDP] CONTROLS accepted:
[SDP]    -SkipSDPList <SkipSDPList[]> - comma separated list of skipping stages in SDP report
[SDP]     Example: .\TSSv2.ps1 -SDP RDS -SkipSDPList skipBPA,skipTS
[SDP]      => Skip List SDP: noNetadapters|skipBPA|skipHang|skipNetview|skipSddc|skipTS|skipHVreplica|skipCsvSMB
[SDP]    -AcceptEula      - do not ask at first run to accept Disclaimer
[SDP]    -EvtDaysBack <N> - Convert Eventlogs only for last N days
[SDP]    -LogFolderName <Drive:\path to log folder>  - use the log folder instead of default location(C:\MS_DATA)
[SDP]    -StartNoWait     - do not wait and prompt will return immediately, this is useful for the scenario where a user needs to log off
[SDP]    -BasicLog        - collect full basic log (by default mini basic log is always collected)

[SDP] 2. Starting SDP with -StartNoWait
[SDP]    With -StartNoWait at start of data collection, use -SDP when stopping trace (i.e. use TSSv2 -Stop -SDP)
[SDP]    PS> .\TSSv2.ps1 -StartNoWait -<ComponentName>
[SDP]    PS> .\TSSv2.ps1 -Stop -SDP <SpecialityName>

[SDP] 3. Starting SDP with AutoLogger (persistent/boot) scenario
[SDP]    Like same as -StartNoWait, use -SDP when stopping trace in case of AutoLogger.
[SDP]    PS> .\TSSv2.ps1 -StartAutoLogger -<ComponentName>
[SDP]    PS> Restart-Computer
[SDP]    PS> .\TSSv2.ps1 -Stop -SDP <SpecialityName>

[StartDiag] Running a system diagnose (-StartDiag)
==================================================
[StartDiag] If there is no need to capture Component traces and collect data, but want to diagnose system, use this option.
[StartDiag] => Run system diagnostics only

[StartDiag] PS> .\TSSv2.ps1 -StartDiag <ComponentName[]> [-InputlogPath <path to log folder for diagnostic>]
[StartDiag]  * supported <ComponentName>s are listed with 'TSSv2.ps1 -ListSupportedDiag'

[StartDiag] CONTROLS accepted:
[StartDiag]   -AcceptEula     - do not ask at first run to accept Disclaimer
[StartDiag]   -DebugMode      - run with debug mode for a developer
[StartDiag]   -InputlogPath <path to log folder for diagnostic> - specify a log path to be diagnosed
[StartDiag]   -LogFolderName <Drive:\path to log folder>  - use the log folder instead of default location(C:\MS_DATA)

[StartAutoLogger] Setting AutoLogger (-StartAutoLogger)
=======================================================
[StartAutoLogger] -StartAutoLogger enables AutoLogger that is a feature to start capturing traces from early boot timing. 
[StartAutoLogger] This is helpful when the issue happens on the early stage of boot.

[StartAutoLogger] 1. Enable a scenario trace + support tools with AutoLogger and stop the traces
[StartAutoLogger]    PS> .\TSSv2.ps1 -StartAutoLogger -Scenario <ScenarioName> -WPR <WPRprofile> -Procmon -Netsh|-NetshScenario <NetshScenario>
[StartAutoLogger]    PS> Restart-Computer          # to start traces from boot time
[StartAutoLogger]    PS> .\TSSv2.ps1 -Stop  # This stops all running traces and deletes AutoLogger settings

[StartAutoLogger] 2. Enable component traces + support tools with AutoLogger
[StartAutoLogger]    PS> .\TSSv2.ps1 -StartAutoLogger <-ComponentName> <-ComponentName> ...  -WPR <WPRprofile> -Procmon -Netsh|-NetshScenario <NetshScenario>
[StartAutoLogger]    PS> Restart-Computer          # to start traces from boot time
[StartAutoLogger]    PS> .\TSSv2.ps1 -Stop  # This stops all running traces and deletes AutoLogger settings

[StartAutoLogger] CONTROLS accepted:
[StartAutoLogger]   -AcceptEula     - do not ask at first run to accept Disclaimer
[StartAutoLogger]   -DebugMode      - run with debug mode for a developer
[StartAutoLogger]   -LogFolderName <Drive:\path to log folder>  - use the log folder instead of default location(C:\MS_DATA)

[RemoveAutoLogger] Deleting AutoLogger settings (-RemoveAutoLogger)
===================================================================
[RemoveAutoLogger] Delete AutoLogger settings. This option can be used when AutoLogger is enabled but want to discard the setting.
[RemoveAutoLogger]    PS> .\TSSv2.ps1 -RemoveAutoLogger

[Status] Showing trace status (-Status)
=======================================
[Status] You can show what traces/tools are running and also this shows what AutoLoggers are enabled on the system.
[Status] PS> .\TSSv2.ps1 -Status

[Help] Displaying help message (-Help)
======================================
[Help] 1. Show the version of TSSv2
[Help]    PS> .\TSSv2.ps1 -version

[Help] 2. Show interactive help message menue
[Help]    PS> .\TSSv2.ps1 -Help
[Help]    Hint: use numbers 0-9 or keyword search for quick help

[Help] 3. List available parameters for each trace / scenario
[Help]    List available options for all or each technology area:
[Help]     PS> .\TSSv2.ps1 -List
[Help]    List available commands / support tools:
[Help]     PS> .\TSSv2.ps1 -ListSupportedCommands 
[Help]    List available components for Diag feature (-StartDiag):
[Help]     PS> .\TSSv2.ps1 -ListSupportedDiag
[Help]    List available components for data collection (-CollectLog):
[Help]     PS> .\TSSv2.ps1 -ListSupportedLog
[Help]    List available options for -NetshScenario switch (Netsh trace scenario=):
[Help]     PS> .\TSSv2.ps1 -ListSupportedNetshScenario
[Help]    List available noOPTIONS:
[Help]     PS> .\TSSv2.ps1 -ListSupportedNoOptions
[Help]    List available performance counter set for -PerfMon and -PerfMonLong:
[Help]     PS> .\TSSv2.ps1 -ListSupportedPerfCounter
[Help]    List available predefined scenario traces:
[Help]     PS> .\TSSv2.ps1 -ListSupportedScenarioTrace
[Help]    List available specialty SDP reports:
[Help]     PS> .\TSSv2.ps1 -ListSupportedSDP
[Help]    List available components for ETW traces:
[Help]     PS> .\TSSv2.ps1 -ListSupportedTrace
[Help]    List available options/profiles for -WPR (Windows Performance Recorder):
[Help]     PS> .\TSSv2.ps1 -ListSupportedWPRScenario
[Help]    List available profiles for -Xperf:
[Help]     PS> .\TSSv2.ps1 -ListSupportedXperfProfile

[Help] 4. Show trace info for components (with providers) or scenarios
[Help]    PS> .\TSSv2.ps1 -TraceInfo <ComponentName>|<ScenarioName>|all
[Help]    * supported <ComponentName>s are listed with 'TSSv2.ps1 -ListSupportedTrace'
[Help]    * supported <ScenarioName>s are listed with 'TSSv2.ps1 -ListSupportedScenarioTrace'

[Help] 5. Find component names that have a passed GUID 
[Help]    PS> .\TSSv2.ps1 -FindGUID <GUID>
[Help]    Ex.: .\TSSv2.ps1 -FindGUID 1234  -- this will show trace name that contains a provider GUID with substring '1234'

[Help] 6. Search and find a keyword or RegEx in TSS help texts
[Help]    PS> .\TSSv2.ps1 -Find <keyword>
[Help]     Ex.: .\TSSv2.ps1 -Find syntax    -- this will show all lines in TSS help which contain the keyword 'syntax'
[Help]    It also finds terms with regular expressions like in keyword 'reg.*path'; this would find i.e. terms 'Registry Path' or 'RegKeyPath'
   
[Help] Help on unexpected PowerShell errors
===========================================
[Help] - run this command after a failure: .\TSSv2.ps1 -Stop 
[Help] - close open elevated PS window and start a new elevated PS window
[Help] - allow PS scripts running on your system with proper ExecutionPolicy
[Help]    If you encounter an error that running scripts is disabled, try 
[Help]    Method#1
[Help]      Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -force -Scope Process
[Help]    and verify with 'Get-ExecutionPolicy -List' that no ExecutionPolicy with higher precedence is blocking execution of this script.
[Help]    Then run ".\TSSv2.ps1 <with desired parameters>" again.

[Help]    Alternate Method#2a: if scripts are blocked by MachinePolicy, run in elevated PowerShell: 
[Help]      Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name ExecutionPolicy -Value RemoteSigned
[Help]      Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell -Name EnableScripts  -Value 1 -Type DWord
[Help]    Alternate Method#2b: if scripts are blocked by UserPolicy, run in elevated PowerShell: 
[Help]      Set-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name ExecutionPolicy -Value RemoteSigned
[Help]      Set-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -Name EnableScripts  -Value 1 -Type DWord
     
[Help]    Note, Method#2a is only a workaround for Policy "MachinePolicy - RemoteSigned", if you also see "UserPolicy - RemoteSigned", please ask the domain admin for temporary GPO exemption.
[Help]    In rare situations you could try -ExecutionPolicy Bypass

[Help] Help on LiteMode
=======================
[TssLite] In case you have downloaded TSS LiteMode package, some external commands will not be collected.
[TssLite] This affects all SysInternals utilities (Handle/ProcMon/ProcDump/SysMon/etc.)

[TSSv1] Help on TSSv1 to TSSv2 translations (FAQ)
=================================================
[TSSv1] TSS <scenario-Name>                  - .\TSSv2.ps1 -Scenario NET_<scenario-Name>
[TSSv1] TSS <module-Name>                    - .\TSSv2.ps1 -NET_<component-Name>
[TSSv1] TSS rOn <xxx>                        - .\TSSv2.ps1 -Start -NET_<component-Name>
[TSSv1] TSS <scenario or module> noWait      - .\TSSv2.ps1 -StartNowait <scenario or component>
[TSSv1] TSS <scenario or module> persistent  - .\TSSv2.ps1 -StartAutologger <scenario or component>
[TSSv1] TSS SDP:Net:skipBPA/skipTS           - .\TSSv2.ps1 -SDP Net -SkipSDPList skipBPA,skipTS
[TSSv1] TSS iDNA:<PID>|name>[:<maxF>]        - .\TSSv2.ps1 -TTD <PID[]|ProcessName[]|ServiceName[]> -TTDMaxFile <size in MB>; note: TTSSv2_TTD.zip is only needed for downlevel OS prior to Win10/Server 2019
[TSSv1] TSS <xxx> Stop:<Evt|Log|ps1|Time>:.. - .\TSSv2.ps1 <xxx> -WaitEvent <Evt|Log|PortLoc|PortDest|Svc|Process|Share|SMB|HTTP|RDP|WINRM|LDAP|RegData|RegValue|RegKey|File|Time|HNSL2Tunnel|LogFile|StopCondition>:.. (see 8 Monitoring)
[TSSv1] TSS <xxx> Stop:Time[:<min>]          - .\TSSv2.ps1 <xxx> -WaitEvent Time:<N>:Sec for wait time in seconds, or -WaitEvent Time:<N> for wait time in minutes
[TSSv1] TSS <xxx> ETLmax:<N>[:<NrKeep>]      - .\TSSv2.ps1 <xxx> -EtlOptions circular|newfile:<ETLMaxSize>:<ETLNumberToKeep>

[TSSv1] see also KB https://internal.support.services.microsoft.com/en-us/help/5011690 WinX: FastStart / Quick Reference: TSSv2 commands for TSS (v1) users 
[TSSv1] Hint: for CX ready email template, see KB https://internal.support.services.microsoft.com/en-us/help/5011695 

[Help] Help on starting TSS remotely, using PowerShell remoting (PSremoting)
============================================================================
[PSremoting] If you want to start a remote PowerShell session (or use Sysinternals PsExec) and run TSS commands silently there, please try the following approach; remmember to append -AcceptEula for a very first remote execution in your user context:
[PSremoting] Prerequisite: expand TSSv2.zip package on remote computer i.e. on C:\TSSv2
[PSremoting]   $RemoteComputer = "Server11"
[PSremoting]   New-PSSession -ComputerName $RemoteComputer
[PSremoting]   Enter-PSSession -ComputerName $RemoteComputer
[PSremoting]   cd C:\TSSv2
[PSremoting]   .\TSSv2.ps1 -SDP NET -AcceptEula -Remote

[FAQ] Frequently asked Questions (see also public TSSv2 KB)
===========================================================
[FAQ] Issue cannot be repro'd when TSS runs?
[FAQ]  TSSv2 basically only actively modifies some settings for troubleshooting purpose (at start, and resets them at stop):
[FAQ]   - starts a NetSH trace, so the NIC driver will be set to promiscuous mode
[FAQ]   - it runs on a server with RemoteAccess service enabled: "netsh interface ipv4 set global multicastforwarding=Disable|Enable"
[FAQ]   - clears all caches (NetBios, DNS, Kerberos, DFS) at start time, unless -noClearCache is specified
[FAQ]   - some scenarios activate additional EventLogs (and de-activate at stop)
[FAQ]   - enables ETW tracing and debug logging, this could change timing

[FAQ] Video recording *.wvm in TSS:
[FAQ]  If your resulting VideoRepro.wmv file covers only part of the screen, while recording plz. decrease screen 'Display settings -> Display resolution' to a standard setting.
'@

$HelpMessageForMonitoring = @'

[Monitoring] Monitoring feature (-WaitEvent)
============================================
[Monitoring] TSSv2 has a feature to monitor lots of events such as an event in Windows event log, shutdown of network port, creation/deletion of file and registry, and so on. Once the event is signaled, traces will be stopped automatically in time.
[Monitoring] If commandline contains -WaitEvent, the system will also monitor for the stop trigger 'System Event ID 999' 

[Monitoring] This feature is helpful when you can't reproduce the issue intentionally or immediately and need to wait for next occurrence. 
[Monitoring] In such case, this feature allows the script to wait for the repro event and stop traces automatically once the expected event happens (no manual human intervention needed).

[Monitoring] After all events are signaled, if you want to wait an addional amount of seconds before stopping traces, use '-StopWaitTimeInSec <N>' to create an addional delay at Stop.
[Monitoring] Note: Whenever item names include a space character, you need to enclose name in single quotes: '<item name>' 

[Monitoring] The monitoring is enabled by -WaitEvent switch. Please see below usage for detail of [Evt|PortLoc|PortDest|Svc|Process|Share|SMB|HTTP|RDP|WINRM|LDAP|RegData|RegValue|RegKey|File|Time|HNSL2Tunnel|LogFile|StopCondition], where <xxx> means any -<ComponentName>, -Scenario <ScenarioName>, -<ToolName>.

[Monitoring] 1. [Evt] Wait and stop traces when an event ID is recorded, optional with CheckIntInSec, StopWaitTimeInSec, StopEventData (Text or ErrorCode), EvtDataPartial (True|False), EvtDataOperator (OR|AND)
[Monitoring]    Separate multiple EventIDs with '/', Ex.: 30800/30809; <StopEventData> can be a string of slash (/) separated data
[Monitoring]    [Syntax]  Eventlog Names that include a space need to be enclosed in single quotes '...'
[Monitoring]    [Control] -MaxEvents <N> will investigate last N number of events with same EventID (default=1)
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent Evt:<EventID>:'<Eventlog Name>'[:<CheckIntInSec>:<StopWaitTimeInSec>:<StopEventData>:<EvtDataPartial True|False>:<OR|AND>] [-MaxEvents <N>]
[Monitoring]     Ex1: .\TSSv2.ps1 -Scenario ADS_ACCOUNTLOCKOUT -WaitEvent Evt:4625:'Security':5:0:user1/user2:True:OR => monitors for partial string 'user1' OR 'user2' in Security EventID 4625
[Monitoring]     Ex2: .\TSSv2.ps1 -Scenario NET_NCSI -WaitEvent Evt:4042:'Microsoft-Windows-NCSI/Operational':0:0:ActiveHttpProbeFailedButDnsSucceeded:True => monitors for partial string 'ActiveHttpProbeFailedButDnsSucceeded' in EventID 4042 

[Monitoring] 2. [PortLoc] Wait for a local network port to be closed
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent PortLoc:<Port number> [-StopWaitTimeInSec <N>]

[Monitoring] 3. [PortDest] Wait for a remote (not local) network port to be closed
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent PortDest:<RemoteHost>:<Port number> [-StopWaitTimeInSec <N>]

[Monitoring] 4. [Svc] Wait for a windows service to be stopped or crashed
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent Svc:<Service name> [-StopWaitTimeInSec <N>]

[Monitoring] 5. [Process] Wait for a process to be stopped or crashed
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent Process:<Process name without extension .exe> [-StopWaitTimeInSec <N>]

[Monitoring] 6. [Share] Wait for a remote share to become inaccessible
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent Share:<ServerName>:<ShareName> [-StopWaitTimeInSec <N>]

[Monitoring] 7. [SMB|HTTP|RDP|WINRM] Wait for a common network port to be closed
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent <SMB|HTTP|RDP|WINRM>:<RemoteHost> [-StopWaitTimeInSec <N>]

[Monitoring] 8. [LDAP] Wait for a domain controller to be inaccessible
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent LDAP:<Domain name> [-StopWaitTimeInSec <N>]

[Monitoring] 9. [RegData] Wait for the creation of registry data entry, or a change FROM (with :True) or TO (with [:False] = default) a specific data entry <ExpectedData>
[Monitoring]    Monitor for registry data change inTO a specific data entry <ExpectedData>
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent RegData:<RegKeyPath>:<RegValueName>:<ExpectedData> [-StopWaitTimeInSec <N>]
[Monitoring]    Monitor for registry data change FROM a specific data entry <ExpectedData> into any other value
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent RegData:<RegKeyPath>:<RegValueName>:<ExpectedData>:True [-StopWaitTimeInSec <N>]
[Monitoring]     Ex: .\TSSv2.ps1 -Start <xxx> -WaitEvent RegData:HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters:TcpTimedWaitDelay:0x1E 
[Monitoring]        will be signaled, once new data turns TO ExpectedData 0x1E; if you append as last parameter :True, then you monitor until actual data is no more 0x1E (ExpectedData)

[Monitoring]   Syntax for monitoring Registry items in 9.[RegData], 10.[RegValue], 11.[RegKey]
[Monitoring]    [Syntax]  registry path <RegKeyPath>          example: 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters'
[Monitoring]    [Syntax]  registry name <RegValueName>        example: TcpTimedWaitDelay
[Monitoring]    [Syntax]  registry data entry <ExpectedData>  example: 0x1E
[Monitoring]    [Syntax]  the last parameter can be set to :True = opposite behaviour; (no last parameter means default= :False)
[Monitoring]    [Syntax]  registry roots can be               HKLM:, HKCU: or HKCR:
[Monitoring]    [Syntax]  registry paths or names that include a space need to be enclosed in single quotes '...'
  
[Monitoring] 10. [RegValue] Wait for the creation(:True)/removal([:False]) of registry value name
[Monitoring]    Monitor a registry value name to be created under <RegKeyPath>
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent RegValue:<RegKeyPath>:<RegValueName>:True [-StopWaitTimeInSec <N>]
[Monitoring]    Monitor a registry value name to be deleted under <RegKeyPath>
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent RegValue:<RegKeyPath>:<RegValueName> [-StopWaitTimeInSec <N>]
[Monitoring]     Ex: .\TSSv2.ps1 -Start <xxx> -WaitEvent RegValue:HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters:TcpTimedWaitDelay
[Monitoring]        will be signaled, 

[Monitoring] 11. [RegKey] Wait for the creation(:True)/removal([:False]) of registry key path
[Monitoring]    Monitor a registry key <RegKeyPath> to be created:
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent RegKey:<RegKeyPath>:True [-StopWaitTimeInSec <N>]
[Monitoring]    Monitor a registry key <RegKeyPath> to be deleted:
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent RegKey:<RegKeyPath> [-StopWaitTimeInSec <N>]

[Monitoring] 12. [File] Wait for a creation or deletion of a specified '<FilePath>' 
[Monitoring]    Monitor a new File to be created:
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent File:'<FilePath>':True [-StopWaitTimeInSec <N>]
[Monitoring]    Monitor an existing File to be deleted:
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent File:'<FilePath>' [-StopWaitTimeInSec <N>]
[Monitoring]    Example: .\TSSv2.ps1 -Start -ADS_Kerb -WaitEvent File:'C:\temp\TestMe.txt'
   
[Monitoring] 13. [Time] Wait for time elapsed event
[Monitoring]    Wait until N minutes elapsed:
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent Time:<N>       => we wait N minutes and then stop data collection
[Monitoring]    Wait until N seconds elapsed:
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent Time:<N>:Sec   => we wait N seconds and then stop data collection

[Monitoring] 14. [HNSL2Tunnel] Wait for HNS L2Tunnel Network is gone (Get-HNSNetwork)
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent HNSL2Tunnel [-StopWaitTimeInSec <N>]

[Monitoring] 15. [LogFile] Wait for specific message/error-string 'search-string' in LogFile 'Path\LogfileName.ext'; 'search-string' could be a Regular Expression, such as 'Access.*Denied' (including 'Access Denied' 'Access is Denied')
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent LogFile:'<Path\LogfileName.ext>':'<search-string>' [-StopWaitTimeInSec <N>]
[Monitoring]     Ex: .\TSSv2.ps1 -Start <xxx> -WaitEvent LogFile:'C:\AppFolder\MyLogfileName.log':'Access.*Denied'

[Monitoring] 16. [StopCondition] wait for a customizable stop condition to become $True
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent StopCondition [-StopWaitTimeInSec <N>]
[Monitoring]     The customizable stop condition needs to be defined in \config\StopCondition.txt file. Please see instructions and some example inside the StopCondition.txt file

[Monitoring] 17. Wait for an event and trigger forced memory dump/crash after the event is signaled.
[Monitoring]     PS> .\TSSv2.ps1 -Start <xxx> -WaitEvent <xxx> -Crash

[Monitoring] See also:
[Monitoring] URL: https://microsoft.githubenterprise.com/css-windows/WindowsCSSToolsDevRep/wiki/Using-event-monitoring
[Monitoring] or section 'Monitoring' in internal KB https://internal.support.services.microsoft.com/en-us/help/4619187

[Remoting] Remoting (-RemoteHosts)
==================================
[Remoting] You can also use the monitoring feature (-WaitEvent) on multiple remote hosts together with remoting feature -RemoteHosts (to be started on 'failing' system). 
[Remoting] Remoting is helpful when you collect data on a system using monitoring and want to wait until a stop condition is met. 
[Remoting] In this case, after the stop condition is met, remoting feature sends signal (event ID 999) to all remote hosts. And then, all running traces on the remote hosts are stopped automatically without user interaction.

[Remoting] Remoting can be enabled 1. from command line or 2. through config file (tss_config.cfg).
[Remoting] Note: Command-line parameters take precedence over config params.

[Remoting] 1. Enable remoting from command line on system which is expected to observe Event ID 1000
[Remoting]   To enable remoting, use -RemoteHosts switch to specify remote hosts that traces will be started.
[Remoting]   You can also specify a remote share folder (RemoteLogfolder) where log files are copied to, after stopping trace. 
[Remoting]    -RemoteLogfolder is helpful if the number of remote hosts is large and you want to centralize log folder.

[Remoting]  -RemoteHosts <host01,host02>           - specify comma separated list of remote hosts that will be signaled after a stop condition is met.
[Remoting]  -RemoteLogfolder "<\\Server01\share>"  - remote share folder name where log files of all remote hosts to be copied.

[Remoting]   Example:
[Remoting]    Run below command on all remote hosts (cluster01, cluster02 and cluster03 in this example)
[Remoting]     PS> .\TSSv2.ps1 -SHA_MsCluster -WaitEvent StopEvt:1000:System -RemoteHosts cluster01,cluster02,cluster03 -RemoteLogfolder "\\cluster01\share"
[Remoting]   Note: besides the Event 1000, a remoting enabled system is also listening on System Event ID 999. This ID basically instructs remote system to stop data-collection. The system that experiences actual ID 1000 will send StopTrigger ID 999 to all other systems.

[Remoting] 2. Enable remoting through config file
[Remoting]    a.) Edit 'tss_config.cfg' in TSSv2 '\config\' folder and add below lines. Also copy your 'tss_config.cfg' file to TSSv2 '\config\' folder on all remote hosts.

[Remoting]      _EnableRemoting=y
[Remoting]      _WriteEventToHosts=cluster01,cluster02,cluster03
[Remoting]      _RemoteLogFolder=\\cluster01\share  # This is optional parameter
[Remoting]      _EnableMonitoring=y
[Remoting]      _EventlogName="System"
[Remoting]      _Stop_EventID=1000

[Remoting]      Above setting means that the script will wait until the event ID 1000 is recorded on one of the remote hosts (cluster01,cluster02,cluster03) and once the event happens on a remote host, 
[Remoting]      TSS will stop all traces running on all remote hosts and copy all collected logs to '\\cluster01\share'. 
[Remoting]      So you don't need to logon to all remote hosts to gather the log files. The log files from all hosts will be copied there in the shared folder that is specified by '_RemoteLogFolder' parameter.

[Remoting]    b.) Start a trace or scenario trace on all remote hosts. The script will wait and does not fall back to command prompt until the event is recorded.
[Remoting]      Ex.: PS> .\TSSv2.ps1 -SHA_MsCluster -WaitEvent Evt:1000:System
[Remoting]    Once the event ID 1000 is recorded in the 'System' log on any of local or remote hosts, the trace running on all (remote) hosts will be stopped automatically and then all logs on all hosts will be saved in '\\cluster01\share'.
'@

if (!$SkipMenu.IsPresent){ # skip Help_Menue for -Find <keyword> # see ProcessFindKeyword
	Write-Host ""
	Write-Host "TSSv2 HELP MESSAGE (Version $global:TSSVerDate):"
	Write-Host "==========================================================================="
	Write-Host "No  Category	 Description"
	Write-Host "==========================================================================="
	Write-Host ([String]::Format("{0,2}","0") + "  Common     Common general help message")
	Write-Host ([String]::Format("{0,2}","1") + "  ADS        All available options for Active Directory Service POD")
	Write-Host ([String]::Format("{0,2}","2") + "  NET        All available options for Networking POD")
	Write-Host ([String]::Format("{0,2}","3") + "  DND        All available options for Device and Deployment POD")
	Write-Host ([String]::Format("{0,2}","4") + "  UEX        All available options for User Experience POD")
	Write-Host ([String]::Format("{0,2}","5") + "  PRF        All available options for Performance POD")
	Write-Host ([String]::Format("{0,2}","6") + "  SHA        All available options for Storage and High Availability POD")
	Write-Host ([String]::Format("{0,2}","7") + "  ALL        All available options for ALL PODs")
	Write-Host ([String]::Format("{0,2}","8") + "  Monitoring Show help message for Monitoring and Remoting feature")
	Write-Host ([String]::Format("{0,2}","9") + "  Config     All available config parameters")
	Write-Host ([String]::Format("{0,2}"," ") + "  keyword    ") -NoNewline -ForegroundColor Cyan; Write-Host ("Enter any search keyword to show all help lines that match the keyword")
	Write-Host ("---------------------------------------------------------------------------")
	Write-Host ("Select a number or enter any keyword ") -NoNewline -ForegroundColor Cyan
	$Ans = Read-Host "[0-9 or any keyword]"
	If([String]::IsNullOrEmpty($Ans)){
		$Ans = '0'
	}
}
	Switch($Ans){
		'0'{
			Write-output $HelpMessage | more
			Return
		}
		'1'{$PODName="ADS";$Pattern="ADS_"}
		'2'{$PODName="NET";$Pattern="NET_"}
		'3'{$PODName="DND";$Pattern="DND_"}
		'4'{$PODName="UEX";$Pattern="UEX_"}
		'5'{$PODName="PRF";$Pattern="PRF_"}
		'6'{$PODName="SHA";$Pattern="SHA_"}
		'7'{ProcessList;return}
		'8'{
			Write-Output $HelpMessageForMonitoring | more
			Return
		}
		'9'{
			Write-Host "See below for the detail on config parameters for TSSv2 (\config\tss_config.cfg)."
			Write-Host "URL: https://microsoft.githubenterprise.com/css-windows/WindowsCSSToolsDevRep/wiki/Parameters-for-TSSv2-config-file"
			Write-Host "or section 'Parameters for TSSv2 config file' in internal KB https://internal.support.services.microsoft.com/en-us/help/4619187"
			Write-Host "Note: Command-line parameters take precedence over config params"
			Return
		}
		default {$PODName="ALL";$Pattern="$Ans"}
	}


	# Create help messages, show Monitoring, Commands, Log, Diag, NetSh, WPR, Xperf, PerfMon, SDP, Components and Scenarios
	Write-Host "...Creating help message..." -ForegroundColor Gray
	Write-Output $HelpMessage | Out-File -Append "$env:temp\TSSv2-help-General.txt"
	Write-Output $HelpMessageForMonitoring | Out-File -Append "$env:temp\TSSv2-help-Monitoring.txt"
	# All outputs from below functions go to information stream(6). So redirect them to standard output(1) by using '6>&1'
	ProcessListSupportedCommands 6>&1 | Out-File -Append "$env:temp\TSSv2-help-Commands.txt"
	ProcessListSupportedNoOptions 6>&1 | Out-File -Append "$env:temp\TSSv2-help-NoOptions.txt"
	ProcessListSupportedLog 6>&1 | Out-File -Append "$env:temp\TSSv2-help-CollectLog.txt"
	ProcessListSupportedDiag 6>&1 | Out-File -Append "$env:temp\TSSv2-help-StartDiag.txt"
	ProcessListSupportedNetshScenario 6>&1 | Out-File -Append "$env:temp\TSSv2-help-NetshScenario.txt"
	ProcessListSupportedWPRScenario 6>&1 | Out-File -Append "$env:temp\TSSv2-help-WPR.txt"
	ProcessListSupportedXperfProfile 6>&1 | Out-File -Append "$env:temp\TSSv2-help-Xperf.txt"
	ProcessListSupportedPerfCounter -AnswerYes 6>&1 | Out-File -Append "$env:temp\TSSv2-help-PerfMon.txt"
	ProcessListSupportedSDP 6>&1 | Out-File -Append "$env:temp\TSSv2-help-SDP.txt"
	ProcessListSupportedTrace $PODName -noMore 6>&1 | Out-File -Append "$env:temp\TSSv2-help-Trace.txt"
	ProcessListSupportedScenarioTrace $PODName -noMore 6>&1 | Out-File -Append "$env:temp\TSSv2-help-Scenario.txt"

	Write-Host "...Searching help messages with keyword=""$Pattern"" ..." -ForegroundColor Gray
	$HelpFiles = @(
		"$env:temp\TSSv2-help-General.txt",
		"$env:temp\TSSv2-help-Monitoring.txt",
		"$env:temp\TSSv2-help-Commands.txt",
		"$env:temp\TSSv2-help-NoOptions.txt"
		"$env:temp\TSSv2-help-CollectLog.txt",
		"$env:temp\TSSv2-help-StartDiag.txt",
		"$env:temp\TSSv2-help-NetshScenario.txt",
		"$env:temp\TSSv2-help-WPR.txt",
		"$env:temp\TSSv2-help-Xperf.txt",
		"$env:temp\TSSv2-help-PerfMon.txt",
		"$env:temp\TSSv2-help-SDP.txt"
		"$env:temp\TSSv2-help-Trace.txt",
		"$env:temp\TSSv2-help-Scenario.txt"
	)

	$MatchInfoList = New-Object 'System.Collections.Generic.List[Object]'
	ForEach($HelpFile in $HelpFiles){
		$Lines = Select-String -Path $HelpFile -Pattern $Pattern
		$Category = $HelpFile -replace "^.*-help-",""
		$Category = $Category -replace "\.txt",""
		$MatchInfoObject = [PSCustomObject]@{
			Name	 = $Category
			MatchInfoArray = $Lines
		}
		$MatchInfoList.Add($MatchInfoObject)
	}

	If($($MatchInfoList.MatchInfoArray).count -eq 0) {
		Write-Host "Could not find any match for keyword ""$Ans""." -ForegroundColor cyan
		#Return		#we# don't return here, as long as there is no caching implemented for generated help-texts
	}
	# Show search result
	ForEach($MatchInfo in $MatchInfoList){
		If($($MatchInfo.MatchInfoArray).Count -ne 0){
			Switch($MatchInfo.Name){
				'Trace' {Write-Host " * Trace (-Start, -StartAutologger, -StartNowait):"}
				'General' {Write-Host " * General help:"}
				default {Write-Host (" -" + $MatchInfo.Name + ":")}
			}

			ForEach($MatchObject in $MatchInfo.MatchInfoArray){
				Write-Host $MatchObject.Line
			}
			Write-Host ""
		}
	}
	Remove-Item -Force "$env:temp\TSSv2-help*" -ErrorAction Ignore | Out-Null
	EndFunc $MyInvocation.MyCommand.Name
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

<# Need check with Walter for the purpose of this function
#Function Test_BCpercent {
#	# if MaxCacheSizeAsNumberOfBytes reaches 120% or 180% , checks performed in intervals of 5 minutes
#	$BCTestStatus =	& "$ScriptParentPath\tss_BCpercentRule.ps1" -Folderpath $Folderpath -BCpercentNr $BCpercent -NrOfDatFilesLimit $NrOfDatFilesLimit #-ErrorAction SilentlyContinue
#	if ("$BCTestStatus" -eq "False" ) {$Script:StopCondFound=0; LogInfo "Branch Cache test breached limit $BCpercent % or *.dat $NrOfDatFilesLimit, BCTestStatus result: $BCTestStatus "}
#	else { Write-Verbose "$(Get-date -Format G) | Result BCpercentRule: $BCTestStatus -- Script:StopCondFound $Script:StopCondFound -- CurrentActiveCacheSize: $((Get-BCDataCache).CurrentActiveCacheSize)" }
#}
#>

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

Function WaitForMultipleEvents{
	# .SYNOPSIS wait until a specific repro 'event' is hit
	EnterFunc $MyInvocation.MyCommand.Name

	###
	### Step 1: Display important global variables	#we# according to #308 these 'LogInfo' could go into 'LogInfoFile' 
	###
	LogInfo "Enter monitoring function with below parameters:"
	LogInfo "  - ErrorLimit = $global:ErrorLimit"
	LogInfo "  - IsRemoting = $global:IsRemoting"
	LogInfo "  - MonitorIntervalInSec = $FwMonitorIntervalInSec"
	LogInfo "  - IsMonitoringEnabledByConfigFile = $FwIsMonitoringEnabledByConfigFile"
	If($FwIsMonitoringEnabledByConfigFile -and [string]::IsNullOrEmpty($WaitEvent)){
		LogInfo "  => Using tss_config file to set up monitoring event"
	}Else{
		Write-Host "  => Using command line input ($WaitEvent) to set up monitoring event"
	}
	Write-Host ""

	###
	### Step 2: Create test cases
	###
	$TestPropertyList = New-Object 'System.Collections.Generic.List[PSObject]'
	If($FwIsMonitoringEnabledByConfigFile -and [string]::IsNullOrEmpty($WaitEvent)){
		$TestCommandList = New-Object 'System.Collections.Generic.List[PSObject]'

		# Create test cases based on tss_config file
		ForEach($Key in $FwConfigParameters.keys){
			Switch($Key){
				'_PortLoc'{
					$LocalPortNumber = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($LocalPortNumber)){
						$TestCommand = "PortLoc:$LocalPortNumber"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_PortLoc=$LocalPortNumber)"
					}
				}
				'_PortDest'{
					$ServerName = $FwConfigParameters['_PortDestServerName']
					$PortNumber = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($ServerName) -and ![string]::IsNullOrEmpty($PortNumber)){
						$TestCommand = "PortDest:$ServerName" + ':' + $PortNumber
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_PortDest=$PortNumber / _PortDestServerName=$ServerName)"
					}
				}
				'_SvcName'{
					$SvcName = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($SvcName)){
						$TestCommand = "Svc:$SvcName"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_SvcName=$SvcName)"
					}
				}
				'_ProcessName'{
					$ProcessName = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($ProcessName)){
						$TestCommand = "Process:$ProcessName"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_ProcessName=$ProcessName)"
					}
				}
				'_ShareName'{
					$ServerName = $FwConfigParameters['_ShareServerName']
					$ShareName = $FwConfigParameters[$Key] -Replace ("`"")
					If(![string]::IsNullOrEmpty($ServerName) -and ![string]::IsNullOrEmpty($ShareName)){
						$TestCommand = "Share:$ServerName" + ':' + $ShareName
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_ShareServerName=$ServerName _ShareName=$ShareName )"
					}
				}
				'_LogFile'{
					$LogFilePath = $FwConfigParameters['_LogFilePath']
					$SearchString = $FwConfigParameters[$Key] -Replace ("`"")
					If(![string]::IsNullOrEmpty($LogFilePath) -and ![string]::IsNullOrEmpty($SearchString)){
						$TestCommand = "LogFile:$LogFilePath" + ':' + $SearchString
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_LogFilePath=$LogFilePath  _SearchString=$SearchString)"
					}
				}
				'_DomainName'{
					$DomainName = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($DomainName)){
						$TestCommand = "LDAP:$DomainName"
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_DomainName=$DomainName)"
					}
				}
				'_CommonTCPPort'{
					$ServerName = $FwConfigParameters['_CommonTCPPortServerName']
					$CommonTCPPort = $FwConfigParameters[$Key] -Replace ("`"")
					If(![string]::IsNullOrEmpty($CommonTCPPort) -and (($CommonTCPPort -eq 'SMB') -or ($CommonTCPPort -eq 'HTTP') -or ($CommonTCPPort -eq 'RDP') -or ($CommonTCPPort -eq 'WINRM'))){
						$TestCommand = ($CommonTCPPort + ":" + $ServerName)
						$TestCommandList.Add($TestCommand)
					}Else{
						LogWarn "Skipping $Key as parameter is null or invalid(_CommonTCPPort=$CommonTCPPort)"
					}
				}
				'_RegDataKey'{
					# Expected format = RegData:$KeyRoot:$KeyPath:$ValueName:$ExpectedData => At least need 5 tokens
					$RegDataKey = $FwConfigParameters[$Key]
					$Token = $RegDataKey -split ('\\')
					Switch($Token[0]){
						'HKEY_LOCAL_MACHINE'{
							$RegKeyRoot = 'HKLM'
						}
						'HKEY_CURRENT_USER'{
							$RegKeyRoot = 'HKCU'
						}
						'HKEY_CLASSES_ROOT'{
							$RegKeyRoot = 'HKCR'
						}
						'HKLM'{$RegKeyRoot = $Token[0]}
						'HKCU'{$RegKeyRoot = $Token[0]}
						'HKCR'{$RegKeyRoot = $Token[0]}
						default{
							LogWarn "Skipping $Key as parameter is null or invalid(RootKey=$($Token[0]))"
							Break
						}
					}
					$RegDataKey = $RegDataKey -replace (($Token[0] + '\\'),'')
					$RegDataValue = $FwConfigParameters['_RegDataValue']
					$RegDataExpectedValue = $FwConfigParameters['_RegDataExpectedData']
					$RegDataIsChanged = $FwConfigParameters['_RegDataDetectIfChanged']
					If(![string]::IsNullOrEmpty($RegDataIsChanged) -and ($RegDataIsChanged.Substring(0,1) -eq 'y')){
						$IsOpposite = 'True'
					}Else{
						$IsOpposite = 'False'
					}
					$TestCommand = ("RegData:" + $RegKeyRoot + ":" + $RegDataKey + ":" + $RegDataValue + ":" + $RegDataExpectedValue + ":" + $IsOpposite)
					$TestCommandList.Add($TestCommand)
				}
				'_RegValueKey'{
					$RegValueKey = $FwConfigParameters[$Key]
					$Token = $RegValueKey -split ('\\')
					Switch($Token[0]){
						'HKEY_LOCAL_MACHINE'{
							$RegKeyRoot = 'HKLM'
						}
						'HKEY_CURRENT_USER'{
							$RegKeyRoot = 'HKCU'
						}
						'HKEY_CLASSES_ROOT'{
							$RegKeyRoot = 'HKCR'
						}
						'HKLM'{$RegKeyRoot = $Token[0]}
						'HKCU'{$RegKeyRoot = $Token[0]}
						'HKCR'{$RegKeyRoot = $Token[0]}
						default{
							LogWarn "Skipping $Key as parameter is null or invalid(RootKey=$($Token[0]))"
							Break
						}
					}
					$RegValueKey = $RegValueKey -replace (($Token[0] + '\\'),'')
					$RegValueValue = $FwConfigParameters['_RegValueValue']
					$RegValueDetectIfValueCreated = $FwConfigParameters['_RegValueDetectIfValueCreated']
					If(![string]::IsNullOrEmpty($RegValueDetectIfValueCreated) -and ($RegValueDetectIfValueCreated.Substring(0,1) -eq 'y')){
						$IsOpposite = 'True'
					}Else{
						$IsOpposite = 'False'
					}
					$TestCommand = ("RegValue:" + $RegKeyRoot + ":" + $RegValueKey + ":" + $RegValueValue + ":" + $IsOpposite)
					$TestCommandList.Add($TestCommand)
				}
				'_RegKey'{
					$RegKey = $FwConfigParameters[$Key]
					$Token = $RegKey -split ('\\')
					Switch($Token[0]){
						'HKEY_LOCAL_MACHINE'{
							$RegKeyRoot = 'HKLM'
						}
						'HKEY_CURRENT_USER'{
							$RegKeyRoot = 'HKCU'
						}
						'HKEY_CLASSES_ROOT'{
							$RegKeyRoot = 'HKCR'
						}
						'HKLM'{$RegKeyRoot = $Token[0]}
						'HKCU'{$RegKeyRoot = $Token[0]}
						'HKCR'{$RegKeyRoot = $Token[0]}
						default{
							LogWarn "Skipping $Key as parameter is null or invalid(RootKey=$($Token[0]))"
							Break
						}
					}
					$RegKey = $RegKey -replace (($Token[0] + '\\'),'')
					$RegKeyDetectIfValueCreated = $FwConfigParameters['_RegKeyDetectIfKeyCreated']
					If(![string]::IsNullOrEmpty($RegKeyDetectIfValueCreated) -and ($RegKeyDetectIfValueCreated.Substring(0,1) -eq 'y')){
						$IsOpposite = 'True'
					}Else{
						$IsOpposite = 'False'
					}
					$TestCommand = ("RegKey:" + $RegKeyRoot + ":" + $RegKey + ":" + $IsOpposite)
					$TestCommandList.Add($TestCommand)
				}
				'_File'{
					$File = $FwConfigParameters[$Key]
					$FileDetectIfFileCreated = $FwConfigParameters['_FileDetectIfFileCreated']
					If(![string]::IsNullOrEmpty($FileDetectIfFileCreated) -and ($FileDetectIfFileCreated.Substring(0,1) -eq 'y')){
						$IsOpposite = 'True'
					}Else{
						$IsOpposite = 'False'
					}
					$TestCommand = ("File:" + $File + ":" + $IsOpposite)
					$TestCommandList.Add($TestCommand)
				}
				'_EventlogName'{
					$EventLogName = $FwConfigParameters[$Key]
					$StopEventID = $FwConfigParameters['_Stop_EventID']
					$StopWaitTimeInSec = $FwConfigParameters['_Stop_WaitTimeInSec']
					$StopEventData = $FwConfigParameters['_Stop_EventData']
					$CheckIntInSec = $FwConfigParameters['_CheckIntInSec']
					$EvtDataPartial = $FwConfigParameters['_EvtDataPartial']
					$EvtDataOperator = $FwConfigParameters['_EvtDataOperator']
					If([string]::IsNullOrEmpty($StopEventID)){
						LogWarn "`'_Stop_EventID' needs to be specified."
						LogError "Skipping eventlog test as _Stop_EventID is null"
						Break
					}
					If([string]::IsNullOrEmpty($StopWaitTimeInSec)){
						$StopWaitTimeInSec = 0
					}
					If([string]::IsNullOrEmpty($CheckIntInSec)){
						$CheckIntInSec = 0
					}

					If([string]::IsNullOrEmpty($EvtDataPartial)){
						$EvtDataPartial = $True
					}Else{
						If($EvtDataPartial.Substring(0,1) -eq 'y'){
							$EvtDataPartial = $True
						}Else{
							$EvtDataPartial = $False
						}
					}
					If([string]::IsNullOrEmpty($StopEventData)){
						$EvtDataPartial = $False
						$StopEventData = '0'
					}
					If([string]::IsNullOrEmpty($EvtDataOperator)){
						$EvtDataOperator = 'OR'
					}ElseIf($EvtDataOperator -ne 'OR'){
							$EvtDataOperator = 'AND'
					}
					If(![string]::IsNullOrEmpty($EventLogName)){
						$TestCommand = "Evt:" + $StopEventID + ":" + $EventLogName + ":" + $CheckIntInSec + ":" + $StopWaitTimeInSec + ":" + $StopEventData + ":" + $EvtDataPartial + ":" + $EvtDataOperator
						$TestCommandList.Add($TestCommand)
					}Else{
						LogInfo "Skipping $Key as parameter is null or invalid"
					}
				}
				'_WaitTime'{
					$WaitTime = $FwConfigParameters[$Key]
					If(![string]::IsNullOrEmpty($WaitTime)){
						$TestCommand = "Time:$WaitTime"
						$TestCommandList.Add($TestCommand)
					}
				}
				Default{
					LogDebug ("Skipping $Key=" + $FwConfigParameters[$Key])
				}
			}
		}

		# Create a property for the test case and put it into $TestPropertyList
		ForEach($TestCommand in $TestCommandList){
			$TestProperty = CreateTestProperty $TestCommand
			If($TestProperty -ne $Null){
				LogDebug "Adding $($TestProperty.Function) to TestPropertyList."
				$TestPropertyList.Add($TestProperty)
			}Else{
				LogError "Error happend in CreateTestProperty with `'$TestCommand`'"
				Return
			}
		}
	}Else{ # Case for command line(-WaitEvent <xxx>)
		# Use condition passed from command line argument
		$TestProperty = CreateTestProperty $WaitEvent
		If($TestProperty -ne $Null){
			$TestPropertyList.Add($TestProperty)
		}Else{
			LogError "Error happend in CreateTestProperty with `'$WaitEvent`'"
			Return
		}
	}

	# If remote monitoring, add event monitor for event 999
	If(($global:IsRemoting) -or ($global:BoundParameters.ContainsKey('WaitEvent'))){ #we#575
		$TestCommand = "StopEvt:$($script:RemoteStopEventID):System"
		$TestProperty999 = CreateTestProperty $TestCommand
		If($TestProperty999 -eq $Null){
			LogError "Error happend in CreateTestProperty with `'$TestCommand`'"
			Return
		}
	}

	LogInfo "Waiting for all below test cases to be signaled. (PollInterval: $FwMonitorIntervalInSec seconds)"
	ForEach($TestProperty in $TestPropertyList){
		LogInfo "  - $($TestProperty.TestName)"
	}
	If(($global:IsRemoting) -or ($global:BoundParameters.ContainsKey('WaitEvent'))){ #we#575
		LogInfo "  - $($TestProperty999.TestName) - will stop as soon as being signaled"
	}
	If(-not $global:IsISE) {
		LogInfo "Want to stop manually?: Press CTRL-C and later run .\TSSv2.ps1 -Stop" "Cyan"
		[console]::TreatControlCAsInput = $true			# for (#556)
	}

	###
	### Step 3: Perform all test cases and wait until all test cases to be failed.
	###
	$StopCondFound = $False
	$SignaledCount = 0
	While($StopCondFound -eq $False){
		For($i=0; $i -lt $TestPropertyList.Count; $i++){
			$TestProperty = $TestPropertyList[$i]
			$param = $TestProperty.Parameters
			### Test function is called here ###
			$Result = & $TestProperty.Function @param
			If(!$Result){
				# Remove test item since this has been signaled and no need to run again.
				$TestProperty.ErrorCount++
				If($TestProperty.ErrorCount -eq $global:ErrorLimit){
					LogInfo ("$($TestProperty.TestName) is signaled")
					$TestPropertyList.Remove($TestProperty) | Out-Null
					$SignaledCount++
				}
				LogDebug "Error count of `'$($TestProperty.TestName)`' is $($TestProperty.ErrorCount)"
			}Else{
				LogDebug "Test result for `'$($TestProperty.TestName)`' is $Result"
			}
		}

		# Check System event 999 if remoting or -WaitEvent.
		If(($global:IsRemoting) -or ($global:BoundParameters.ContainsKey('WaitEvent'))){ #we#575
			$param = $TestProperty999.Parameters
			$Result = & $TestProperty999.Function @param
			If(!$Result){
				LogInfo "Stop event $script:RemoteStopEventID was detected!! Will stop all running traces." "Red"
				Return
			}
		}

		LogDebug "Remaining condition count=$($TestPropertyList.Count) / Signaled condition count=$SignaledCount"
		If($TestPropertyList.Count -eq 0){
			# In remoting, we record event 999 to remote host's System Eventlog
			If($global:IsRemoting){
				$RemoteHosts = $global:BoundParameters['RemoteHosts']
				ForEach($RemoteHost in $RemoteHosts){
					# Send actual event 999 to remote hosts.
					$SendTimeStamp = (Get-Date).ToUniversalTime().ToString("yyMMdd-HHmmss.fffffff")
					LogInfo "Writing event id $script:RemoteStopEventID into System Eventlog of $RemoteHost"
					Try{
						Write-EventLog -LogName 'System' -EntryType Error -Source "EventLog" -EventId $script:RemoteStopEventID -Message "This is StopMe Event ID: $script:RemoteStopEventID from script $ScriptName in order to stop data collection. Event was sent by user $Env:username on computer $Env:Computername at $SendTimeStamp UTC" -Category 1 -ComputerName $RemoteHost
					}Catch{
						LogException "Error happened in Write-EventLog" $_
						LogError "Please stop the script manually with '.\TSSv2.ps1 -Stop' on all remote hosts."
					}
				}
			}
			$TimeUTC = $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss"))
			LogInfo "============= Repro condition HIT - STOP now $TimeUTC UTC ============" "Green"
			LogInfo ("All -WaitEvent cases are siginaled! Will stop all active data collectors.")
			$StopCondFound = $True
		}Else{
			Write-Host '.' -NoNewline
			# allow CTRL-C to stop WaitEvent loop and terminate TSSclock as well (#556 )
			if ($Host.UI.RawUI.KeyAvailable -and (3 -eq [int]$Host.UI.RawUI.ReadKey("AllowCtrlC,IncludeKeyUp,NoEcho").Character))
			{
				Write-Host "You pressed CTRL-C. Do you want to terminate TSSv2 [Y/N]?" -ForegroundColor Cyan
				$key = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
				if ($key.Character -eq "Y") { StopTSSClock; break; }
			}
			Start-Sleep -Second $FwMonitorIntervalInSec
		}
	}

	If($StopCondFound){
		# Wait StopWaitTimeInSec
		If($global:BoundParameters.ContainsKey('StopWaitTimeInSec')){ # Command line
			$StopWaitTimeInSec = $global:BoundParameters['StopWaitTimeInSec']
		}ElseIf($script:FwConfigParameters.ContainsKey('_Stop_WaitTimeInSec')){ # Config
			$StopWaitTimeInSec = $FwConfigParameters['_Stop_WaitTimeInSec']
		}Else{
			$StopWaitTimeInSec = 0 # Default
		}

		If($StopWaitTimeInSec -gt 0){
			LogInfo "Waiting addtional $StopWaitTimeInSec seconds."
			Start-Sleep -Seconds $StopWaitTimeInSec
		}
	}
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

Function SetupRemoting{
	EnterFunc $MyInvocation.MyCommand.Name

	LogDebug "IsRemoting is set to True"
	$global:IsRemoting = $True

	# RemoteHosts: if command line does not have '-RemoteHosts', get the remote hosts from config file and add them to $global:BoundParameters
	If(!($global:BoundParameters.ContainsKey('RemoteHosts'))){ # Case for remoting cofigured by config file
		$Data = $FwConfigParameters['_WriteEventToHosts']
		If($Data -ne $Null -and $Data.contains(',')){
			$Data = $Data -split ','  # Convert a comma separated string to string array.
		}
		$global:BoundParameters.Add('RemoteHosts',$Data)
	}

	# RemoteStopEventID: This is configurable only through config file.
	$Value = $FwConfigParameters['_Remote_Stop_EventID']
	If(!([string]::IsNullOrEmpty($Value))){
		LogDebug "RemoteStopEventID is set to $Value"
		$script:RemoteStopEventID = $Value
	}

	# RemoteLogFolder: if command line does not have '-RemoteLogFolder', get the remote hosts from config file and add it to $global:BoundParameters
	If(!($global:BoundParameters.ContainsKey('RemoteLogFolder'))){ # Case for remoting cofigured by config file
		$Value = $FwConfigParameters['_RemoteLogFolder']
		If(!([string]::IsNullOrEmpty($Value))){
			LogDebug "RemoteLogFolder is set to $Value"
			$global:BoundParameters.Add('RemoteLogFolder',$Value)
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion monitoring functions

#region FW functions for custom object
Function StartTTD{
	EnterFunc $MyInvocation.MyCommand.Name

	# Case with -TTDPath(Internal TTD)
	LogDebug ("Searching tttracer.exe")
	$TTTracerPath = SearchTTTracer
	If($TTTracerPath -eq $Null){
		Throw "Unable to find tttracer.exe."
	}

	LogInfo ("[TTD] Using $TTTracerPath")

	$TTD = $global:BoundParameters['TTD']
	$TTDMode = $global:BoundParameters['TTDMode']
	If($TTDMode -eq $Null){
		$TTDMode = 'Full' # By default TTDMode is 'Full'.
	}
	$TTDOptions = $global:BoundParameters['TTDOptions']
	$TTDMaxFile = $global:BoundParameters['TTDMaxFile']

	If($TTD.Count -ne 1 -and $TTDMode -eq 'onLaunch'){
		Throw "TTD with -onLaunch does not support starting multiple processes."
	}

	$IsInitialized = $False

	# Create temp LogTTD folder
	If(![string]::IsNullOrEmpty($LogFolderName)){
		$Script:LogTTD = FwNew-TemporaryFolder -RelativeFolder $LogFolderName
	}Else{
		$Script:LogTTD = FwNew-TemporaryFolder -RelativeFolder "$env:SystemDrive\MS_DATA\"
	}

	If(!(Test-Path $Script:LogTTD)){
		FwCreateLogFolder $Script:LogTTD
	}Else{
		LogDebug "$Script:LogTTD already exists."
		Get-ChildItem -Path $Script:LogTTD -Include * -File -Recurse | foreach { Remove-Item $_ -ErrorAction Ignore}
		Start-Sleep -s 5 #add some time for deletion to complete
	}
	
	ForEach($Target in $TTD){

		# Check if passed string for -TTD is PID, exe name or service name.
		$fFound = $False
		$fProcess = $False
		$fService = $False
		$fPID = $False
		$fAppX = $False

		If(([int]::TryParse($Target,[ref]$Null))){
			Try{
				 $Process = Get-Process -Id $Target -ErrorAction Stop
			}Catch{
				$ErrorMessage = "Invalid PID $Target was specified for -TTD. Check the PID."
				LogError $ErrorMessage
				Throw ($ErrorMessage)
			}
			$ProcID = $Process.Id
			$fFound = $True
			LogDebug ("Found target process with PID $ProcID")
		}
		# Process or service name case
		If(!$fFound){
			If($Target.Contains('.exe')){
				If($TTDMode -ne 'onLaunch'){
					Try{
						$ProcName = $Target.Replace('.exe','')
						$Processes = Get-Process -IncludeUserName -Name $ProcName -ErrorAction Stop
					}Catch{
						$ErrorMessage = "$Target is not running or invalid process name."
						LogError $ErrorMessage
						Throw ($ErrorMessage)
					}
					If($Processes.Count -gt 1){
						LogInfo "Found mutiple processes below."
						LogInfo "-----------------------------------------"
						ForEach($Process in $Processes){
							Write-Host ("- " + $Process.Name +"(PID:" + $Process.Id + " User:" + $Process.UserName + ")")
						}
						LogInfo "-----------------------------------------"
						Try{
							FwPlaySound
							$SpecifiedPID = Read-Host "Enter PID of process you want to attach"
							$Process = Get-Process -Id $SpecifiedPID -ErrorAction Stop
						}Catch{
							$ErrorMessage = "Invalid PID `'$SpecifiedPID`' was specified. Check enter correct PID."
							LogError $ErrorMessage
							Throw ($ErrorMessage)
						}
						$ProcID = $SpecifiedPID
					}Else{
						$Process = $Processes
						$ProcID = $Processes.Id
					}
					$fPID = $True
					LogDebug "Conversion of process name to PID was successful and target process was found with PID $ProcID"
				}Else{
					$fProcess = $True
				}
				$fFound = $True
			}Else{ # Service name or package name case
				Try{
					$Service = Get-CimInstance -Class win32_service -ErrorAction Stop | Where-Object {$_.Name -eq $Target}
				}Catch{
					$ErrorMessage = "Error happened during running Get-CimInstance -Class win32_service"
					LogError $ErrorMessage
					Throw ($ErrorMessage)
				}
				If ($Service -ne $Null){
					If($Service.ProcessID -eq $Null){
						$ProcID = $Null
					}Else{
						$ProcID = $Service.ProcessID
					}
					$fService = $True
					$fFound = $True
					LogDebug ("Target service " + $Service + " was found.")
				}
				# Search as a package name
				If($TTDMode -eq 'onLaunch' -and !$fFound){
					$AppXApps = Get-AppxPackage -Name $Target
					If ($AppXApps.count -eq 1){
						$fAppX = $True
						$fFound = $True
						LogDebug "Found AppX package for $($AppXApps.Name)"
					}ElseIf($AppXApps.count -gt 1){
						$ErrorMessage = "We see multiple packages that have name of $Target. Please specify accurate package name for -TTD."
						LogError $ErrorMessage
						Throw ($ErrorMessage)
					}
				}

				# At this point, we don't support onlaunch + Service/Appx with built-in TTD in Windows.
				If($TTDMode -eq 'onLaunch' -and !$Script:UsePartnerTTD){
					LogError "Built-in native TTTracer.exe with -onLaunch + Service or Appx is not supported yet."
					Throw ($ErrorMessage)
				}
			}
		}
		If(!$fFound){
			$ErrorMessage = "Unable to find target process/service/package($Target)"
			LogError $ErrorMessage
			Throw ($ErrorMessage)
		}

		# -onlaunch case
		If($TTDMode -eq 'onLaunch'){
			If($fService){
				$TTDArg = "/k $TTTracerPath -out `"$Script:LogTTD`" -onLaunch $Target"  # For a service
			}ElseIf($fProcess){
				$TTDArg = "/k $TTTracerPath -out `"$Script:LogTTD`" -onLaunch $Target -Parent *" # For a process
			}ElseIf($fAppX){
				$TTDArg = "/k $TTTracerPath -out `"$Script:LogTTD`" -onLaunch $Target -plm" # For an AppX
			}

			# Add MaxFile
			If($TTDMaxFile -ne $Null){
				$TTDArg = $TTDArg + " -MaxFile $TTDMaxFile"
			}

			# At the last, add other options.
			If($TTDOptions -ne $Null){
				$TTDArg = $TTDArg + " $TTDOptions"
			}

			$TTDcmd = "cmd.exe $TTDArg"
			LogInfo ("[TTD] Starting $TTDcmd")
			Try{
				Start-Process 'cmd.exe' -ArgumentList "/c $TTTracerPath -cleanup" -ErrorAction Stop
				Start-Sleep -Seconds 3
				Start-Process 'cmd.exe' -ArgumentList $TTDArg -ErrorAction Stop
			}Catch{
				$ErrorMessage = "An exception happened during starting `'TTTracer.exe -onLaunch`'. See error in command prompt open with another window."
				LogError $ErrorMessage
				Throw ($ErrorMessage)
			}
			Return
		}

		# -Attach case
		If($ProcID -eq $Null){
			$ErrorMessage = "Unable to find PID for $Target"
			LogError $ErrorMessage
			Throw ($ErrorMessage)
		}
		If($fService){
			LogInfo ("[TTD] Target service is `'" + $Service.Name + "`'(PID:$ProcID)")
		}Else{
			LogInfo ("[TTD] Target process is `'" + $Process.Name + ".exe`'(PID:$ProcID)")
		}

		# Create argument for TTD
		If(!$Script:UsePartnerTTD){
			$TTDArg =  "-out `"$Script:LogTTD`" -attach $ProcID"  # Built-in TTD
		}Else{
			$TTDArg =  "-bg -out `"$Script:LogTTD`" -attach $ProcID"  # Partner Package
		}

		# Add MaxFile
		If($TTDMaxFile -ne $Null){
			$TTDArg = $TTDArg + " -MaxFile $TTDMaxFile"
		}

		# Add mode
		Switch($TTDMode){
			'Full' {$TTDArg = $TTDArg + " -Dumpfull"}
			'Ring' {$TTDArg = $TTDArg + " -Ring"}
		}

		# At the last, add other options.
		If($TTDOptions -ne $Null){
			$TTDArg = $TTDArg + " $TTDOptions"
		}

		$TTDcmd = "$TTTracerPath $TTDArg"
		# TTTracer.exe starts here. We use call operator(&) as TTD shows small window and we also would like to see every outputs as TTD is risky command.
		#& $TTTracerPath -out `"$LogFolder`" -attach $ProcID #& $TTTracerPath -bg -out `"$LogFolder`" -attach $ProcID
		Try{
			# TTTracer.exe starts here. We use call operator(&) as TTD shows small window and we also would like to see every outputs as TTD is risky command.
			#Start-Process 'cmd.exe' -ArgumentList $TTDArg -ErrorAction Stop
			If($Script:UsePartnerTTD){
				If(!$IsInitialized){
					Runcommands "TTD" "$TTTracerPath -initialize"
					Start-Sleep -Seconds 3
					$IsInitialized = $True
				}
			}
			LogInfo ("[TTD] Starting $TTDcmd")
			$TTDProc = Start-Process -FilePath $TTTracerPath -ArgumentList $TTDArg -RedirectStandardOutput "$global:Logfolder\TTD-output.txt" -RedirectStandardError "$global:Logfolder\TTD-err.txt" -PassThru -ErrorAction Stop
		}Catch{
			$ErrorMessage = "An exception happed during starting `'TTTracer.exe -onLaunch`'. See error in command prompt open with another window."
			LogError $ErrorMessage
			Throw ($ErrorMessage)
		}
	}
	
	#If($LASTEXITCODE -ne 0){
	#	$ErrorMessage = "An exception happed during starting `'$TTDcmd`'. See error in command prompt open with another window."
	#	LogError ($ErrorMessage)
	#	Throw ($ErrorMessage)
	#}
	Start-Sleep 1  # Wait for tttracer to be started.
	Try{
		# See if tttracer.exe is started or not.
		$TTDProc = Get-Process -Name "tttracer" -ErrorAction Stop
		LogInfo ("[TTD] TTTracer started successfully with PID:" + $TTDProc.Id)
		If($Script:UsePartnerTTD){
			LogInfo "[TTD] Note: Please start your repro steps AFTER TTD fully initialized and the tiny TTD window is seen on screen." "Cyan"
		}
	}Catch{
		$ErrorMessage = "Failed to start TTD. See above error message for detail."
		LogError $ErrorMessage
		Throw ($ErrorMessage)
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopTTD{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[TTD] Stopping TTD."
	$Script:TTDFullPath = $Null  # $Script:TTDFullPath is also used in TTDPostStop()
	$fDownLevel = $False

	# See if tttracer.exe is started or not.
	$TTDProcs = Get-Process -Name "tttracer" -ErrorAction Ignore
	If($TTDProcs -ne $Null){
		LogInfo "[TTD] Detected running TTTracer"
		If($TTDProcs.count -gt 1){
			# This is case for downlevel OS like WS2012R2
			# In this case, there are two tttracers, normal tttracer.exe and 'downlevel/tttracer.exe' are running.
			# If we see tttracer for downlevel, we have to use it to stop running tttracer.
			ForEach($TTDProc in $TTDProcs){
				If(($TTDProc.Path).contains("downlevel\tttracer.exe")){
					LogInfo ("[TTD] Detected downlevel TTTracer and will use the tttracer to stop trace.")
					$Script:TTDFullPath = $TTDProc.Path
					$fDownLevel = $True
					break
				}Else{
					$Script:TTDFullPath = $TTDProc.Path
				}
			}
		}ElseIf($TTDProcs.count -eq 1){
			$Script:TTDFullPath = $TTDProcs.Path
		}
	}Else{
		LogWarn "[TTD] TTTracer.exe is not running. Just clean up everything."
		$Script:TTDFullPath = SearchTTTracer
		If($Script:TTDFullPath -eq $Null){
			Throw "Unable to find tttracer.exe."
		}
	}

	If(!(Test-Path $Script:TTDFullPath)){
		Throw "Unable to find TTTracer.exe"
	}

	If($Script:TTDFullPath -eq "C:\Windows\System32\TTTracer.exe"){
		$Script:UsePartnerTTD = $False # Built-in TTD
	}Else{
		$Script:UsePartnerTTD = $True # Partner package
	}

	LogInfo "[TTD] Using $Script:TTDFullPath"
	Try{
		RunCommands "TTD" "$Script:TTDFullPath -stop all" -ThrowException:$True -ShowMessage:$True -ShowError:$True
	}Catch{
		Throw('ERROR: An error happened during stopping' + '(Error=0x' + [Convert]::ToString($LASTEXITCODE,16) + ')')
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectTTD{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	$TTDProcObj = Get-Process -Name 'tttracer' -ErrorAction Ignore # we could use 'FwWaitForProcess $TTDProcObj <N>' later

	If($TTDProcObj -ne $Null){
		LogDebug "$($TTDProcObj.Path) is running" Yellow
		$fResult = $True
	}

	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartWFPdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$WFPdiagLogfile = "$global:Logfolder\$LogPrefix" + "WFPdiag.cab"
	# We run native commands directly without using RunCommands() as it uses Invoke-Expression and the cmdlet does not work for wfpdiag.
	LogInfo "[WFPdiag] Running netsh wfp capture start file=$($WFPdiagProperty.LogFileName)"
	netsh wfp capture start file=$($WFPdiagProperty.LogFileName)
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopWFPdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$WFPStopCommand = "netsh wfp capture stop"
	Try{
		RunCommands "WFPDiag" $WFPStopCommand -ThrowException:$True -ShowMessage:$True
	}Catch{
		$2ndWFPdiagStopCommand = "logman stop wfpdiag -ets"
		LogWarn "Error happened during running `'$WFPStopCommand`'. Try running `'$2ndWFPdiagStopCommand`' instead."
		RunCommands "WFPDiag" $2ndWFPdiagStopCommand -ThrowException:$True -ShowMessage:$True
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectWFPdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	$WFPdiagSessionName = "wfpdiag"

	$ETWSessionList = logman -ets | Out-String
	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$Token = $Line -Split '\s+'
		If($Token[0].Contains($WFPdiagSessionName)){
			LogDebug ('DetectWFPdiag detects running WFPdiag.')
			$fResult = $True
			Break
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartRASdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$RASdiagStartCommand = @(
		"Netsh Ras diagnostics set loglevel all",
		"Netsh Ras diagnostics set trace enable"
	)
	RunCommands "RASdiag" $RASdiagStartCommand -ThrowException:$True -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopRASdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$RASdiagStopCommand = @(
		"Netsh Ras diagnostics set trace disable",
		"xcopy /s/e/i/q/y $env:SystemRoot\tracing $global:LogFolder\tracing"
	)
	RunCommands "RASdiag" $RASdiagStopCommand -ThrowException:$True -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectRASdiag{
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	$RASdiagSessionName = "RRAS-EtwTracing"

	$ETWSessionList = logman -ets | Out-String
	ForEach($Line in ($ETWSessionList -split "`r`n")){
		$Token = $Line -Split '\s+'
		If($Token[0].Contains($RASdiagSessionName)){
			LogDebug ('DetectRASdiag detects running RASdiag.')
			$fResult = $True
			Break
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartPktMon{
	EnterFunc $MyInvocation.MyCommand.Name

	If(($global:BoundParameters.ContainsKey('noPktMon'))){
		LogInfoFile "skip Starting PktMon, because of -noPktMon switch"
		Return
	}

	If($OSBuild -lt 17763){
		LogInfoFile "PktMon is not implemented in downlevel OS"
		Return
	}

	# Sometimes pktmon is started with 'Flow packets only' type by OS. Hence we stop previous pktmon session just in case.
	RunCommands "PktMon" "PktMon.exe Stop --etw" -ThrowException:$False -ShowMessage:$False -ShowError:$False

	If($OSBuild -ge 19041){ # Above ver2004(20H1)
		$PktMonStartCommand = "PktMon Start --capture --pkt-size 128 -f $($PktMonProperty.LogFileName) -s 1024"
	}ElseIf($OSBuild -ge 18362){ # ver1903(19H1) and 1909(19H2)
		$PktMonStartCommand = "PktMon Start --etw --pkt-size 128 -f $($PktMonProperty.LogFileName) -s 1024"
	}ElseIf($OSBuild -ge 17763){ # ver1809(RS5)
		$PktMonStartCommand = "PktMon Start -c all"
	}

	RunCommands "PktMon" $PktMonStartCommand -ThrowException:$True -ShowMessage:$True -ShowError:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopPktMon{
	EnterFunc $MyInvocation.MyCommand.Name

	#we# Issue#380 - PktMon is only supported on RS5+
	If($OSBuild -lt 17763){
		LogInfoFile "PktMon is not implemented in downlevel OS"
		Return
	}

	If(!($global:BoundParameters.ContainsKey('noPktMon'))){
		$PktMonStopCommand = @(
			"PktMon.exe comp List 		| Out-File -Append ""$global:LogFolder\$($LogPrefix)PktMon.txt""",
			"PktMon.exe comp counters 	| Out-File -Append ""$global:LogFolder\$($LogPrefix)PktMon.txt""",
			"PktMon.exe Stop --etw		| Out-File -Append ""$global:LogFolder\$($LogPrefix)PktMon.txt"""
		)
		If($OSBuild -ge 17763 -and $OSBuild -lt 18362){
			$PktMonStopCommand += "sc.exe stop pktmon"
		}
		RunCommands "PktMon" $PktMonStopCommand -ThrowException:$False -ShowMessage:$True
	} else {
		LogInfoFile "skip Stopping PktMon, because of -noPktMon switch"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectPktMon{
	[OutputType([Bool])]
	param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False

	# Use TSSv2 reg to see if PktMon is enabled or not.(#404 ,#445)
	$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
	$PktMonInReg = $RegValue.PktMon
	If(![String]::IsNullOrEmpty($PktMonInReg)){
		$fResult = $True
	}

	<#
	#we# Issue#380 - PktMon is only supported on RS5+
	If($OSBuild -lt 17763){
		LogInfoFile "PktMon is not implemented in downlevel OS"
		Return $fResult
	}

	If($OSBuild -ge 18362){ # Above ver1903(19H1)
		# Issue#354 - Change the way to detect PktMon
		$Line = PktMon status | Select-String "Log file"
		If ($Line -ne $Null){
			$fResult = $True
		}
	}ElseIf($OSBuild -ge 17763){ # ver1809(RS5)
		# Issue#404
		#$Line = sc.exe query pktmon | Select-String "RUNNING"
		If (((Get-Service "PktMon" -ErrorAction SilentlyContinue).status) -eq [System.ServiceProcess.ServiceControllerStatus]::Running){
			$fResult = $True
		}
	}
	#>

	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartFiddler{
	EnterFunc $MyInvocation.MyCommand.Name
	LogInfo "[$($MyInvocation.MyCommand.Name)] starting Fiddler Logging, waiting to configure traffic decrypt" "Cyan"
	LogInfo "*** by default it will NOT decrypt the traffic, please enable `Decrypt HTTPS traffic` option" "Magenta"
	LogInfo " ** [INFO] to decrypt https, see https://fiddlerbook.com/fiddler/help/httpsdecryption.asp" "Cyan"
	LogInfo " ** [INFO]  Enable the traffic decryption option by clicking Tools > Fiddler Options > HTTPS > and ticking the 'Decrypt HTTPS Traffic' box. Click OK, and accept the dialog to install " "Cyan"

	# Run Fiddler.exe -ArgumentList
	LogInfo "[Fiddler] Running Fiddler.exe -noVersionCheck"
	Start-Process "Fiddler.exe" -ArgumentList "-noVersionCheck"

	# Run ExecAction.exe start
	FwRead-Host-YN -Message "Please configure 'Decrypt HTTPS traffic' option, hit 'Y' to continue " -Choices 'y' | Out-Null  # no interest in answer
	RunCommands "Fiddler" "ExecAction.exe start" -ThrowException:$True -ShowMessage:$True -ShowError:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopFiddler{ #saves dump to $Env:USERPROFILE\Documents\Fiddler2\Captures\dump.saz
	EnterFunc $MyInvocation.MyCommand.Name
	$LogPrefix = "Fiddler"
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. saving Fiddler dump"
	$Commands = @(
		"ExecAction.exe dump"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$True -ShowMessage:$True -ShowError:$True
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. waiting 5 sec to save Fiddler dump"
	Start-Sleep -Seconds 5
	$Commands = @(
		"xcopy /i/q/y $Env:USERPROFILE\Documents\Fiddler2\Captures\*.saz $DirRepro"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$True -ShowMessage:$True -ShowError:$True
	LogInfo "[$($MyInvocation.MyCommand.Name)] .. stopping and closing Fiddler app"
	$Commands = @(
		"ExecAction.exe stop"
		"ExecAction.exe quit"
	)
	RunCommands $LogPrefix $Commands -ThrowException:$True -ShowMessage:$True -ShowError:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectFiddler{
	[OutputType([Bool])]
	param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	# Use TSSv2 reg to see if Fiddler is enabled or not.
	$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
	$FiddlerInReg = $RegValue.Fiddler
	If(![String]::IsNullOrEmpty($FiddlerInReg)){
		$fResult = $True
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartSysMon{
	EnterFunc $MyInvocation.MyCommand.Name
	$UseConfigFile = $False
	$EvtxLogSize = 104857600  # 100MB by default
	$SysmonConfig = ".\Config\sysmonConfig.xml"
	
	If(Test-Path -Path $SysmonConfig){
		LogInfo "Found $SysmonConfig. SysMon will start using the config file."
		$UseConfigFile = $True
	}

	# Install SysMon service and start capturing events.
	Try{
		RunCommands "SysMon" "SysMon.exe -i -nobanner /AcceptEula" -ThrowException:$True -ShowMessage:$True
	}Catch{
		# Sometimes we get ERROR_SWAPERROR(0x3e7) but this is ignorable.
		If($LASTEXITCODE -ne 999){ 
			LogInfoFile "Got ERROR_SWAPERROR(0x3e7) during running `"SysMon.exe -i -nobanner /AcceptEula`" but this is ignorable and will continue."
		}Else{
			Throw $_  # This might be problematic error. Re-throw the exception.
		}
	}
	# If there is a config file, use it.
	If($UseConfigFile){
		RunCommands "SysMon" "SysMon.exe -c $SysmonConfig -nobanner" -ThrowException:$True -ShowMessage:$True
	}

	# If event log size(_EvtxLogSize) is specified in config, use it(default is 100MB).
	If(!([string]::IsNullOrEmpty($script:FwEvtxLogSize))){ 
		$EvtxLogSize = $script:FwEvtxLogSize
	}

	# Update log size
	LogInfo "Updating log size for Microsoft-Windows-Sysmon/Operational to $EvtxLogSize bytes"
	FwEventLogsSet "Microsoft-Windows-Sysmon/Operational" -Enabled:$True -Retention:$True -Quiet:$True -MaxSize:$EvtxLogSize
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopSysMon{
	EnterFunc $MyInvocation.MyCommand.Name

	If(!$global:BoundParameters.ContainsKey('Discard')){
		# Export event log first as SysMon.exe -u called later removes the eventlog.
		FwExportEventLog "Microsoft-Windows-Sysmon/Operational" $global:LogFolder -DaysBack 1
	}

	# Then uninstall Sysmon
	RunCommands "SySMon" "SysMon.exe -u -nobanner" -ThrowException:$True -ShowMessage:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectSysMon{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False

	# To see if sysmon was enabled by TSSv2, we check if 'Sysmon' service is running and also the 'sysmon' is stored in TSSv2 reg.
	$SysMonService = Get-Service -Name "sysmon" -ErrorAction Ignore
	If($SysMonService -ne $Null){
		$RegValues = Get-ItemProperty -Path  $global:TSSv2ParamRegKey -ErrorAction Ignore
		If($RegValues.sysmon -ne $Null){
			$fResult = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartTSSClock{
	EnterFunc $MyInvocation.MyCommand.Name

	If($global:IsServerCore -or $global:IsRemoteHost -or $Remote.IsPresent){
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

Function StopTSSClock{
	EnterFunc $MyInvocation.MyCommand.Name
	$TSSClockProcesses = Get-CimInstance Win32_Process | Where-Object {$_.Commandline -like "*tss-clock*"}
	If($TSSClockProcesses -ne $Null){
		ForEach($TSSClockProcess in $TSSClockProcesses){
			LogInfoFile "Stopping TSS Clock (PID:$($TSSClockProcess.ProcessId))" "Gray"
			#Write-Host ""
			Stop-Process -Id $TSSClockProcess.ProcessId -ErrorAction Ignore
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StartLiveKD{
	EnterFunc $MyInvocation.MyCommand.Name
	$LiveKD = $global:BoundParameters['LiveKD']
	If($LiveKD -eq 'Start' -or $LiveKD -eq 'Both'){
		FwSetEventLog "Microsoft-Windows-Kernel-LiveDump/Analytic" -EvtxLogSize:102400000 -ClearLog  # 102400000
		$command = "$($LiveKDProperty.CommandName) -ml -o $global:LogFolder\$($LogPrefix)LiveDump-Start.dmp /AcceptEula"
		RunCommands "LiveKD" $command -ThrowException:$False -ShowMessage:$True -ShowError:$True

		# In case of 'start', stop the Analytic log here.
		If($LiveKD -eq 'Start'){
			FwResetEventLog "Microsoft-Windows-Kernel-LiveDump/Analytic"
		}
	}

	# In case of StartNoWait, register the mode to TSSv2 registry
	If(($LiveKD -ne 'Start') -and ($global:ParameterArray -contains 'StartNoWait' -or $global:ParameterArray -contains 'StartAutoLogger')){
		If(!(Test-Path $global:TSSv2ParamRegKey)){
			RunCommands "LiveKD" "New-Item -Path `"$global:TSSv2ParamRegKey`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$True  -ShowError:$True
		}
		# Save parameter to TSSv2 registry
		SaveToTSSv2Reg 'LiveKD' $LiveKD
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopLiveKD{
	EnterFunc $MyInvocation.MyCommand.Name

	If($Stop.IsPresent){
		# In case of -Stop, $LiveKD is set in ReadParameterFromTSSv2Reg().
		If([String]::IsNullOrEmpty($LiveKD)){
			$LiveKD = "Both" # Set default value
		}
		# Remove 'LiveKD' registry in TSSv2RegKey.
		Remove-ItemProperty -Path $global:TSSv2ParamRegKey -Name 'LiveKD' -ErrorAction SilentlyContinue  # Record to $Error
	}Else{ # Load from BoundParameters[]
		$LiveKD = $global:BoundParameters['LiveKD']
	}

	If($LiveKD -eq 'Start'){
		FwAddEvtLog "Microsoft-Windows-Kernel-LiveDump/Analytic"
		#we# LogDebug "Returning as $LiveKD is specified and nothing to do for stop."
		Return
	}
	If($LiveKD -eq 'Stop'){
		FwSetEventLog "Microsoft-Windows-Kernel-LiveDump/Analytic" -EvtxLogSize:102400000 -ClearLog  # 102400000
	}
	$command = "$($LiveKDProperty.CommandName) -ml -o $global:LogFolder\$($LogPrefix)LiveDump-Stop.dmp /AcceptEula"
	RunCommands "LiveKD" $command -ThrowException:$False -ShowMessage:$True -ShowError:$True
	FwResetEventLog "Microsoft-Windows-Kernel-LiveDump/Analytic"
	# Add LiveDump log to $global:EvtLogNames using FwAddEvtLog so that it be picked up later in one of functions FwCollect_BasicLog, FwCollect_MiniBasicLog or Stop_Common_Tasks (which invoke_FwGetEvtLogList_ )
	FwAddEvtLog "Microsoft-Windows-Kernel-LiveDump/Analytic"
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectLiveKD{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False

	# Use TSSv2 reg to see if LiveKD is enabled or not. For -Start, DetectLiveKD is called only to see if LiveKD is running.
	# But LiveKD is not a trace. So this function just returns with false in case of -Start.
	If($Status.IsPresent){
		$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
		$LiveKDInReg = $RegValue.LiveKD
		If(![String]::IsNullOrEmpty($LiveKDInReg) -and ($LiveKDInReg -eq 'Both' -or $LiveKDInReg -eq 'Stop')){
			$fResult = $True
		}
	}ElseIf($Stop.IsPresent){
		# In case of -Stop, $LiveKD is set in ReadParameterFromTSSv2Reg().
		If(![String]::IsNullOrEmpty($LiveKD) -and ($LiveKD -eq 'Both' -or $LiveKD -eq 'Stop')){
			$fResult = $True
		}
	}

	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartGPresult{
	EnterFunc $MyInvocation.MyCommand.Name
	$GPresult = $global:BoundParameters['GPresult']
	If($GPresult -eq 'Start' -or $GPresult -eq 'Both'){
		FwGetGPresultAS
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopGPresult{
	EnterFunc $MyInvocation.MyCommand.Name
	$GPresult = $global:BoundParameters['GPresult']
	If($GPresult -eq 'Stop' -or $GPresult -eq 'Both'){
		FwGetGPresultAS
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectGPresult{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	If($Status.IsPresent){
		$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
		$GPresultInReg = $RegValue.GPresult
		If(![String]::IsNullOrEmpty($GPresultInReg) -and ($GPresultInReg -eq 'Both' -or $GPresultInReg -eq 'Stop')){
			$fResult = $True
		}
	}ElseIf($Stop.IsPresent){
		# In case of -Stop, $script:GPresult is set in ReadParameterFromTSSv2Reg().
		If(![String]::IsNullOrEmpty($script:GPresult) -and ($script:GPresult -eq 'Both' -or $script:GPresult -eq 'Stop')){
			$fResult = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartPoolMon{
	EnterFunc $MyInvocation.MyCommand.Name
	$PoolMon = $global:BoundParameters['PoolMon']
	If($PoolMon -eq 'Start' -or $PoolMon -eq 'Both'){
		FwGetPoolmon
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopPoolMon{
	EnterFunc $MyInvocation.MyCommand.Name
	$PoolMon = $global:BoundParameters['PoolMon']
	If($PoolMon -eq 'Stop' -or $PoolMon -eq 'Both'){
		FwGetPoolmon
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectPoolMon{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	If($Status.IsPresent){
		$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
		$PoolMonInReg = $RegValue.PoolMon
		If(![String]::IsNullOrEmpty($PoolMonInReg) -and ($PoolMonInReg -eq 'Both' -or $PoolMonInReg -eq 'Stop')){
			$fResult = $True
		}
	}ElseIf($Stop.IsPresent){
		# In case of -Stop, $script:PoolMon is set in ReadParameterFromTSSv2Reg().
		If(![String]::IsNullOrEmpty($script:PoolMon) -and ($script:PoolMon -eq 'Both' -or $script:PoolMon -eq 'Stop')){
			$fResult = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartHandle{
	EnterFunc $MyInvocation.MyCommand.Name
	$Handle = $global:BoundParameters['Handle']
	If($Handle -eq 'Start' -or $Handle -eq 'Both'){
		FwGetHandle
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopHandle{
	EnterFunc $MyInvocation.MyCommand.Name
	$Handle = $global:BoundParameters['Handle']
	If($Handle -eq 'Both' -or $Handle -eq 'Stop'){
		FwGetHandle
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectHandle{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	If($Status.IsPresent){
		$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
		$HandleInReg = $RegValue.Handle
		If(![String]::IsNullOrEmpty($HandleInReg) -and ($HandleInReg -eq 'Both' -or $HandleInReg -eq 'Stop')){
			$fResult = $True
		}
	}ElseIf($Stop.IsPresent){
		# In case of -Stop, $script:Handle is set in ReadParameterFromTSSv2Reg().
		If(![String]::IsNullOrEmpty($script:Handle) -and ($script:Handle -eq 'Both' -or $script:Handle -eq 'Stop')){
			$fResult = $True
		}
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

Function StartProcDump{
	EnterFunc $MyInvocation.MyCommand.Name
	$ProcDumpInterval = $global:BoundParameters['ProcDumpInterval'] # specified in command-line
	If(($ProcDumpInterval -eq $Null) -or ([string]::IsNullOrEmpty($ProcDumpInterval))) {
		$ProcDumpInterval = $script:ProcDumpInterval				# specified in config.cfg or default specified in ReadConfigFile
	}
	$ProcDumpOption = $global:BoundParameters['ProcDumpOption']		# specified in command-line
	If(($ProcDumpOption -eq $Null) -or ([string]::IsNullOrEmpty($ProcDumpOption))) {
		$ProcDumpOption = $script:ProcDumpOption					# specified in config.cfg or default specified in ReadConfigFile
	}
	LogInfo "[StartProcDump] ProcDumpOption $ProcDumpOption - ProcDumpInterval $ProcDumpInterval " "Gray"

	# Capture user dump
	If($ProcDumpOption -eq 'Start' -or $ProcDumpOption -eq 'Both'){
		RunProcDump
	}

	# In case of StartNoWait, register the mode to TSSv2\Parameters registry
	If(!(Test-Path $global:TSSv2ParamRegKey)){
		RunCommands "ProcDump" "New-Item -Path `"$global:TSSv2ParamRegKey`" -Force -ErrorAction Stop" -ThrowException:$True -ShowMessage:$False  -ShowError:$True
	}
	# Saving parameters to TSSv2 registry for -NoWaistart and also so that -Status can detect procdump.
	SaveToTSSv2Reg 'ProcDump' ($ProcDump -join ',') # $ProcDump is string array. Hence convert it to comma separated single string.
	SaveToTSSv2Reg 'ProcDumpOption' $ProcDumpOption
	SaveToTSSv2Reg 'ProcDumpInterval' $ProcDumpInterval	#we#604

	LogDebug "[StartProcDump] ProcDumpOption $ProcDumpOption / global: $global:ProcDumpOption - ProcDumpInterval $ProcDumpInterval / global: $global:ProcDumpInterval - Bound: $($global:BoundParameters['ProcDumpInterval'])"
	EndFunc $MyInvocation.MyCommand.Name
}

Function RunProcDump{
	EnterFunc $MyInvocation.MyCommand.Name
	$ProcDump = $global:BoundParameters['ProcDump']
	ForEach($Target in $ProcDump){
		$IsService = $Null
		If(!$Target.Contains('.exe')){
			$IsService = $True
		}
		Try{
			If([int]::TryParse($Target,[ref]$Null)){
				[int]$ProcID = $Target
				FwCaptureUserDump -ProcPID $ProcID -DumpFolder $global:LogFolder	# PID
			}ElseIf($IsService){
				FwCaptureUserDump "$Target" $global:LogFolder -IsService:$True 		# Service
			}Else{
				FwCaptureUserDump "$Target" $global:LogFolder -IsService:$False		# Process
			}
		}Catch{
			LogException "Error happened in FwCaptureUserDump" $_
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopProcDump{
	EnterFunc $MyInvocation.MyCommand.Name
	# In case of -Stop, $ProcDump, $ProcDumpOption and $ProcDumpInterval are set in ReadParameterFromTSSv2Reg().
	LogDebug "[StopProcDump] ProcDumpOption: $ProcDumpOption - ProcDumpInterval: $ProcDumpInterval - global: $global:ProcDumpInterval"

	If($ProcDumpOption -eq 'Start'){
		# Do nothing
		LogDebug "Returning as `'$ProcDumpOption`' is specified and nothing to do for stop."
		Return
	}

	# Capture user dump
	RunProcDump
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectProcDump{
	[OutputType([Bool])]
	Param()
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False

	If(!(Test-Path "$global:TSSv2ParamRegKey")){
		LogDebug "There are no parameter settings in TSSv2 registry."
		$fResult = $False
	} else {
		$ParamArray = Get-Item "$global:TSSv2ParamRegKey" | Select-Object -ExpandProperty Property -ErrorAction Ignore
		$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
		ForEach($Param in $ParamArray){
			$Data = $RegValue.$Param
			If($Param -eq 'Procdump'){
				LogDebug "Procdump is enabled with `'$Data`'"
				$fResult = $True
			}
		}
	}
	EndFunc "$($MyInvocation.MyCommand.Name) Return=$fResult"
	Return $fResult
}

Function StartWireshark{
	EnterFunc $MyInvocation.MyCommand.Name

	# If parameters are set by tss_config file, respect them. Otherwise, set default value.
	If([String]::IsNullOrEmpty($global:WS_TraceBufferSizeInMB)){
		[int32]$WS_TraceBufferSizeInKB = (512 *1024)
	} else {
		[int32]$WS_TraceBufferSizeInKB =( [convert]::ToInt32($global:WS_TraceBufferSizeInMB) * 1024) #_# config value multiplied by 1024 (for MB instead of KB) #_# #294
	}
	If([String]::IsNullOrEmpty($global:WS_PurgeNrFilesToKeep)){
		$global:WS_PurgeNrFilesToKeep = 10
	}

	# Get interface number
	$IFNoArray = [System.Collections.ArrayList]@()
	If([String]::IsNullOrEmpty($global:WS_IF)){
		# Get IF dynamically
		$IFlist = & "C:\Program Files\Wireshark\dumpcap.exe" -D | Write-Output
		ForEach($Line in ($IFlist -split "`r`n")){
			$IFNoArray.add(($Line -split "\.")[0]) | Out-Null
		}
	}Else{ # Interface number is set from config or script parameter
		$IFNoArray.add($global:WS_IF) | Out-Null
	}

	# Create option string for -i(interface)
	If($IFNoArray.Count -gt 0){
		ForEach($IFNo in $IFNoArray){
			$iOptionString = $iOptionString + " -i $IFNo"
			If(![String]::IsNullOrEmpty($global:WS_Filter)){
				$iOptionString = $iOptionString + " -f `"$global:WS_Filter`""
			}
			If(![String]::IsNullOrEmpty($global:WS_Snaplen)){
				$iOptionString = $iOptionString + " -s $global:WS_Snaplen"
			}
			If(![String]::IsNullOrEmpty($global:WS_Options)){ # Other options for -i
				$iOptionString = $iOptionString + " $global:WS_Options"
			}
		}
	}Else{
		Throw "Unabled to find valid network interface."
	}

	# Add "C:\Program Files\Wireshark" to $PATH
	Add-path "C:\Program Files\Wireshark"

	$WSOptionString = "$iOptionString -B 1024 -n -t -w $($WireSharkProperty.LogFileName) -b files:$global:WS_PurgeNrFilesToKeep -b filesize:$WS_TraceBufferSizeInKB" #_# #294
	LogInfo "[WireShark] Running dumpcap.exe $WSOptionString"
	Start-Process "dumpcap.exe" -ArgumentList $WSOptionString -RedirectStandardOutput "$global:LogFolder\WSStartProcess-output.txt" -RedirectStandardError "$global:LogFolder\WSStartProcess-err.txt" -NoNewWindow
	Start-Sleep -Seconds 2 # Wait for a few seconds to see if the dumpcap.exe exits with error.
	$Dumpcap = $Null
	$Dumpcap = Get-Process -Name "dumpcap" -ErrorAction Ignore
	If($Dumpcap -eq $Null){ # Error case
		$ErrorMessage = ('An error happened in dumpcap.exe (Error=0x' + [Convert]::ToString($Process.ExitCode,16) + ')')
		LogError $ErrorMessage
		Write-Host "-------------------- ERROR MESSAGE --------------------"
		Get-Content "$global:LogFolder\WSStartProcess-output.txt"
		Get-Content "$global:LogFolder\WSStartProcess-err.txt"
		Write-Host "-------------------------------------------------------"
		Remove-Item "$global:LogFolder\StartProcess*" -ErrorAction Ignore
		Throw $ErrorMessage
	}Else{ # Normal case
		LogInfo "[WireShark] WireShark(dumpcap.exe) started in background."
	}
	EndFunc $MyInvocation.MyCommand.Name
}

Function StopWireshark{
	EnterFunc $MyInvocation.MyCommand.Name
	RunCommands "WireShark" "taskkill /F /IM dumpcap.exe" -ShowMessage:$True -ShowError:$True -ThrowException:$True
	EndFunc $MyInvocation.MyCommand.Name
}

Function DetectWireshark{
	EnterFunc $MyInvocation.MyCommand.Name
	$fResult = $False
	$WSProcObj = Get-Process -Name 'dumpcap' -ErrorAction Ignore
	If($WSProcObj -ne $Null){
		LogDebug "$($WSProcObj.Path) is running" Yellow
		$fResult = $True
	}
	EndFunc ($MyInvocation.MyCommand.Name + "($fResult)")
	Return $fResult
}

#endregion FW functions for custom object

#region pre/post functions for the object with 'command' type.
Function ProcmonPreStart{
	EnterFunc $MyInvocation.MyCommand.Name

	# In case of Procmon 3.8 or later, use flight recorder mode which is enabled by registry.
	$ProcmonCommand = Get-Command $ProcmonProperty.CommandName
	$ProcmonVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ProcmonCommand.Path).FileVersion
	If($ProcmonVersion -ne $Null -and $ProcmonVersion -gt 3.8){
		If(!([string]::IsNullOrEmpty($global:ProcmonRingBufferSize))){
			$RingBufferSize = $global:ProcmonRingBufferSize
		}Else{
			$RingBufferSize = 3096
		}
		LogDebug "Setting Procmon RingBufferSize registry to $RingBufferSize"
		Try{
			If(!(Test-Path "HKCU:Software\Sysinternals\Process Monitor")){
				New-Item -Path "HKCU:Software\Sysinternals\Process Monitor" -Force -ErrorAction Ignore | Out-Null
			}
			Set-ItemProperty -Path "HKCU:Software\Sysinternals\Process Monitor" -Name "FlightRecorder" -Value 1 -ErrorAction Stop	#we# changed from HKCU:\
			Set-ItemProperty -Path "HKCU:Software\Sysinternals\Process Monitor" -Name "RingBufferSize" -Value $RingBufferSize -ErrorAction Stop	#we# changed from HKCU:\
		}Catch{
			LogWarn "Failed to set ring buffer size. Procmon will run without flight recorder mode."
			LogException "Failed to set RingBufferSize registry." $_ -fErrorLogFileOnly:$True
		}
	}

	# Check pre-existing Procmon session. If there is running Procmon, stop it.
	$ProcmonProcess = Get-Process -Name 'Procmon*' -ErrorAction Ignore
	If($ProcmonProcess -ne $Null){
		# Trying to kill Procmon by using taskkill.exe.
		LogInfo "Currently Procmon.exe is running and stopping the process."
		RunCommands "Procmon" "TASKKILL.exe /F /IM Procmon.exe /T"
	}

	EndFunc $MyInvocation.MyCommand.Name
}
Function ProcmonPostStop{
	<#
	.SYNOPSIS
	This is a function to delete Procmon 'Logfile' registry.

	.DESCRIPTION
	After stopping Procmon, 'Logfile' is created with our log path and this causes Procmon 
	to be started using the log path next time when the Procmon is started manually. 
	To prevent this from occuring, we delete the registry after stoppping Procmon.

	.NOTES
	No parameters. Exception is not thrown.
	#>
	EnterFunc $MyInvocation.MyCommand.Name
#	If((Get-Item "HKCU:\Software\Sysinternals\Process Monitor" -ErrorAction Ignore).Property -contains "Logfile"){
	If(FwTestRegistryValue "HKCU:\Software\Sysinternals\Process Monitor" "Logfile"){
		Try{
			Remove-ItemProperty -Path "HKCU:\Software\Sysinternals\Process Monitor" -Name "Logfile" -ErrorAction Stop
		}Catch{
			LogException "Failed to delete registry in ProcmonPostStop" $_ -fErrorLogFileOnly:$True
		}
	}

	$ProcmonCommand = Get-Command $ProcmonProperty.CommandName
	$ProcmonVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ProcmonCommand.Path).FileVersion
	If($ProcmonVersion -ne $Null -and $ProcmonVersion -gt 3.8){
		LogDebug "Setting RingBufferSize registry back to 0"
		Try{
			Set-ItemProperty -Path "HKCU:Software\Sysinternals\Process Monitor" -Name "FlightRecorder" -Value 0 -ErrorAction Stop	#we# changed from HKCU:\
			Set-ItemProperty -Path "HKCU:Software\Sysinternals\Process Monitor" -Name "RingBufferSize" -Value 0 -ErrorAction Stop	#we# changed from HKCU:\
		}Catch{
			LogException "Failed to set RingBufferSize registry." $_ -fErrorLogFileOnly:$True
		}
	}

	# Check if the Procmon is really stopped. If not, kill it using taskkill.
	$ProcmonProcess = Get-Process -Name 'Procmon*' -ErrorAction Ignore
	If($ProcmonProcess -ne $Null){
		# Trying to kill Procmon by using taskkill.exe.
		LogWarn "Stopping Procmon.exe might have failed. Stopping the Procmon process forcibly using taskkill."
		RunCommands "Procmon" "TASKKILL.exe /F /IM Procmon.exe /T"
	}
	EndFunc $MyInvocation.MyCommand.Name
}

# WPR  - to detect WPR: logman query -ets "WPR_initiated_WprApp_WPR System Collector" (or "WPR_initiated_WprApp_WPR Event Collector")
Function WPRPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	# In rare case, WPR keeps working after stopping it. So we make sure if it was really stopped or not. If it is still running, cancel the WPR as this means something wrong happened.
	LogDebug "Checking if WRP is still running."
	$RunningTraces = GetExistingTraceSession
	$WPRObject = $RunningTraces | Where-Object {$_.Name -eq 'WPR'}
	If($WPRObject -ne $Null){
		#LogWarn "Stopping WRP failed at first attempt. Canceling the WPR. You might not see a log for WPR."
		LogWarn "Stopping WRP failed at first attempt. Retrying the WPR -Stop. You might not see a log for WPR."
		LogWarn "Retrying to Stop WRP $WPR"									#_we#
		WPR.EXE -Stop $WPRLogFile											#_we#
		WPR.EXE -Status | Out-File -FilePath $global:ErrorLogFile -Append 	#_we#
		wpr.exe -cancel | Out-File -FilePath $global:ErrorLogFile -Append	#_we#
	}
	EndFunc $MyInvocation.MyCommand.Name
}

# Xperf  - to detect Xperf: logman query -ets "NT Kernel Logger" (before #546), we now use the existence of temporary log file 
Function XperfPostStop{
	EnterFunc $MyInvocation.MyCommand.Name

	$RegValue = Get-ItemProperty -Path  "$global:TSSv2ParamRegKey" -ErrorAction Ignore
	$LogFolderInReg = $RegValue.LogFolder
	If(![String]::IsNullOrEmpty($LogFolderInReg)){
		$XperfFileName = "$LogFolderInReg\xperf.etl"
		If(Test-Path -Path $XperfFileName){
			Try{
				Remove-Item $XperfFileName -Force -ErrorAction Stop
			}Catch{
				LogWarn "Xperf might be still running. Please stop Xperf manually."
			}
		}
	}

	# In rare case, Xperf keeps running after stopping it. So we make sure if it was really stopped or not. If it is still running, Please stop Xperf manually
	LogDebug "Checking if Xperf is still running."
	$RunningTraces = GetExistingTraceSession
	$XperfObject = $RunningTraces | Where-Object {$_.Name -eq 'Xperf'}
	If($XperfObject -ne $Null){
		LogWarn "Stopping Xperf failed. Please stop Xperf manually."
	}

	# Set DisablePagingExecutive.
	$RegValues = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management" -ErrorAction Ignore
	If($RegValues.DisablePagingExecutive -eq 1){
		$Command = "Remove-ItemProperty -Path `"HKLM:\System\CurrentControlSet\Control\Session Manager\Memory Management`" -Name 'DisablePagingExecutive' -ErrorAction Ignore"
		Runcommands "Xperf" $Command
	}

	# Remove c:\kernel.etl
	If(Test-Path "C:\kernel.etl"){
		LogInfo "Removing C:\kernel.etl"
		Remove-Item -Path "C:\kernel.etl" -Force -ErrorAction Ignore
	}
	EndFunc $MyInvocation.MyCommand.Name
}

# PSR
Function PSRPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	StartTSSClock

	# Check pre-existing PSR session. If there is running PSR session, just kill it.
	$PSRProcess = Get-Process -Name 'PSR' -ErrorAction Ignore
	If($PSRProcess -ne $Null){
		# Trying to kill psr by using taskkill.exe.
		LogInfo "Currently PSR.exe is running. Stopping the process and re-run the PSR from TSSv2."
		RunCommands "PSR" "TASKKILL.exe /F /IM psr.exe /T"
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function PSRPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	# Stop TSS Clock
	StopTSSClock

	# Check if psr.exe is still running. If it is, kill the process using taskkill.exe.
	$PSRProcess = Get-Process -Name 'PSR' -ErrorAction Ignore
	If($PSRProcess -ne $Null){
		# Trying to kill psr by using taskkill.exe.
		LogInfo "PSR.exe is still running. Stopping the process with taskkill."
		RunCommands "PSR" "TASKKILL.exe /F /IM psr.exe /T"
		Start-Sleep 3
		# Double check if the PSR really stopped.
		$PSRProcess = $Null
		$PSRProcess = Get-Process -Name 'PSR' -ErrorAction Ignore
		If($PSRProcess -ne $Null){
			LogError "Unable to stop PSR.exe."
		}Else{
			LogWarn "Failed to stop PSR gracefully and it was killed forcibly. PSR log might not be saved correctly."
		}
	}
	EndFunc $MyInvocation.MyCommand.Name
}

# Video
Function VideoPreStart{
	EnterFunc $MyInvocation.MyCommand.Name
	StartTSSClock
	EndFunc $MyInvocation.MyCommand.Name
}
Function VideoPostStop{
	EnterFunc $MyInvocation.MyCommand.Name
	StopTSSClock
	EndFunc $MyInvocation.MyCommand.Name
}

Function TTDPreStart{ #we# #532
	EnterFunc $MyInvocation.MyCommand.Name
	LogDebug "Accepting TTD/TTD EULA per registry"
	# if using \BIN64\TTTracer.exe from package TSSv2_TTD.zip
	Try{
		If(!(Test-Path "HKCU:.DEFAULT\Software\Microsoft\TTD")){ #HKCU\.DEFAULT\Software\Microsoft\TTD
			New-Item -Path "HKCU:.DEFAULT\Software\Microsoft\TTD" -Force -ErrorAction Ignore | Out-Null
			New-Item -Path "HKCU:.DEFAULT\Software\Microsoft\TTT" -Force -ErrorAction Ignore | Out-Null
		}
		Set-ItemProperty -Path "HKCU:.DEFAULT\Software\Microsoft\TTD" -Name "EULASigned" -Value 1 -ErrorAction Stop
		Set-ItemProperty -Path "HKCU:.DEFAULT\Software\Microsoft\TTT" -Name "EULASigned" -Value 1 -ErrorAction Stop

		If(!(Test-Path "HKLM:Software\Microsoft\TTD")){
			New-Item -Path "HKLM:Software\Microsoft\TTD" -Force -ErrorAction Ignore | Out-Null
			New-Item -Path "HKLM:Software\Microsoft\TTT" -Force -ErrorAction Ignore | Out-Null
		}
		Set-ItemProperty -Path "HKLM:Software\Microsoft\TTD" -Name "EULASigned" -Value 1 -ErrorAction Stop
		Set-ItemProperty -Path "HKLM:Software\Microsoft\TTT" -Name "EULASigned" -Value 1 -ErrorAction Stop

	}Catch{
		LogWarn "Failed to set TTD EULASigned."
		LogException "Failed to set TTD EULASigned." $_ -fErrorLogFileOnly:$True
	}
	EndFunc $MyInvocation.MyCommand.Name
}
Function TTDPostStop{
	EnterFunc $MyInvocation.MyCommand.Name

	Start-Sleep -Seconds 10  # It seems like we have to wait several seconds after issuing '-stop all' for -delete and -cleanup to work properly.
	
	# $Script:TTDFullPath is initialized in StopTTD()
	RunCommands "TTD" "$Script:TTDFullPath -delete all" -ThrowException:$False -ShowMessage:$True -ShowError:$False
	Start-Sleep -Seconds 3
	RunCommands "TTD" "$Script:TTDFullPath -cleanup" -ThrowException:$False -ShowMessage:$True -ShowError:$False

	# As .run file is still being opened by the attached process, we cannot compress logfolder later.
	# To prevent this, TTSv2 saves the .run file to temporary folder tmp*.tmp when starting capturing and copy .run and related files to log folder after stopping it.
	LogInfo "Trying to Copy $Script:LogTTD\*.run,*.out,*.err logs to $global:LogFolder" "Gray"
	Get-ChildItem -Path "$Script:LogTTD\*" -Include *.run,*.out,*.err -Recurse | Copy-Item -Destination $global:Logfolder -force
	LogInfo " . Rename TTD $global:LogFolder\*.run* logs to $global:LogPrefix *" "Gray"
	Get-ChildItem -Path "$global:LogFolder" -Filter "*.run*" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	LogInfo " . Rename TTD $global:LogFolder\*.out logs to $global:LogPrefix *" "Gray"
	Get-ChildItem -Path "$global:LogFolder" -Filter "*.out" | Rename-Item -NewName {$global:LogPrefix + $_.Name}
	LogInfo " . Rename TTD $global:LogFolder\TTD*.txt logs to $global:LogPrefix *" "Gray"
	Get-ChildItem -Path "$global:LogFolder" -Filter "TTD*.txt" | Rename-Item -NewName {$global:LogPrefix + $_.Name}

	# Remove TTD services if TTD is partner package.
	If($Script:UsePartnerTTD){
		LogInfo "Unregistering TTD Services"
		$TTDFolder = Split-Path $Script:TTDFullPath -Parent
		$RemoveCommands = @(
			"$TTDFolder\TTDService.exe /unregserver",
			"$TTDFolder\wow64\TTDService.exe /unregserver"
		)
		RunCommands "TTD" $RemoveCommands -ThrowException:$False -ShowMessage:$True -ShowError:$False
	}

	# Kill command prompt if onLaunch as the cmd prompt remains even after stopping TTD in case of onLaunch
	$cmdProcs = Get-CimInstance Win32_Process -Filter "name = 'cmd.exe'" -ErrorAction Ignore | Where-Object {$_.CommandLine -like '*TTTracer.exe*onLaunch*'}
	ForEach($cmdProc in $cmdProcs){
		LogInfo "Killing command prompt for TTD(PID:$($cmdProc.ProcessId))"
		RunCommands "TTD" "Taskkill /PID $($cmdProc.ProcessId) /T"
	}
	EndFunc $MyInvocation.MyCommand.Name
}
#endregion pre/post functions

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
	LogInfo "TSSv2 Script Version: $global:TssVerDate" "Cyan"
}

If((IsStart) -and !$global:BoundParameters.ContainsKey('Start')){
	$global:BoundParameters.Add('Start',$True)
	$global:ParameterArray = InsertArrayIntoArray -Array $global:ParameterArray -insertAfter 0 -valueToInsert 'Start'
}

# Set $TSSv2Commandline. This is used when new PowerShell session is created.
$Script:TSSv2Commandline = $MyInvocation.Line

# Start new PowerShell session to clear all pre-existing global variables and run on fresh environment.
If($global:ParameterArray -notcontains 'NewSession' -and ((IsStart) -or $global:ParameterArray -contains 'StartAutoLogger' -or $global:ParameterArray -contains 'Stop' -or $global:ParameterArray -contains 'CollectLog'-or $global:ParameterArray -contains 'StartDiag')){
	If($Host.Name -match "ISE"){
		If($global:ParameterArray -contains 'StopAutologger'){
			LogError "-StopAutologger is no longer used. Please use '-Stop' instead to stop and delete autologger sessions."
			CleanUpAndExit
		}
		LogWarn "TSSv2 is running on PowerShell ISE. Global variables created in previous run might be reused and that causes expected behavior. When you see value in tss_config file is updated but not reflected in the session, please relaunch the PowerShell ISE and run it again for workaround."
	}Else{
		# To handle path having space, use &(call operator) to start new powershell session
		$CommandArg = $MyInvocation.Line -replace "^.*ps1.",""  # & 'C:\temp\tssv2 (1)\TSSv2.ps1' -Dev_TEST1 => -Dev_TEST1
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
	LogInfo "Skipping PreRequisiteCheckInStage1() as -noPrereqC was specified." "Gray"
}

# Show EULA if needed.
If($AcceptEULA.IsPresent){
	$eulaAccepted = ShowEULAIfNeeded "TSSv2" 2  # Silent accept mode.
}Else{
	$eulaAccepted = ShowEULAIfNeeded "TSSv2" 0  # Show EULA popup at first run.
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
$global:ScriptPrefix 	= 'TSSv2'
$global:ScriptName 		= $MyInvocation.MyCommand.Name
$global:ScriptFolder 	= Split-Path $MyInvocation.MyCommand.Path -Parent
$global:ScriptsFolder 	= $global:ScriptFolder + "\scripts"
$global:ConfigFolder	= $global:ScriptFolder + "\config"
$global:ConfigFile		= $global:ConfigFolder + "\tss_config.cfg"
$global:InvocationLine	= $($MyInvocation.Line) #we# to enable inspect in TSSv2_[POD].psm1
$global:IsRemoting		= $False
$global:ProcDump		= ""
$global:OperatingSystemInfo = global:FwGetOperatingSystemInfo
$global:OSBuild			= [int]$global:OperatingSystemInfo.CurrentBuildHex
$global:OSVersion		= [environment]::OSVersion.Version # This is just for compatibility.
$global:OriginalDisableRegistryTools = (Get-ItemProperty -ErrorAction Ignore -Path Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System).DisableRegistryTools
$global:TSSv2RegKey		= "HKLM:Software\Microsoft\CESDiagnosticTools\TSSv2" # To support autologger and purge task, need to set params to under HKLM
$global:TSSv2ParamRegKey = "$global:TSSv2RegKey\Parameters"
$global:IsServerCore	= IsServerCore
$global:IsServerSKU 	= FwGetSrvSKU
$global:IsISE 			= $Host.Name -match "ISE Host"
$global:IsRemoteHost 	= $Host.Name -match "RemoteHost"
$global:IsLiteMode		= IsLiteMode
$global:RegAvailable = $True
# below ProgressPreference should only be set if we are running in Azure Serial Console
If($Remote.IsPresent) {$global:ProgressPreference = "SilentlyContinue"} else {$global:ProgressPreference = "Continue"} #we# test for P2: powershell ( serial console): "Win32 internal error "Access is denied" 0x5 occurred while reading the console output buffer. (#675) 

# Global variables previously (only defined) in _NET.psm1
$global:Sys32			= $Env:SystemRoot + "\system32"
$global:PoolmonPath 	= $global:ScriptFolder + "\Bin\Poolmon.exe"
$global:HandlePath 		= $global:ScriptFolder + "\Bin\Handle.exe"
$global:DirScript		= $global:ScriptFolder
$global:DirRepro		= $global:LogFolder
$global:RegKeysModules = @()
$global:EvtLogNames = @()
# endregion Global variables
# Change current working directory and will access all tools with relative path.
cd $global:ScriptFolder

# Make sure all *.ps1/.psm1 files are Unblocked 
Get-ChildItem -Recurse -Path $global:ScriptFolder\*.ps* | Unblock-File -Confirm:$false

# In case of stop, read parameters from TSSv2 registry and set them to $global:BoundParameters
If($Stop.IsPresent -or $Status.IsPresent){
	ReadParameterFromTSSv2Reg # This adds params to $global:BoundParameters
}

# Version check
#If(($OperatingSystemInfo.OSVersion -lt 10) -and !($OperatingSystemInfo.OSVersion -eq 6 -and $OperatingSystemInfo.CurrentBuildHex -ge 9200)){
If($OSBuild -le 9200){ #we# OSver is lower then Win2012 
	LogInfo "This script is supported starting with Windows 8.1 or Windows Server 2012 R2" "Cyan"
	Write-Host ("... running on OS: $global:OSVersion with PS version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor) `n [Beta-phase] ...parts of the script may not work or throw errors running on older OS - NOT tested!") -ForegroundColor Red
	Write-Host ""
	#_# CleanUpandExit #we# uncommenting for now to test with Win7/2008R2 with updated PS version v5
}

# Global variables for sub Folder and data locations
$global:LogPrefix 		= $env:COMPUTERNAME + "_" + "$(Get-Date -f yyMMdd-HHmmss)_" 
$global:LogSuffix 		= "-$(Get-Date -f yyyy-MM-dd.HHmm.ss)"  

# Log sub folder
$LogSubFolder = 'TSSv2_' + $env:COMPUTERNAME + "_" + "$(Get-Date -f yyMMdd-HHmmss)_" 

# Log folders
# 1. If -LogFolderName exists, set it to $global:LogFolder
# 2. Set default log foldername($global:LogRoot + $LogSubFolder)
# 3. If 'LogFolder' is saved in TSSv2 registry, set it to $global:LogFolder
If($global:BoundParameters.ContainsKey('Start') -and $global:BoundParameters.ContainsKey('LogFolderName')){
	$global:LogRoot = $LogFolderName + "\"
	$global:LogFolder = $LogFolderName + "\" + $LogSubFolder
}Else{ # Normal case
	$global:LogRoot = "$env:SystemDrive\MS_DATA\"
	$global:LogFolder = $global:LogRoot + $LogSubFolder

	# If 'LogFolder' exists in TSSv2 reg, overwrite the $global:LogFolder with the LogFolder in reg.
	If(Test-Path "$global:TSSv2ParamRegKey"){
		$RegValues = Get-ItemProperty -Path  $global:TSSv2ParamRegKey -ErrorAction SilentlyContinue
		If($RegValues -ne $Null){
			If($($RegValues.LogFolder)){	#_# fix to avoid LogFolder=''
				LogDebug "Found LogFolder in TSSv2 reg. Set it to LogFolder"
				$global:LogRoot = Split-Path $($RegValues.LogFolder) -Parent
				$global:LogFolder = $RegValues.LogFolder
			}
		}
	}

	# in case of collecting -SDP only, shorten subfolder to SDP_<specialty>
	if (($MyInvocation.BoundParameters.keys[0] -eq "SDP") -and ($global:BoundParameters.Count -le 2)) {
		$SDPcombi = ([string]::Concat($SDP)).replace(',','_') # $SDP is string array
		$global:LogFolder = "$env:SystemDrive\MS_DATA" + '\SDP_' + $SDPcombi
	}
}
If((IsTraceOrDataCollection)){
	LogInfo "LogFolder is set to `'$global:LogFolder`'" "Cyan"
}

$global:PrefixCn	= $global:LogFolder + "\" + $Env:Computername + "_"
$global:PrefixTime	= $global:LogFolder + "\" + $global:LogPrefix

# Error log
$global:ErrorLogFile = "$global:LogFolder\$($LogPrefix)_Log-Warn-Err-Info.txt"
$global:ErrorVariableFile = "$global:LogFolder\$($LogPrefix)_ErrorVariable.txt"
$global:TempCommandErrorFile = "$global:LogFolder\$($LogPrefix)Command-Error.txt" #"$env:TMP\TSSv2-Command-Error.txt"

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
		LogInfoFile "Commandline: $($MyInvocation.Line)" "Gray" # Log commandline first.
		# Log PS window type
		If($Host.Name -match "ISE"){ LogInfoFile "$global:ScriptName v$global:TSSverDate script execution is attempted in 'PowerShell ISE' window ($($Host.Name))."} else { LogInfoFile "$global:ScriptName v$global:TSSverDate script execution is running in regular 'PowerShell' window ($($Host.Name))."}
		LogInfo "... running TSSv2 v$global:TSSverDate on OS: $global:OSVersion with PS version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)" "Gray"
	}Catch{
		LogError ("Error happened in Start-Transcript")
	}
	If(!(IsRegCommandAvailable)){
		LogInfoFile "global:RegAvailable is set to false"
		$global:RegAvailable = $False
	}
}

#_# checking online for latest public version
if (( -Not $noVersionChk.IsPresent) -or ($global:ParameterArray -notcontains 'noVersionChk')){
	If (( -Not $noUpdate.IsPresent) -and ((IsStart) -or $StartAutoLogger.IsPresent -or ![string]::IsNullOrEmpty($StartDiag) -or ![string]::IsNullOrEmpty($CollectLog))) {
		LogInfo "Checking if a new version is available on https://aka.ms/getTSS"
		CheckVersion($global:TssVerDate)
	}
}
<#
# ToDo: possibly run AutoUpdate in production here (do it while in broad Testing phase)
If (( -Not $noUpdate.IsPresent) -and ($Script:fUpToDate -eq $False) -and ((IsStart) -or $StartAutoLogger.IsPresent -or ![string]::IsNullOrEmpty($StartDiag) -or ![string]::IsNullOrEmpty($CollectLog))) {
	UpdateTSS	# skip this step with -noUpdate #_# -> keeping active while beta testing, # -> remove for production
}
#> 

#
# Set $global:EnableCOMDebug to use the value in TSSv2_UEX.psm1
If($EnableCOMDebug.IsPresent){
	$global:EnableCOMDebug = $EnableCOMDebug
}

#
# Set $global:StartAutoLogger to use the value in TSSv2_NET.psm1 and other modules
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

## bail out if running in MS prod domain
if (!($Mode -iMatch "traceMS")) {
	if (($env:USERDNSDOMAIN -match "\.microsoft\.com") -and (IsTraceOrDataCollection)) {
		Write-Host " .. running on Domain: $env:USERDNSDOMAIN"
		Write-Host -ForegroundColor Magenta "`n ..exiting, as testing TSSv2 in microsoft.com domain may cause Security alerts. Please test TSSv2 in Lab environment without CorpNet access and read 'Important Note' in internal KB4619187. `nIn case you need data from this MS domain joined machine, plz append: -Mode traceMS"
		Exit
	}
}

# Executing external PS script and exiting
#
If([string]::IsNullOrEmpty($ExternalScript)) {			
	write-debug "TSSv2 started without providing external script"}
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
If((IsStart) -or $StartAutoLogger.IsPresent -or !([string]::IsNullOrEmpty($StartDiag)) -or $Stop.IsPresent -or !([string]::IsNullOrEmpty($CollectLog))){
	if ([Environment]::Is64BitOperatingSystem -eq $True){
		$Global:ProcArch = 'x64'
	}else{
		$Global:ProcArch = 'x86'
	} # Binaries are supposed to be located in $global:ScriptFolder\BIN$Global:ProcArch or $global:ScriptFolder\BIN
	
	# add TSSv2 Binary folders (\BIN, \BINx**) to $Env:Path #we#
	foreach ($sub in @("bin", "bin$Global:ProcArch")){
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
}
$global:BinArch			= "\Bin" + $global:ProcArch

# Global variables previously (only defined) in _NET.psm1
If($global:ProcArch -eq "x64"){
	$global:NotMyFaultPath =  $global:ScriptFolder + $BinArch + "\NotMyFault64.exe"
}Else{
	$global:NotMyFaultPath =  $global:ScriptFolder + $BinArch + "\NotMyFault.exe"
}
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
$Script:PurgeTaskName = "TSSv2 Purge Task"
$Script:PurgeTaskNameForAutologger = "TSSv2 Purge Task for AutoLogger"
$Script:IsCrashInProgress = $False

# Collections
$script:ETWPropertyList = New-Object 'System.Collections.Generic.List[Object]'
$CommandPropertyList = New-Object 'System.Collections.Generic.List[Object]'
$globalTraceCatalog = New-Object 'System.Collections.Generic.List[Object]'
$LogCollector = New-Object 'System.Collections.Generic.List[Object]'
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

LogDebug ("===========================	 ETL Option	 ============================")
LogDebug ("ETLOptions: $EtlOptions")
LogDebug ("ETLMode=" + $Script:EtlMode + "   ETLMaxSize=" + $Script:ETLMaxSize + "   ETLNumberToKeep=" + $Script:ETLNumberToKeep)
LogDebug ("===========================================================================")

# AutoLogger
$AutoLoggerLogFolder = $global:LogFolder
$AutoLoggerPrefix = 'autosession\'
$AutoLoggerBaseKey = 'HKLM:\System\CurrentControlSet\Control\WMI\AutoLogger\'

# Batch file
$BatFileName = "$global:LogFolder\TSSv2.cmd"
$StartAutoLoggerBatFileName = "$AutoLoggerLogFolder\StartAutoLogger.cmd"
$StopAutoLoggerBatFileName = "$AutoLoggerLogFolder\StopAutoLogger.cmd"

# Read-only valuables
Set-Variable -Name 'fLogFileOnly' -Value $True -Option readonly

# Loading all POD modules.
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

# Setup remoting if enabled.
$Value = $FwConfigParameters['_EnableRemoting']
If((![string]::IsNullOrEmpty($Value) -and $Value.Substring(0,1) -eq 'y') -or $global:BoundParameters.ContainsKey('RemoteHosts')){
	SetupRemoting
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

# Netsh RASdiag
$RASdiagProperty = @{
	Name = 'RASdiag'
	TraceName = 'Netsh RASdiag'
	LogType = 'Custom'
	CommandName = $Null
	Providers = $Null
	LogFileName = $Null
	StartOption = $Null
	StopOption = $Null
	PreStartFunc = $Null
	StartFunc = 'StartRASdiag'
	StopFunc = 'StopRASdiag'
	PostStopFunc = $Null
	DetectionFunc = 'DetectRASdiag'
	AutoLogger = $Null
	Wait = $True
	SupportedOSVersion = $Null
	Status = $TraceStatus.Success
	StartPriority = $StartPriority.RASdiag
	StopPriority = $StopPriority.RASdiag
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

$ALLPODsPerfCounter = Get-Variable -Name "*_SupportedPerfCounter" -ValueOnly
ForEach($PODPerfCounter in $ALLPODsPerfCounter){
	ForEach($Key in $PODPerfCounter.keys){
		$SupportedPerfCounter.Add($Key, $PODPerfCounter[$Key])
	}
}

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

#support for scenarios (simulating import parameters)
If($Scenario.Count -ne 0 -and !$Stop.IsPresent){
	ForEach($ScenarioName in $Scenario){
		$myArrayToInsert = @()
		$ScenarioTraceSetName = "$($ScenarioName)_ETWTracingSwitchesStatus"
		$Scenario_ETWTracingSwitchesStatus = Get-Variable $ScenarioTraceSetName -ValueOnly -ErrorAction Ignore
		If($Scenario_ETWTracingSwitchesStatus -eq $Null){
			LogError "Invalid scenario name $ScenarioName was specified."
			Write-Host "=> Run `'.\TSSv2.ps1 -ListSupportedScenario`' to see available scenario names." -ForegroundColor Yellow
			Write-Host " and Please also run '.\TSSv2.ps1 -Stop' once after such error, in order to cleanup previous failed TSS attempts." -ForegroundColor  Cyan	#we# added to avoid Perfmon errors in next run
			CleanUpAndExit
		}

		$ETWTraceCountInScenario = 0
		LogInfo "Specified scenario $ScenarioName contains following traces and parameters:" "Gray"
		ForEach($Key in $Scenario_ETWTracingSwitchesStatus.Keys){
			$Token = $Null
			$ValueName = $Null
			$OriginalCommand = $Null

			If($Key.contains(' ')){ # Parameter with option
				$Token = $Key -split ' '  # Example: 'WPR General' to WPR
				$Command = $Token[0]
				$OriginalCommand = $Key

				# Create NetshOptions for Netsh
				If(!$MyInvocation.BoundParameters.ContainsKey($Command)){
					# Netsh
					If(($Token[0] -eq 'Netsh')){
						# If there is 2nd token, that is NetshOptions and set it to BoundParameters.
						If($Token.Length -gt 2){
							$OptionString = $Null
							For($i=1;$i -lt $Token.Length;$i++){
								$OptionString += $Token[$i] + ' '
							}
							$OptionString = $OptionString -replace " $",""  # remove space at the end.
							If(!$global:BoundParameters.containskey('NetshOptions')){
								$global:BoundParameters.Add('NetshOptions',$OptionString)
							}Else{
								LogInfo "NetshOptions has already been set from command line. Using the command line option."
							}
						}
						$global:BoundParameters.Add('Netsh',$True)
						Write-Host "   - $OriginalCommand"
						Continue
					}

					# Create NetshOptions for Netsh and WPROptions for WPR
					If(($Token[0] -eq 'NetshScenario') -or ($Token[0] -eq 'WPR')){
						# If 3rd token exists, it is netshoptions and set it to BoundParameters.
						If($Token[2] -ne $Null){
							$OptionString = $Null
							For($i=2;$i -lt $Token.Length;$i++){
								$OptionString += $Token[$i] + ' '
							}
							$OptionString = $OptionString -replace " $",""  # remove space at the end.
							If($Token[0] -eq 'NetshScenario'){
								$OptionName = 'NetshOptions'
							}ElseIf($Token[0] -eq 'WPR'){
								$OptionName = 'WPROptions'
							}
							If(!$global:BoundParameters.containskey($OptionName)){
								$global:BoundParameters.Add($OptionName,$OptionString)
							}Else{
								LogInfo "$OptionName has already been set from command line. Using the command line option."
							}
						}
					}

					# Other all options that take string, string array, integer are set to BoundParameters[].
					If(($Token[1]).contains(',')){
						$Parameter = $Token[1] -split ','
					}Else{
						$Parameter = $Token[1]
					}
					$global:BoundParameters.Add($Command,$Parameter)
				}Else{
					# In case that the same switch is specified by command line and scenario trace, we will respect command line.
					LogInfo "$Command was specified by both command line and scenario trace. Using `'$Command' in command line instead of scenario definition."
					Continue # Skip adding to $myArrayToInsert
				}
			}Else{ # Parameter without option is set to BoundParameters[] here.
				$Command = $Key
				# Add only command type trace. ETW will be added later.
				If(!($MyInvocation.BoundParameters.ContainsKey($Command))){
					If($CommandSwitches.ContainsKey($Command)){
						$global:BoundParameters.Add($Command,$True)
					}
				}Else{
					# In case that the same switch is specified by command line and scenario trace, we will respect command line.
					LogInfo "$Command was specified by both command line and scenario trace. Using `'$Command' in command line instead of scenario definition."
					Continue # Skip adding to $myArrayToInsert
				}
			}

			# Only when trace is '$True'(enabled), we add it to parameter.
			If($Scenario_ETWTracingSwitchesStatus[$Key]){
				# ETW: Add prefix to trace name so that framework recognize this trace is part of scenario.
				ForEach($TraceProperty in $TraceDefinitionList){
					If($TraceProperty.Name -eq $Command){
						$ScenarioTraceName = $ScriptPrefix + '_' + $Scenario + "Scenario_" + $Command
						LogDebug "Renaming $Command to $ScenarioTraceName"

						# ETW is added here.
						$global:BoundParameters.Add($ScenarioTraceName,$True)
						$ETWTraceCountInScenario++
						break
					}
				}

				# Add command switches(netsh, WPR, Procmon and so on)
				If($ControlSwitches -Contains $Command){
					If(!($global:BoundParameters.ContainsKey($Command))){
						$global:BoundParameters.Add($Command,$True)
					}
				}Else{
					LogDebug "$Command is not added to ParameterArray."
				}
				If($OriginalCommand -eq $Null){
					Write-Host "   - $Command"
				}Else{
					Write-Host "   - $OriginalCommand"
				}
			}Else{
				LogDebug ("$Key in $ScenarioName scenario is disabled")
			}
		}
	}
}

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

<# Add switches in noSettingList to BoundParameters
If($global:BoundParameters.ContainsKey('noSettingList')){
	ForEach($Token in $global:BoundParameters['noSettingList']){
		If(!($global:BoundParameters.ContainsKey($Token))){
			LogDebug "Adding $Token to BoundParameters"
			$global:BoundParameters.Add($Token,$True)
		}Else{
			LogDebug "$Token is already contained in BoundParameters. Skipping this switch."
		}
	}
} #>

# Issue#321
# For Server Core, or when running in Remote PSsession, add noVideo and noPSR so that -Video and -PSR will be removed later.
If(($global:IsServerCore) -or ($global:BoundParameters.ContainsKey('Remote'))){ 
	LogInfo "TSSv2 is running on Server Core or in Remote PSsession. Adding -noVideo and -noPSR to script parameter"
	$noSwichForServerCore = @(
		'noVideo'
		'noPSR'
	)

	# Add no switches
	ForEach($noSwich in $noSwichForServerCore){
		If(!($global:BoundParameters.ContainsKey($noSwich))){
			$global:BoundParameters.Add($noSwich,$True)
		}
	}
}

# Initialize $global:ParameterArray again as parameters have been updated until reaching here.
[String[]]$global:ParameterArray = $Null
ForEach($Key in $global:BoundParameters.Keys){
	$global:ParameterArray += $Key
}

# Create variables for no switches. These are mainly refered from POD modules
ForEach($noSwitch in $noSwitchList){
	Remove-Variable $noSwitch -ErrorAction Ignore
	If($global:ParameterArray -contains $noSwitch){
		Set-Variable -Name $noSwitch -Scope Global -Value $True -ErrorAction Ignore	#we# replaced New-Variable with Set-Variable, as they can already exist in tss_config.cfg
	}Else{
		Set-Variable -Name $noSwitch -Scope Global -Value $False -ErrorAction Ignore
	}
}

# We have all no parameters in $global:ParameterArray and $global:BoundParameters at this point. Now start removing switches corresponding to the noSwitch.
$noSwitchesForRecording = @('PSR', 'Video')
ForEach($noCommandSwitch in $noSwitchList){
	#write-host "____checking $noCommandSwitch"
	If($global:ParameterArray -contains $noCommandSwitch){
		$CommandParameter = $noCommandSwitch -replace '^no',''
		If($global:ParameterArray -contains $CommandParameter){
			LogInfo "Removing -$CommandParameter from parameters as -$noCommandSwitch is specified."
			$global:ParameterArray = RemoveItemFromArray $global:ParameterArray $CommandParameter
			$global:BoundParameters.Remove($CommandParameter) | Out-Null
		}ElseIf($noCommandSwitch -eq 'noRecording'){
			ForEach($noSwitchForRecording in $noSwitchesForRecording){
				If($global:BoundParameters.ContainsKey($noSwitchForRecording)){
					LogInfo "Removing -$noSwitchForRecording from parameters as -noRecording is specified."
					$global:ParameterArray = RemoveItemFromArray $global:ParameterArray $noSwitchForRecording
					$global:BoundParameters.Remove($noSwitchForRecording) | Out-Null
				}
			}
		}
	} 
}

	# Issue#567 remove -NetshScenario for -noNetsh
	If(($global:BoundParameters.ContainsKey('NetshScenario')) -and ($global:ParameterArray -contains 'noNetsh')){
		LogInfo "Removing -NetshScenario from parameters as -noNetsh is specified."
		$global:BoundParameters.Remove('NetshScenario') | Out-Null
		$global:BoundParameters.Remove('NetshOptions') | Out-Null
	}
	
If((IsStart) -or $Stop.IsPresent){
	#LogInfo "TSSv2 will run with below parameters."
	ForEach($Parameter in $global:ParameterArray){
		$ParameterString = $ParameterString + ' ' + $Parameter
	}
	LogInfo "Working on Parameters:$ParameterString"
}

If($global:ParameterArray -notcontains 'noPrereqC'){
	PreRequisiteCheckInStage2
}Else{
	LogInfo "Skipping PreRequisiteCheckInStage2() as -noPrereqC was specified." "Gray"
}

If((IsStart) -or $Stop.IsPresent -or ![string]::IsNullOrEmpty($CollectLog) -or ![string]::IsNullOrEmpty($StartDiag)){
	If(($PSVersionTable.PSVersion.Major -le 4) -or ($global:OSBuild -le 9600)){ # PowerShell 4.0 / #we# Get-TimeZone fails on Srv2012R2 with PS v5.0 
		$TimeZone = [System.TimeZoneInfo]::Local.DisplayName
	}Else{
		$TimeZone = (Get-TimeZone).DisplayName
	}
	$SessionID = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
	LogInfoFile "___globals -Mode: $Global:Mode -Mini: $Global:Mini -beta: $Global:beta -noRestart: $Global:noRestart -noClearCache: $Global:noClearCache"
	LogInfoFile "$global:ScriptPrefix Version $global:TssVerDate /_NET: $global:TssVerDateNET /_DND: $global:TssVerDateDND /_ADS: $global:TssVerDateADS /_UEX: $global:TssVerDateUEX /_SHA: $global:TssVerDateSHA /_PRF: $global:TssVerDatePRF" 
	$OSVersionReg = Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows NT\CurrentVersion'
	If($OSBuild -gt 9600){
		$OS_Version= "$($OSVersionReg.CurrentMajorVersionNumber)" + "." + "$($OSVersionReg.CurrentMinorVersionNumber)" + "." + "$($OSVersionReg.CurrentBuildNumber)" + "." + "$($OSVersionReg.UBR)"
	}Else{
		$OS_Version= "$($OSVersionReg.CurrentVersion)" + "." + "$($OSVersionReg.CurrentBuild)"
	}
	LogInfoFile "OS Version:        $OS_Version"
	$global:ProductType = FwGetProductTypeFromReg
	LogInfoFile "ProductType:       $global:ProductType"
	LogInfoFile "OS Culture:        $((Get-Culture).name) [ UI Culture: $((Get-UICulture).name) ]"
	LogInfoFile "TimeUTC:           $((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH:mm:ss")) [TZ: $TimeZone]"
	LogInfoFile "Computer:          $ENV:COMPUTERNAME - User: $ENV:USERNAME - Domain: $env:USERDNSDOMAIN - Session: $SessionID"
	LogInfoFile "PATH:              $Env:PATH"
	Get-ExecutionPolicy -list | Out-File -FilePath $global:ErrorLogFile -Append
}

# In case of -discard, remove previous folders and keep only lastest folder
If($global:ParameterArray -contains 'Discard'){
	$LogFoldersAndFiles = Get-Childitem (Split-Path -parent $global:LogFolder) | Sort-Object -Property LastWriteTime -Descending
	If($LogFoldersAndFiles.Count -gt 1){
		LogInfo "Removing previous log folders below."
		For($i=1;$i -lt $LogFoldersAndFiles.Count;$i++){
			LogInfo "  - $($LogFoldersAndFiles[$i].FullName)"
			Remove-Item -Path $LogFoldersAndFiles[$i].FullName -Recurse -Force -ErrorAction Ignore
		}
	}
}

Try{
	Switch($global:ParameterArray[0]){
		'start'{
			If($CreateBatFile.IsPresent){
				ProcessCreateBatFile
			}Else{
				ProcessStart
			}
		}
		'StartAutoLogger'{
			If($CreateBatFile.IsPresent){
				ProcessCreateBatFile
			}Else{
			   ProcessStart
			}
		}
		'StartDiag'{
			ProcessStartDiag
		}
		'stop'{
			ProcessStop
		}
		'RemoveAutoLogger'{
			RemoveAutoLogger
		}
		'set'{
			ProcessSet
		}
		'unset'{
			ProcessUnset
		}
		'help'{
			ProcessHelp
			#ProcessList $Help
		}
		'TraceInfo'{
			ProcessTraceInfo
		}
		'Find'{
			ProcessFindKeyword
		}
		'FindGUID'{
			ProcessFindGUID
		}
		'status'{
			ProcessStatus
		}
		'CollectLog'{
			ProcessCollectLog
		}
		'CollectEventLog'{
			ProcessCollectEventLog
			CompressLogIfNeededAndShow
		}
		'List'{
			ProcessList
		}
		'ListSupportedTrace'{
			ProcessListSupportedTrace
		}
		'ListSupportedLog'{
			ProcessListSupportedLog
		}
		'ListSupportedNetshScenario'{
			ProcessListSupportedNetshScenario
		}
		'ListSupportedPerfCounter'{
			ProcessListSupportedPerfCounter
		}
		'ListSupportedCommands'{
			ProcessListSupportedCommands
		}
		'ListSupportedNoOptions'{
			ProcessListSupportedNoOptions
		}
		'ListSupportedDiag'{
			ProcessListSupportedDiag
		}
		'ListSupportedScenarioTrace'{
			ProcessListSupportedScenarioTrace
		}
		'ListSupportedWPRScenario'{
			ProcessListSupportedWPRScenario
		}
		'ListSupportedXperfProfile'{
			ProcessListSupportedXperfProfile
		}
		'ListSupportedSDP'{
			ProcessListSupportedSDP
		}
		'Version'{
			# Check online and Display only Version, then exit
			CheckVersion($global:TssVerDate)
			Write-Host -ForegroundColor Cyan "$global:ScriptPrefix Script Version: $global:TssVerDate"
			Write-Host -ForegroundColor Cyan " - Version _ADS.psm1: $global:TssVerDateADS"
			Write-Host -ForegroundColor Cyan " - Version _DND.psm1: $global:TssVerDateDND"
			Write-Host -ForegroundColor Cyan " - Version _NET.psm1: $global:TssVerDateNET"
			Write-Host -ForegroundColor Cyan " - Version _PRF.psm1: $global:TssVerDatePRF"
			Write-Host -ForegroundColor Cyan " - Version _SHA.psm1: $global:TssVerDateSHA"
			Write-Host -ForegroundColor Cyan " - Version _UEX.psm1: $global:TssVerDateUEX"
		}
		'update'{
			CheckVersion($global:TssVerDate)
			# Update current TSSv2 package, then exit
			if ($Script:fUpToDate -eq $False) { UpdateTSS }
		}
		'SDP'{
			ProcessSDP
		}
		'Xray'{
			ProcessXray
		}
		default{
			ProcessStart
		}
	}
}Finally{ 
	# Usually we reach here when user stops the script with Ctrl + C
	CleanUpandExit 
}

Write-Host ""
CleanUpandExit
#endregion MAIN

# SIG # Begin signature block
# MIInrQYJKoZIhvcNAQcCoIInnjCCJ5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDtwItTVBtnCAB/
# EHs7Wx3tPKXfxidnRLhbonWBvD2TrqCCDYEwggX/MIID56ADAgECAhMzAAACUosz
# qviV8znbAAAAAAJSMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMjU5WhcNMjIwOTAxMTgzMjU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDQ5M+Ps/X7BNuv5B/0I6uoDwj0NJOo1KrVQqO7ggRXccklyTrWL4xMShjIou2I
# sbYnF67wXzVAq5Om4oe+LfzSDOzjcb6ms00gBo0OQaqwQ1BijyJ7NvDf80I1fW9O
# L76Kt0Wpc2zrGhzcHdb7upPrvxvSNNUvxK3sgw7YTt31410vpEp8yfBEl/hd8ZzA
# v47DCgJ5j1zm295s1RVZHNp6MoiQFVOECm4AwK2l28i+YER1JO4IplTH44uvzX9o
# RnJHaMvWzZEpozPy4jNO2DDqbcNs4zh7AWMhE1PWFVA+CHI/En5nASvCvLmuR/t8
# q4bc8XR8QIZJQSp+2U6m2ldNAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUNZJaEUGL2Guwt7ZOAu4efEYXedEw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDY3NTk3MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAFkk3
# uSxkTEBh1NtAl7BivIEsAWdgX1qZ+EdZMYbQKasY6IhSLXRMxF1B3OKdR9K/kccp
# kvNcGl8D7YyYS4mhCUMBR+VLrg3f8PUj38A9V5aiY2/Jok7WZFOAmjPRNNGnyeg7
# l0lTiThFqE+2aOs6+heegqAdelGgNJKRHLWRuhGKuLIw5lkgx9Ky+QvZrn/Ddi8u
# TIgWKp+MGG8xY6PBvvjgt9jQShlnPrZ3UY8Bvwy6rynhXBaV0V0TTL0gEx7eh/K1
# o8Miaru6s/7FyqOLeUS4vTHh9TgBL5DtxCYurXbSBVtL1Fj44+Od/6cmC9mmvrti
# yG709Y3Rd3YdJj2f3GJq7Y7KdWq0QYhatKhBeg4fxjhg0yut2g6aM1mxjNPrE48z
# 6HWCNGu9gMK5ZudldRw4a45Z06Aoktof0CqOyTErvq0YjoE4Xpa0+87T/PVUXNqf
# 7Y+qSU7+9LtLQuMYR4w3cSPjuNusvLf9gBnch5RqM7kaDtYWDgLyB42EfsxeMqwK
# WwA+TVi0HrWRqfSx2olbE56hJcEkMjOSKz3sRuupFCX3UroyYf52L+2iVTrda8XW
# esPG62Mnn3T8AuLfzeJFuAbfOSERx7IFZO92UPoXE1uEjL5skl1yTZB3MubgOA4F
# 8KoRNhviFAEST+nG8c8uIsbZeb08SeYQMqjVEmkwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZgjCCGX4CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAlKLM6r4lfM52wAAAAACUjAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgZwhgzOAU
# rr0dOx0d7gd6d/cnpTyRUwwoELst0Yr0GsgwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCOa1mSE79dJ3HTXqHpaYYVLReUfpwsZlsD0hP/Ijym
# udX89ADLSYsfHufB3ROrxjqJdNZ3HodC74W1XH6/DyfSzIDBZW/OgnlUThJ4s9cL
# Om6roAlc0LEfIZkGAjrNYbS4dfSPxrLHG9V1G6LUzd9gnnjO1FfMV1584ihKQUks
# aqJ2/HnTzaWd3hu3ccSG2P6M5dtc0afLOBC42QmRPqJWlv1TzAnFyMFfkCNGGwIB
# lzsWRQwOcxtIQo8Q/y42YgwX9F8BacVd7MUDqxneM3e0N+QnIUGxsiEhbdrKb02P
# 6aZ+vG/l4iNJ0WCe6jgrAxBqS5BBgo4is8nZ0C8WH45poYIXDDCCFwgGCisGAQQB
# gjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglghkgBZQME
# AgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIL9dBSJtKL3OW9ys2q/2H5ancN9+Ok+1JmHQzwhu
# CcHKAgZisc3fX9IYEzIwMjIwNzIxMTMzOTMxLjM5MVowBIACAfSggdSkgdEwgc4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1p
# Y3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMg
# VFNTIEVTTjo2MEJDLUUzODMtMjYzNTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgU2VydmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABpllFgzlNnutLAAEA
# AAGmMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MB4XDTIyMDMwMjE4NTEyMVoXDTIzMDUxMTE4NTEyMVowgc4xCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
# YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo2MEJD
# LUUzODMtMjYzNTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANmYv3tSI+fJ/NQJnjz7
# JvCnc+Xm0rKoe9YKD4MvMYCul7egdrT/zv5vFbQgjNQ74672fNweaztkR65V8y29
# u5PL2sf01p+uche0Zu4tSig+GsQ6ZQl9tjPRAY/3ITBHDeIYyvq8Wne9+7NoPLhx
# DSO6dtX7YCuQ4zcTP3SE6MvB4b5NighdtvoZVaYk1lXpjUTfdmKoX1ABq1sJbULS
# nSi0Qd4vvl3mZ9jxwv9dR/nlZP62lrZYZq7LPtHD6BlmclB5PT89DnSm1sjaZnFH
# rKzOsmq5GlmL5SFugCCZOoKz133FJeQaFMcXBZSCQjNABWBbHIRCE1ysHHG83Ddo
# nRmnC8EOlYeRwTWz/QCz6q0riOIbYyC/A2BgUEpu9/9EymrTsyMr2/zS8GdEybQ5
# W7f0WrcrmKB/Y62+g6TmfOS8NtU+L1jGoKNG6Q5RlfJwZu8J/Q9dl4OxyHKuy78+
# wm6HsF7uAizpsWh63UUaoK/OGQiBG3NJ+kef5eWpnva4ZJfhAnqYTAZD1uHgf8Vf
# Qjnl0BB2YXzK9WaTqde8d+8qCxVKr5hJYvbO+X3+2k5PCirUK/SboreX+xUhVaQE
# hVDYqlatyPttI7Z2IrkhMzwFvc+p0QeyMiNmo2cBZejx8icDOcUidwymDUYqGPE7
# MA8vtKW3feeSSYJsCEkuUO/vAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUOlQhO/zG
# lqK99UkNL/Gu/AryN9gwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIw
# XwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3Js
# MGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENB
# JTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcD
# CDANBgkqhkiG9w0BAQsFAAOCAgEAgMDxWDTpGqLnFoPhm/iDfwHGF8xr2NbrJl8e
# gEg2ThTJsTf0wBE+ZQsnYfrRmXBbe6sCXLVN70qPuI+OEbN5MOai7Bue1/4j5VTk
# WquH5GZeVat2N+dD7lSUWp0dU8j+uBhBL5GFSmoDVVm+zW2GR2juPI1v254AJTb2
# l458anlkJjGvmYn2BtRS13h/wDR7hrQaI7BgdyHWAV5+HEj5UhrIrrvtwJiivSaU
# EA3qK6ZK/rZIQv/uORDkONw+2pHHIE1SXm/WIlhrVS2HIogfr3JjqvZion6LJSD7
# 41j8xVDLiClwAbspHoVFjxtxBcMjqPx6aWCJS8vjSoTnhkV4PO55mqsM7Q8XQRGQ
# hA7w4zNQOJu9kD4xFdYpPUmLN/daIcEElofBjGz+sEd1B4yqqIk3u2G4VygTXFmt
# hL8chSo7r+GIvTqWKhSA/sanS4N3jCgCCe3FTSJsp4g5nwavLvWAtzcOIvSRorGm
# AeN0m2wgzBK95T/qgrGGDXSos1JNDWRVBnP0qsw1Qoq5G0D8hxvQPs3X43KBv1GJ
# l0wo5rcC+9OMWxJlB63gtToQsA1CErYoYLMZtUzJL74jwZk/grpHEQhIhB3sneC8
# wzGKJuft7YO/HWCpuwdChIjynTnBh+yFGMdg3wRrIbOcw/iKmXZopMTQMOcmIeIw
# JAezA7AwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3
# DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIw
# MAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAx
# MDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# 5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/
# XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1
# hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7
# M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3K
# Ni1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy
# 1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF80
# 3RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQc
# NIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahha
# YQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkL
# iWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV
# 2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIG
# CSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUp
# zxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBT
# MFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
# MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186a
# GMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsG
# AQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcN
# AQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1
# OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYA
# A7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbz
# aN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6L
# GYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3m
# Sj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0
# SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxko
# JLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFm
# PWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC482
# 2rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7
# vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYIC0jCC
# AjsCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo2MEJDLUUzODMtMjYzNTElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# anQzrZW9TB93Ve7Pa4UPao2ffK2ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOaDL4kwIhgPMjAyMjA3MjEwNTUx
# MDVaGA8yMDIyMDcyMjA1NTEwNVowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5oMv
# iQIBADAKAgEAAgIhXgIB/zAHAgEAAgIS1zAKAgUA5oSBCQIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBAG7JOMaLIvJnfzYC+nL6nkPB4Kvw63VyZI9YVl7f/6eO
# wdokffPRzWWo+BdU8BZR7cNDhCr+o84/Yd3rLAdP1cG8vkAZ1372jS7PLcPMYTRV
# Z9QjGo/4MfbH6vvYs2R4048nr0pkfDhBwewKoakM9Zqx78PvrFmlppIbRggaT9j+
# MYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAGmWUWDOU2e60sAAQAAAaYwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg4JicVZ8EjArnqz2HuUTo
# CxKSJOaU3/TOxYc+HOmhRXQwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCD
# CxmLwz90fWvhMKbJTAQaKt3DoXeiAhfp8TD9tgSrDTCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABpllFgzlNnutLAAEAAAGmMCIEIAXl
# gD05jbPiYvqiJjFzeax9DAS0s3NVtrQYWqPxXBZmMA0GCSqGSIb3DQEBCwUABIIC
# AEuUajeJhWicy8xHf3h12icUj2YmmkhErlT8YK9NJWhY1ajLqvNKJqZK5//mu+CY
# io0sWDaFz1aTSKC9cTXdF9fK1m+EUawfS3hATVN8bJq5fEofmK4lQJQUt7KjxcF7
# uRRhJXhXa1uy8t077LcqPl7JUeE2EpYNuxRidFnuCoxvXUFBy2VBOKozzCFsQDbN
# YatULCC/c3BSZ4HaYtFeJNRZSg7ib6C/tx8WIl5Fpc3rsApoqkHLKcJ9b7uT3y8u
# 6gD4iDJwu9794H0KyojDUpqnHmCCPDCfNZm2ZHarW1H4e7wFDOctckmyaaC0Dlc3
# 0ewnwgdhcVN4ZTw+ulIKDYiCQ0q4VIMX0lpLTHvkeMMOH2qrWsQiBTbnu2sA7P4o
# 1bjbz7noo40OSg1bkp5uVxCMEgyC+oVr3T7hphXc5qYq2WKVZYtIYJ7d57yYzmPg
# dsIFs4U7/RdWsuizk4nrPyLCfV8fjmscwyEylrgj6iw5TYYUWS323T8vEYObPSzt
# fUqgJ7MT2lvF+Y3XGzuMPCBPRulFB27iDfM0+FHRy/szeSN0kYEGwUXRpcOXeo1W
# i4a+tWGlKPP1VDdJKoVYM2V6bu0u0meEP0JNRz8SrDZQq+7ulDP3bBE+hYARb2tD
# Ts0gJU4qCdJ6gZohCHxJepHKt88S0vysbh/8sJhXUv0m
# SIG # End signature block
