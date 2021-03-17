# --------------------------------------------------------------
#  Copyright © Microsoft Corporation.  All Rights Reserved.
#  Microsoft Corporation (or based on where you live, one of its affiliates) licenses this sample code for your internal testing purposes only.
#  Microsoft provides the following sample code AS IS without warranty of any kind. The sample code arenot supported under any Microsoft standard support program or services.
#  Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#  The entire risk arising out of the use or performance of the sample code remains with you.
#  In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the code be liable for any damages whatsoever
#  (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
#  arising out of the use of or inability to use the sample code, even if Microsoft has been advised of the possibility of such damages.
# ---------------------------------------------------------------
<#
.SYNOPSIS 
    Removes the virtual machines and configuration created by the 
    SDNExpress.ps1 script
.EXAMPLE
    .\SDNExpressUndo -ConfigurationDataFile .\MyConfig.psd1
    Reads in the configuration from a PSD1 file that contains a hash table 
    of settings data and removes any settings applied.
.EXAMPLE
    .\SDNExpressUndo -ConfigurationData $MyConfigurationData
    Uses the hash table that is passed in as the configuration data.  This 
    parameter set is useful when programatically generating the 
    configuration data. This configuration data must match what was passed
    in to .\SDNExpress
.NOTES

#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationFile")]
    [String] $ConfigurationDataFile=$null,
    [Parameter(Mandatory=$true,ParameterSetName="ConfigurationData")]
    [object] $ConfigurationData=$null
)    
$ErrorActionPreference = "Continue"

switch ($psCmdlet.ParameterSetName) 
{
    "ConfigurationFile" {
        Write-Verbose "Using configuration from file [$ConfigurationDataFile]"
        $configdata = [hashtable] (iex (gc $ConfigurationDataFile | out-string))
    }
    "ConfigurationData" {
        Write-Verbose "Using configuration passed in from parameter"
        $configdata = $configurationData 
    }
}

$sdnVMs = $configdata.NCs + $configdata.Muxes + $configdata.Gateways
foreach ($sdnVM in $sdnVMs) {
    $vm = Get-VM -VMName $sdnVM.ComputerName -ComputerName $sdnVM.HostName
    if ($vm -ne $null) {
        Stop-VM -VM $vm -Force -TurnOff
        Invoke-Command {
            param([String[]]$path)
            Remove-Item -Force -Path $path
        } -ComputerName $sdnVM.HostName -ArgumentList (Get-VMHardDiskDrive -VM $vm).Path
    
        Remove-VM -VM $vm -Force
    }

    Disable-ADAccount (Get-ADComputer $sdnVM.ComputerName)
}

foreach ($h in $configdata.HyperVHosts) {
    Invoke-Command {
        param([String]$restName)
        Stop-Service SLBHostAgent -Force
        Stop-Service NCHostAgent -Force

        New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name "Connections" -Value @() -PropertyType "MultiString" -Force
        Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters" -Name "PeerCertificateCName", "HostAgentCertificateCName", "HostId" -Force
        Remove-Item c:\windows\system32\slbhpconfig.xml -Force

        $nics = Get-VMNetworkAdapter -ManagementOS | ? { $_.Name -like 'PAHostvNic*' }
        foreach($nic in $nics) {
            Remove-VMNetworkAdapterRoutingDomainMapping -ManagementOS -VMNetworkAdapterName $nic.Name
            Set-VmNetworkAdapterIsolation -ManagementOS -IsolationMode None -VMNetworkAdapterName $nic.Name
            Remove-VMNetworkAdapter -ManagementOS -VMNetworkAdapterName $nic.Name
        }

        Get-ChildItem -Force -Recurse Cert:\LocalMachine | ? { $_.Subject -like $restName } | Remove-Item -Force

        Set-Content @"
OVSDB JSON 924 fa5d760ff1b9395c3a7093feab38094724f1658b
{"tables":{"FW_Global":{"columns":{"cur_cfg":{"type":"integer"},"next_cfg":{"type":"integer"}},"maxRows":1},"FW_Rules":{"columns":{"protocols":{"type":"string"},"rule_id":{"type":"string"},"src_ip_addresses":{"type":"string"},"rule_state":{"type":{"key":{"type":"string","enum":["set",["Disabled","Enabled"]]}}},"priority":{"type":"integer"},"logging_state":{"type":{"key":{"type":"string","enum":["set",["Disabled","Enabled"]]}}},"src_ports":{"type":"string"},"vnic_id":{"type":"string"},"direction":{"type":{"key":{"type":"string","enum":["set",["Inbound","Outbound"]]}}},"dst_ports":{"type":"string"},"rule_type":{"type":{"key":{"type":"string","enum":["set",["RuleWithAdminPriority","RuleWithControllerPriority"]]}}},"action":{"type":{"key":{"type":"string","enum":["set",["Allow","Block"]]}}},"dst_ip_addresses":{"type":"string"}},"indexes":[["rule_id","vnic_id","rule_type"]]}},"name":"ms_firewall","version":"1.0.1"}
"@ -Path C:\ProgramData\Microsoft\Windows\NcHostAgent\Firewall.conf -Encoding UTF8

        Set-Content @"
OVSDB JSON 905 7a03ee7613dd0f9fab203be42aafc60b3a009145
{"tables":{"Global":{"columns":{"cur_cfg":{"type":"integer"},"next_cfg":{"type":"integer"}},"maxRows":1,"isRoot":true},"Ports":{"columns":{"enable_ip_forwarding":{"type":"boolean"},"name":{"type":"string"},"mac_address":{"type":"string"},"ip_addresses":{"type":{"key":{"type":"uuid","refTable":"IP_Addresses"},"min":0,"max":"unlimited"}},"is_primary":{"type":"boolean"}},"isRoot":true,"indexes":[["name"]]},"IP_Addresses":{"columns":{"dns_suffix":{"type":"string"},"routers":{"type":{"key":"string","min":0,"max":"unlimited"}},"is_primary":{"type":"boolean"},"mask":{"type":"string"},"address":{"type":"string"},"dns_servers":{"type":{"key":"string","min":0,"max":"unlimited"}}}},"Switches":{"columns":{"name":{"type":"string"},"vlans":{"type":{"key":{"maxInteger":4095,"minInteger":0,"type":"integer"},"min":0,"max":"unlimited"}}},"isRoot":true,"indexes":[["name"]]}},"name":"ms_darv","version":"1.1.0"}"
"@ -Path C:\ProgramData\Microsoft\Windows\NcHostAgent\ms_darv.conf -Encoding UTF8

        Set-Content @"
OVSDB JSON 4720 3909a7d43fca6d0d3134733b2eae0baa6b972441
{"tables":{"Physical_Locator_Set":{"columns":{"locators":{"mutable":false,"type":{"key":{"type":"uuid","refTable":"Physical_Locator"},"max":"unlimited"}}}},"Physical_Port":{"columns":{"description":{"type":"string"},"vlan_stats":{"type":{"key":{"maxInteger":4095,"minInteger":0,"type":"integer"},"min":0,"value":{"type":"uuid","refTable":"Logical_Binding_Stats"},"max":"unlimited"}},"name":{"type":"string"},"status":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}},"vlan_bindings":{"type":{"key":{"maxInteger":4095,"minInteger":0,"type":"integer"},"min":0,"value":{"type":"uuid","refTable":"Logical_Switch"},"max":"unlimited"}},"other_config":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}}}},"Manager":{"columns":{"is_connected":{"ephemeral":true,"type":"boolean"},"status":{"ephemeral":true,"type":{"key":"string","min":0,"value":"string","max":"unlimited"}},"target":{"type":"string"},"other_config":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}},"inactivity_probe":{"type":{"key":"integer","min":0}},"max_backoff":{"type":{"key":{"minInteger":1000,"type":"integer"},"min":0}}},"indexes":[["target"]]},"Global":{"columns":{"db_version":{"type":{"key":"string","min":0}},"managers":{"type":{"key":{"type":"uuid","refTable":"Manager"},"min":0,"max":"unlimited"}},"other_config":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}},"switches":{"type":{"key":{"type":"uuid","refTable":"Physical_Switch"},"min":0,"max":"unlimited"}},"cur_cfg":{"type":"integer"},"next_cfg":{"type":"integer"}},"maxRows":1,"isRoot":true},"Mcast_Macs_Local":{"columns":{"ipaddr":{"type":"string"},"locator_set":{"type":{"key":{"type":"uuid","refTable":"Physical_Locator_Set"}}},"logical_switch":{"type":{"key":{"type":"uuid","refTable":"Logical_Switch"}}},"MAC":{"type":"string"}},"isRoot":true},"Logical_Switch":{"columns":{"description":{"type":"string"},"name":{"type":"string"},"static_routes":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}},"other_config":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}},"tunnel_key":{"type":{"key":"integer","min":0}},"encryption_credential_thumbprint":{"type":"string"}},"isRoot":true,"indexes":[["name"]]},"Ucast_Macs_Local":{"columns":{"ipaddr":{"type":"string"},"logical_switch":{"type":{"key":{"type":"uuid","refTable":"Logical_Switch"}}},"MAC":{"type":"string"},"locator":{"type":{"key":{"type":"uuid","refTable":"Physical_Locator"}}}},"isRoot":true},"Physical_Switch":{"columns":{"description":{"type":"string"},"tunnel_ips":{"type":{"key":"string","min":0,"max":"unlimited"}},"name":{"type":"string"},"distributed_router_mac":{"type":"string"},"ports":{"type":{"key":{"type":"uuid","refTable":"Physical_Port"},"min":0,"max":"unlimited"}},"management_ips":{"type":{"key":"string","min":0,"max":"unlimited"}},"other_config":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}}},"indexes":[["name"]]},"Physical_Locator":{"columns":{"bfd":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}},"dst_ip":{"mutable":false,"type":"string"},"bfd_status":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}},"encapsulation_type":{"mutable":false,"type":{"key":{"type":"string","enum":["set",["nvgre_over_ipv4","nvgre_over_ipv6","vxlan_over_ipv4","vxlan_over_ipv6"]]}}}},"indexes":[["encapsulation_type","dst_ip"]]},"Logical_Binding_Stats":{"columns":{"packets_to_local":{"type":"integer"},"bytes_to_local":{"type":"integer"},"bytes_from_local":{"type":"integer"},"packets_from_local":{"type":"integer"}}},"Ucast_Macs_Remote":{"columns":{"ipaddr":{"type":"string"},"logical_switch":{"type":{"key":{"type":"uuid","refTable":"Logical_Switch"}}},"MAC":{"type":"string"},"mapping_type":{"mutable":false,"type":{"key":{"type":"string","enum":["set",["default","learning_disabled","load_balanced"]]}}},"locator":{"type":{"key":{"type":"uuid","refTable":"Physical_Locator"}}}},"isRoot":true},"Logical_Router":{"columns":{"description":{"type":"string"},"enable_logical_router":{"type":"boolean"},"name":{"type":"string"},"switch_binding":{"type":{"key":"string","min":0,"value":{"type":"uuid","refTable":"Logical_Switch"},"max":"unlimited"}},"static_routes":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}},"other_config":{"type":{"key":"string","min":0,"value":"string","max":"unlimited"}}},"isRoot":true,"indexes":[["name"]]},"Mcast_Macs_Remote":{"columns":{"ipaddr":{"type":"string"},"locator_set":{"type":{"key":{"type":"uuid","refTable":"Physical_Locator_Set"}}},"logical_switch":{"type":{"key":{"type":"uuid","refTable":"Logical_Switch"}}},"MAC":{"type":"string"}},"isRoot":true}},"name":"ms_vtep","version":"1.1.1"}
"@ -Path C:\ProgramData\Microsoft\Windows\NcHostAgent\ms_vtep.conf -Encoding UTF8

        Set-Content @"
OVSDB JSON 623 badd2b8b1dad69f0618eae45ba76625abc8d8512
{"tables":{"SI_Rule":{"columns":{"protocols":{"type":"string"},"rule_id":{"type":"string"},"src_ip_addresses":{"type":"string"},"priority":{"type":"integer"},"src_ports":{"type":"string"},"vnic_id":{"type":"string"},"dst_ports":{"type":"string"},"rule_type":{"type":{"key":{"type":"string","enum":["set",["MirrorDestinaion","MirrorSource","ServiceInsertion"]]}}},"dst_ip_addresses":{"type":"string"},"routing_information":{"type":"string"}},"indexes":[["rule_id","vnic_id"]]},"SI_Global":{"columns":{"cur_cfg":{"type":"integer"},"next_cfg":{"type":"integer"}},"maxRows":1}},"name":"ms_service_insertion","version":"1.0.0"}
"@ -Path C:\ProgramData\Microsoft\Windows\NcHostAgent\ServiceInsertion.conf -Encoding UTF8

    } -ComputerName $h -ArgumentList $configdata.RestName
}
