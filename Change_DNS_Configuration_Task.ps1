#$networkName  = "Ethernet 3"
#$DNS_Server = "8.8.8.8,4.4.4.4"
#$Protocol_IPV4_IPV6 = 'IPV4'


$dnsServers   = ("$DNS_Server")
$dnsServers = $dnsServers.split(',')

if($dnsServers[0] -ne $null -or $dnsServers[0] -eq ""){
   $Primary_DNS = $($dnsServers[0])
}
if($dnsServers[1] -ne $null -or $dnsServers[1] -eq ""){
   $Secondry_DNS = $($dnsServers[1])
}
$dnsServers   = ("$Primary_DNS","$Secondry_DNS")

#$ip_address   = '10.0.0.1'
#$subnetMask   = '255.0.0.0'
#$gateway      = '10.0.0.2'

$Global:FinalDNS1 = @()
cls
##############################
######Check PreCondition######
##############################

$hostVerSionMajor = ($PSVersionTable.PSVersion.Major).ToString()
$hostVerSionMinor = ($PSVersionTable.PSVersion.Minor).ToString()
$hostVersion = $hostVerSionMajor +'.'+ $hostVerSionMinor 
 
$osVersionMajor = ([System.Environment]::OSVersion.Version.major).ToString()
$osVersionMinor = ([System.Environment]::OSVersion.Version.minor).ToString()
$osVersion = $osVersionMajor +'.'+ $osVersionMinor
 
[boolean]$isPsVersionOk = ([version]$hostVersion -ge [version]'2.0')
[boolean]$isOSVersionOk = ([version]$osVersion -ge [version]'6.0')
      
Write-Host "Powershell Version : $($hostVersion)"
if(-not $isPsVersionOk){
   
  Write-Warning "PowerShell version below 2.0 is not supported"
  return 
 
}
 
Write-Host "OS Name : $((Get-WMIObject win32_operatingsystem).Name.ToString().Split("|")[0])"  
if(-not $isOSVersionOk){
 
   Write-Warning "PowerShell Script supports Window 7, Window 2008R2 and higher version operating system"
   return 
 
}

Write-Host "`n##########################################"
write-host 'Validating the Network Adapter existance'
Write-Host "########################################## `n"

############################################################################################
##################### Process for Setting Changes #######################
############################################################################################
function Process_For_Change_Setting
{
param($networkName)

        ######## Get Adapter Settings
        $adapter = Gwmi win32_networkadapter | where {$_.NetConnectionID -eq $networkName}

        ######## Get Adapter Settings    
        $adapterSettings = Get-WmiObject win32_networkAdapterConfiguration | where {$_.index -eq $adapter.index}
        
        ######### Get Target Adapter DNS config
        $global:Current_Adapter_Config = Get_Current_Adapter_Info -adapterSettings $adapterSettings

        $Sec = $Global:FinalDNS | ? {$_.Prim_Second -eq 'Second'} | % {$_.Address}
        $Prim = $Global:FinalDNS | ? {$_.Prim_Second -eq 'Prim'} | % {$_.Address}
        $Prim_Current_config = $global:Current_Adapter_Config.DNSServers.split(',')[0]
        $Sec_Current_config = $global:Current_Adapter_Config.DNSServers.split(',')[1]

        $dnsServers = ProcessForChanges -Primary_DNS $Prim -Secondry_DNS $Sec -Primary_DNS_Current_Config $Prim_Current_config -Secondry_DNS_Current_Config $Sec_Current_config
        
        if($Sec -ne $null -and $prim -eq $null){
        write-host "process for changes : $($Sec)"}
        if($prim -ne $null -and $Sec -eq $null){
        write-host "process for changes : $($prim)"}
        if($Sec -ne $null -and $prim -ne $null){        
        write-host "process for changes : $($prim,$Sec)"
        }                
        write-host "`nAttemp to change DNS configuration.." -ForegroundColor yellow
               
        $Specified_Setting = 'DNS Server_Address Changes'
        $dnsChange_ReturnValue = ($adapterSettings.SetDNSServerSearchOrder($dnsServers)).ReturnValue
        sleep 2
       $Return_Info = Check_ReturnValue -Return_Value $dnsChange_ReturnValue -Specified_Setting $Specified_Setting
       
       if($dnsChange_ReturnValue -eq 0 -or $dnsChange_ReturnValue -eq 1)
       {
          $DNSIPs = ($dnsServers) -join ','
          write-host "DNS is successfully changed`n" -ForegroundColor Green


      Write-Host "`n#######################################################################"
      Write-Host "Post Changes of Network Adapter: ($($networkName))"
      Write-Host "#######################################################################`n"
    
    $adapterSettings = Get-WmiObject win32_networkAdapterConfiguration | where {$_.index -eq $adapter.index}  
    $global:Current_Adapter_Config1 = Get_Current_Adapter_Info -adapterSettings $adapterSettings
    write-host "IPAddress     : $($global:Current_Adapter_Config1.IPAddress)"
    write-host "SubnetMask    : $($global:Current_Adapter_Config1.SubnetMask)"
    write-host "Gateway       : $($global:Current_Adapter_Config1.Gateway)" 
    write-host "IsDHCPEnabled : $($global:Current_Adapter_Config1.IsDHCPEnabled)" 
    write-host "DNSServers    : $($global:Current_Adapter_Config1.DNSServers)"           
              
       }

}
#########################################################
function ProcessForChanges{
param($Primary_DNS,$Secondry_DNS,$Primary_DNS_Current_Config,$Secondry_DNS_Current_Config)

  Write-Host "`n#########################################"
  Write-Host "Changes in Progress of Network_Adapter Setting"
  Write-Host "#########################################`n"
  
#$Primary_DNS   = '8.8.4.4'
#$Secondry_DNS  = '8.8.8.8'


#$Primary_DNS_Current_Config  = $null
#$Secondry_DNS_Current_Config  = '8.8.8.8'


if($Primary_DNS -ne $null -and $Secondry_DNS -ne $null)
{
   $DNSConfig = @("$Primary_DNS","$Secondry_DNS")  
        
}


if($Primary_DNS -ne $null -and $Secondry_DNS -eq $null)
{
    if($Secondry_DNS_Current_Config -ne $null)
    {
        $DNSConfig = @("$Primary_DNS","$Secondry_DNS_Current_Config")
    }

    if($Secondry_DNS_Current_Config -eq $null)
    {
        $DNSConfig = @("$Primary_DNS")
    }
        
}

if($Primary_DNS -eq $null -and $Secondry_DNS -ne $null)
{
    if($Primary_DNS_Current_Config -ne $null)
    {
        $DNSConfig = @("$Primary_DNS_Current_Config","$Secondry_DNS")
    }

    if($Primary_DNS_Current_Config -eq $null)
    {
        #$DNSConfig = @($null,"$Secondry_DNS")
        write-host "No Primary found hence Valid Secondry address going to set as Primary Address $Secondry_DNS"          
        $DNSConfig = @("$Secondry_DNS")
        
    }    
}

return $DNSConfig

}


############################################################################################
##################### Validate the Adapter Setting Changes #######################
############################################################################################
function Check_ReturnValue
{ param($Return_Value,$Specified_Setting)


    #write-host "$Specified_Setting Status"

    switch ($Return_Value) 
    {
        -1 {Write-host ''}
        0  {#Write-Host 'Successful completion, no reboot required'; break
           }
        1  {#Write-Host 'Successful completion, reboot required'; break
           }
        64 {Write-Host 'Method not supported on this platform'; break}
        65 {Write-Host 'Unknown failure'; break}
        66 {Write-Host 'Invalid subnet mask'; break}
        67 {Write-Host 'An error occurred while processing an Instance that was returned'; break}
        68 {Write-Host 'Invalid input parameter'; break}
        69 {Write-Host 'More than 5 gateways specified'; break}
        70 {Write-Host 'Invalid IP address'; break}
        71 {Write-Host 'Invalid gateway IP address'; break}
        72 {Write-Host 'An error occurred while accessing the Registry for the requested information'; break}
        73 {Write-Host 'Invalid domain name'; break}
        74 {Write-Host 'Invalid host name'; break}
        75 {Write-Host 'No primary/secondary WINS server defined'; break}
        76 {Write-Host 'Invalid file'; break}
        77 {Write-Host 'Invalid system path'; break}
        78 {Write-Host 'File copy failed'; break}
        79 {Write-Host 'Invalid security parameter'; break}
        80 {Write-Host 'Unable to configure TCP/IP service'; break}
        81 {Write-Host 'Unable to configure DHCP service'; break}
        82 {Write-Host 'Unable to renew DHCP lease'; break}
        83 {Write-Host 'Unable to release DHCP lease'; break}
        84 {Write-Host 'IP not enabled on adapter'; break}
        85 {Write-Host 'IPX not enabled on adapter'; break}
        86 {Write-Host 'Frame/network number bounds error'; break}
        87 {Write-Host 'Invalid frame type'; break}
        88 {Write-Host 'Invalid network number'; break}
        89 {Write-Host 'Duplicate network number'; break}
        90 {Write-Host 'Parameter out of bounds'; break}
        91 {Write-Host 'Access denied'; break}
        92 {Write-Host 'Out of memory'; break}
        93 {Write-Host 'Already exists'; break}
        94 {Write-Host 'Path, file or object not found'; break}
        95 {Write-Host 'Unable to notify service'; break}
        96 {Write-Host 'Unable to notify DNS service'; break}
        97 {Write-Host 'Interface not configurable'; break}
        98 {Write-Host 'Not all DHCP leases could be released/renewed'; break}
        100 {Write-Host 'DHCP not enabled on adapter'; break}
        2147786788 {Write-Host "Write lock not enabled"; break}
        2147749891 {Write-Host "Must be run with admin privileges"; break}
        default {Write-Host "Faild with error code $($Return_Value)"; break}
    }

}
##############################################################################################################################

############################################################################################
##################### Validate DNS Address format and provided Protocol match ####
############################################################################################  
function Check_DNSIP_Format_Protocol
{
  param($Primary_DNS,$secondary_dns,$Protocol)

if($Primary_DNS -ne $null){
$Primary_DNS = "$Primary_DNS|Prim"
}
if($secondary_dns -ne $null){
$secondary_dns = "$secondary_dns|Second"
}

    if($Primary_DNS -ne $null -and $secondary_dns -ne $null){
    $dnsServers   = ("$Primary_DNS","$secondary_dns")
    }
    if($Primary_DNS -ne $null -and $secondary_dns -eq $null){
    $dnsServers   = ("$Primary_DNS")
    }
    if($Primary_DNS -eq $null -and $secondary_dns -ne $null){
    $dnsServers   = ("$secondary_dns")
    }

#write-host $dnsServers
      
    $testAddresses = $dnsServers
    $Protocol = "$Protocol"


function Test-IsValidIPv6Address 
{
    param(
        [Parameter(Mandatory=$true,HelpMessage='Enter IPv6 address to verify')] [string] $IP)
    $IPv4Regex = '(((25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))'
    $G = '[a-f\d]{1,4}'
    # In a case sensitive regex, use:
    #$G = '[A-Fa-f\d]{1,4}'
    $Tail = @(":",
        "(:($G)?|$IPv4Regex)",
        ":($IPv4Regex|$G(:$G)?|)",
        "(:$IPv4Regex|:$G(:$IPv4Regex|(:$G){0,2})|:)",
        "((:$G){0,2}(:$IPv4Regex|(:$G){1,2})|:)",
        "((:$G){0,3}(:$IPv4Regex|(:$G){1,2})|:)",
        "((:$G){0,4}(:$IPv4Regex|(:$G){1,2})|:)")
    [string] $IPv6RegexString = $G
    $Tail | foreach { $IPv6RegexString = "${G}:($IPv6RegexString|$_)" }
    $IPv6RegexString = ":(:$G){0,5}((:$G){1,2}|:$IPv4Regex)|$IPv6RegexString"
    $IPv6RegexString = $IPv6RegexString -replace '\(' , '(?:' # make all groups non-capturing
    [regex] $IPv6Regex = $IPv6RegexString
    if ($IP -imatch "^$IPv6Regex$") {
        $true
    } else {
        $false
    }
}

Function Test-IPv4Address($ipAddress) {
 if($testAddress -match "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b") {
  $addressValid = $true
 } else {
  $addressValid = $false
 }
 return $addressValid
}
#--------------------------------------------------------------------------------------------------#

$IPAddress_Protocol_Format = @()
#--------------------------------------------------------------------------------------------------#
foreach($testAddress in $testAddresses) {
$Prim_Second = ($testAddress.split('|'))[1]
$testAddress = ($testAddress.split('|'))[0]


 if((Test-IPv4Address $testAddress)) {
  #Write-Host "$testAddress is a valid formatted IPv4 Address" -foregroundColor Green

            if($Protocol -notmatch 'IPv4')
            {
              $matchs = 'Not matched'
            }
            if($Protocol -match 'IPv4')
            {
              $matchs = 'Matched'
            }            
             $IPAddress_Protocol_Format += New-Object psobject -Property @{
             "IPAddress"    = $testAddress
             "Provided Protocol"     = "$Protocol"
             "Protocol Detected"     = "IPv4"
             "Valid Format" = "YES"
             Prim_Second    = "$Prim_Second"
             "Protocol_IP Match" = "$matchs"}
             
  
 } else {
        
        if($testAddress -match ':')
         {
            if( (Test-IsValidIPv6Address $testAddress)) {
            #Write-Host "$testAddress is a valid formatted IPv6 Address" -foregroundColor Green

            if($Protocol -notmatch 'IPv6')
            {
              $matchs = 'Not matched'
            }
            if($Protocol -match 'IPv6')
            {
              $matchs = 'Matched'
            }            
             $IPAddress_Protocol_Format += New-Object psobject -Property @{
             "IPAddress"    = $testAddress
             "Provided Protocol"     = "$Protocol"
             "Protocol Detected"     = "IPv6"
             "Valid Format" = "YES"
             Prim_Second    = "$Prim_Second"
             "Protocol_IP Match" = "$matchs"}
            
            }
            else{
            #Write-Host "$testAddress is not a valid formatted IPV6 Address" -foregroundColor Red

            if($Protocol -notmatch 'IPv6')
            {
              $matchs = 'Not matched'
            }
            if($Protocol -match 'IPv6')
            {
              $matchs = 'Matched'
            }            
             $IPAddress_Protocol_Format += New-Object psobject -Property @{
             "IPAddress"    = $testAddress
             "Provided Protocol"     = "$Protocol"
             "Protocol Detected"     = "IPv6"
             "Valid Format" = "No"
             Prim_Second    = "$Prim_Second"
             "Protocol_IP Match" = "$matchs"}
                        
            }
          }
        
        if($testAddress -notmatch ':')
        {  
        #Write-Host "$testAddress is not a valid formatted IPv4 Address" -foregroundColor Red

            if($Protocol -notmatch 'IPv4')
            {
              $matchs = 'Not matched'
            }
            if($Protocol -match 'IPv4')
            {
              $matchs = 'Matched'
            }            
             $IPAddress_Protocol_Format += New-Object psobject -Property @{
             "IPAddress"    = $testAddress
             "Provided Protocol"     = "$Protocol"
             "Protocol Detected"     = "IPv4"
             "Valid Format" = "No"
             Prim_Second    = "$Prim_Second"
             "Protocol_IP Match" = "$matchs"}
                    
        }
    }
}

$global:aa = $IPAddress_Protocol_Format | select IPAddress,'Provided Protocol','Protocol Detected','Protocol_IP Match','Valid Format',Prim_Second

$Protocol_Matched_Valid_Formata0 = $global:aa | ? {$_.'Valid Format' -eq 'Yes' -and $_.'Protocol_IP Match' -eq 'Matched'}
$InValid_Format = $global:aa | ? {$_.'Valid Format' -eq 'No'} 
$Protocol_IP_Match = $global:aa | ? {$_.'Protocol_IP Match' -eq 'Not matched'}

function InValid_Format
{
param($InValid_Format,$Primary_DNS,$Secondary_DNS)
    
    if($InValid_Format -ne $null)
    {
        if(($InValid_Format).GetType().BaseType.name -eq 'Array')
        {   if($InValid_Format.IPAddress -ne ""){ 
             write-host "Invalid format of DNS Address (Primary : $("$Primary_DNS") and (Secondary : $("$Secondary_DNS").  Expected format is: 192.168.129.1, 192.168.129.254 `n" -ForegroundColor Red
             }
           }

          if(($InValid_Format).GetType().BaseType.name -eq 'Object')
           {  
              if($InValid_Format.IPAddress -ne ""){  
              
              $prim = $InValid_Format | ? {$_.Prim_Second -eq 'Prim'} | % {$_.IPAddress}
              $Sec = $global:aa | ? {$_.Prim_Second -eq 'Second'} | % {$_.IPAddress}
              
                if($Sec -ne $null -and $prim -eq $null){
                $Prim_Secc =  "Secondary"}
                if($prim -ne $null -and $Sec -eq $null){
                $Prim_Secc =  "Primary"}
                      
              write-host "Invalid format of $Prim_Secc DNS Address : $($InValid_Format.IPAddress). | Expected format is: 192.168.129.1, 192.168.129.254 `n" -ForegroundColor Red
              }
           }
     }
 }
 
if($Protocol_Matched_Valid_Formata0 -ne $null)
{
    if( ($Protocol_Matched_Valid_Formata0).GetType().BaseType.name -eq 'Object')
    {

       $1st_Phase_Result = $Protocol_Matched_Valid_Formata0

       if($1st_Phase_Result.Prim_Second -eq 'Prim')
       {
          
           InValid_Format -InValid_Format $InValid_Format -Primary_DNS $Primary_DNS 
           write-host "Process for Reachiblity test against Primary DNS Address: $($Protocol_Matched_Valid_Formata0.IPAddress)`n" -ForegroundColor Yellow

           $Global:FinalDNS1 = Check_DNS_Server_Reachability -Primary_DNS $Primary_DNS

            if($Global:FinalDNS1 -eq $null){ 
               Return ;  
           }
           else{
           $Global:FinalDNS = $Global:FinalDNS1
           Process_For_Change_Setting -networkName "$networkName"
           
           }

       }
       
       if($1st_Phase_Result.Prim_Second -eq 'Second')
       {
           InValid_Format -InValid_Format $InValid_Format -Secondary_DNS $Secondary_DNS 
           write-host "`nProcess for Reachiblity test against Secondary DNS Address: $($Protocol_Matched_Valid_Formata0.IPAddress)`n" -ForegroundColor Yellow  
           
           $Global:FinalDNS1 = Check_DNS_Server_Reachability  -Secondary_DNS $Secondary_DNS          
           
        if($Global:FinalDNS1 -eq $null){ 
           Return ;  
       }
       else{
           $Global:FinalDNS = $Global:FinalDNS1
           Process_For_Change_Setting -networkName "$networkName"

           }

       }       



       
}
    if(($Protocol_Matched_Valid_Formata0).GetType().BaseType.name -eq 'Array')
    {
       #$aa | select IPAddress,'Provided Protocol','Protocol Detected','Protocol_IP Match','Valid Format' | ft
       InValid_Format -InValid_Format $Valid_Format -Primary_DNS $Primary_DNS -Secondary_DNS $Secondary_DNS
       write-host "`nBoth DNS_Server Address are in valid format and Protocol also matched || Primary:($($Protocol_Matched_Valid_Formata0[0].IPAddress)) Secondary:($($Protocol_Matched_Valid_Formata0[1].IPAddress))`n" -ForegroundColor Yellow
       

       write-host "Process for checking Reachiblity for Both DNS_Server Address : ($($Protocol_Matched_Valid_Formata0[0].IPAddress)) and ($($Protocol_Matched_Valid_Formata0[1].IPAddress))" -ForegroundColor Yellow
       write-host ""
       $Global:FinalDNS1 = Check_DNS_Server_Reachability  -Primary_DNS "$Primary_DNS" -Secondary_DNS "$Secondary_DNS"
       
        if($Global:FinalDNS1 -eq $null){ 
           Return ;  
       }
       else{
           $Global:FinalDNS = $Global:FinalDNS1
           Process_For_Change_Setting -networkName "$networkName"

           }
    }

}
else{
       $Protocol_Matched_Valid_Formata1 | select IPAddress,'Provided Protocol','Protocol Detected','Protocol_IP Match','Valid Format' | ft
       write-host "`nInvalid DNS Address format OR DNS Address Protocol and Provided Protocol doesn't match" -ForegroundColor red
       Return $False
}

}

############################################################################################
##################### Reachability test ####
############################################################################################  
function Check_DNS_Server_Reachability
{
   param($Primary_DNS,$secondary_dns,$Protocol)

        write-host "########################"
        write-host "Reachiblity Valaidation..."
        write-host "########################"
        write-host ""
        
    if($Primary_DNS -ne $null -and $secondary_dns -ne $null){
    $dnsServers   = ("$Primary_DNS","$secondary_dns")
    }
    if($Primary_DNS -ne $null -and $secondary_dns -eq $null){
    $dnsServers   = ("$Primary_DNS")
    }
    if($Primary_DNS -eq $null -and $secondary_dns -ne $null){
    $dnsServers   = ("$secondary_dns")
    }
    
      
    $servers = $dnsServers

     $ping = new-object system.net.networkinformation.ping
     $pingreturns = @()

    foreach ($entry in $servers) {

        $Prim_Second = ($entry.split('|'))[1]
        $testAddress = ($entry.split('|'))[0]

      $pingreturns += $ping.send($testAddress) | select Status,@{name = 'Address';exp = {"$testAddress"}},@{name = 'Prim_Second';exp = {"$Prim_Second"}}
      #$pingreturns
    }

    $Success_To_contact = ($pingreturns | where {$_.Status -eq 'Success'}) | select Status,Address,Prim_Second

    $Failed_To_contact = ($pingreturns | where {$_.Status -ne 'Success'}) | select Status,Address,Prim_Second

    $Global:PRoceed_Data = @()

    if($Success_To_contact -ne $null)
    {
    $Global:PRoceed_Data += $Success_To_contact | select Address,@{name = 'Reachable Status';exp = {'YES'}},@{name = 'Process for DNS Setting Changes';exp = {'YES'}},Prim_Second
    }

    if($Failed_To_contact -ne $null)
    {
    $Global:PRoceed_Data += $Failed_To_contact | select Address,@{name = 'Reachable Status';exp = {'No'}},@{name = 'Process for DNS Setting Changes';exp = {'NO'}},Prim_Second

    }

    $Global:Process_Data_Changes     = $Global:PRoceed_Data | ? {$_.'Process for DNS Setting Changes' -eq 'YES'} | select Address,Prim_Second
    $Global:NOT_Process_Data_Changes = $Global:PRoceed_Data | ? {$_.'Reachable Status' -eq 'NO'} | % {$_.Address} | select Address,Prim_Second
    

    
    if($Global:Process_Data_Changes -ne $null)
    {
        if(($Global:Process_Data_Changes).GetType().BaseType.name -eq 'Array')
        {    
           write-host "Process for DNS Address changes (Primary : $("$Primary_DNS")) and (Secondary : $("$Secondary_DNS"))" -ForegroundColor Yellow
           $Global:DNS_TO_Process = $dnsServers -join ','
        }

        if(($Global:Process_Data_Changes).GetType().BaseType.name -eq 'Object')
        {  
          if($Global:Process_Data_Changes.Prim_Second -eq 'Prim')
          {
            $prim1 = ($Primary_DNS.split('|'))[0]
           write-host "Process for DNS Address changes (Primary : $("$prim1"))" -ForegroundColor Yellow
           $Global:DNS_TO_Process = $Process_Data_Changes    
          }
          
          if($Global:Process_Data_Changes.Prim_Second -eq 'Second')
          {
             $Second1 = ($secondary_dns.split('|'))[0]         
           write-host "Process for DNS Address changes (Secondary : $("$Second1"))" -ForegroundColor Yellow
           $Global:DNS_TO_Process = $Process_Data_Changes    
          }
          
        }
    }

 
 
 if($Global:Process_Data_Changes -eq $null)
 {
      
     if($Secondary_DNS -ne $null)
     {
      write-host "(Secondary : $("$Secondary_DNS")) DNS unreachable" -ForegroundColor red
     }
     if($Primary_DNS -ne $null)
     {
      write-host "(Primary : $("$Primary_DNS")) DNS unreachable" -ForegroundColor red
     }
 }

    $Global:Process_Data_Changes
    
    #return $DNS_TO_Process
}

############################################################################################
##################### Get Current Adapter Info ####
############################################################################################  
function Get_Current_Adapter_Info
{
param($adapterSettings)

    foreach($Network in $adapterSettings)
    {
    $IPAddress  = $Network.IpAddress[0]
    $SubnetMask  = $Network.IPSubnet[0]
    $DefaultGateway = $Network.DefaultIPGateway
    $DNSServers  = $Network.DNSServerSearchOrder
    $IsDHCPEnabled = $false
    If($network.DHCPEnabled) {
     $IsDHCPEnabled = $true
    }
    $OutputObj  = New-Object -Type PSObject
    $OutputObj | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress
    $OutputObj | Add-Member -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask
    $OutputObj | Add-Member -MemberType NoteProperty -Name Gateway -Value ($DefaultGateway -join ",")      
    $OutputObj | Add-Member -MemberType NoteProperty -Name IsDHCPEnabled -Value $IsDHCPEnabled
    $OutputObj | Add-Member -MemberType NoteProperty -Name DNSServers -Value ($DNSServers -join ",")     
    $OutputObj
    ############################################################
    ############### Re-enable network adapter   
    ############################################################
    #$networkAdapter_Index = $network.index
    #Enable_Disable_Adapter -networkAdapter_Index $networkAdapter_Index

}

}

$adapter = Gwmi win32_networkadapter | where {$_.NetConnectionID -eq $networkName}
if($adapter)
    {

      Write-Host "Found Network Adapter: ($($networkName))" -ForegroundColor Green

      $adapterSettings = Get-WmiObject win32_networkAdapterConfiguration | where {$_.index -eq $adapter.index}

        if($adapterSettings.DHCPEnabled -eq $True){
        
     write-host "`n#############################################################"
     write-host "DHCP Status for Adapter ($($networkName))"
     write-host "#############################################################`n"

        write-host "`n`nDHCP is Enabled, can't perform changes for DNS`n `n" -ForegroundColor Yellow
        return
        }


     write-host "`n#############################################################"
     write-host "Valaidation- Match DNS-Address protocol & DNS-Address Format"
     write-host "#############################################################`n"

    $Check_Format_Protocol = Check_DNSIP_Format_Protocol -Primary_DNS "$Primary_DNS" -Secondary_DNS "$Secondry_DNS" -Protocol "$Protocol_IPV4_IPV6"

    if(!$Check_Format_Protocol){
      return
    }

    if($Global:FinalDNS -eq $null){
      return
    }
    else{     
      
   }
      Write-Host '#######################################################################'
      Write-Host "Network Adapter Setting Changes for Network Adapter: ($($networkName))"
      Write-Host '#######################################################################'

    }
else
{
  Write-Host "Network Adapter (($networkName)) does not exist, Hence retrieving available Network Adapters......." -ForegroundColor Yellow
  Write-Host ''

  Write-Host '#########################################'
  Write-Host "List of available Network Adapters"
  Write-Host '#########################################'
  get-wmiobject win32_networkadapter | where {$_.netconnectionid -ne $null}| select NetConnectionID,Name,Description,NetEnabled,index | ft

}