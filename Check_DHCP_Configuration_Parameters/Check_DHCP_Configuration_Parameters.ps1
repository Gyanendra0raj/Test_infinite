cls
$Global:Adapters  = @()
$Global:STDOUT = @()
##############################
######Check PreCondition######
##############################


######################################### Convert to JSON Function
#####################################
################ Create STDerr data
######################################
function Get_stderr
{
param($Title,$details)
$info = @()
$ID = 0

 $details | %{
    $info += new-object psobject -Property @{
    "id" = $ID
    "title" = $Title
    "detail" = $_
    }
    $ID++
    }

return $info
}

function Get_DataObject
{
param($Title,$details)
$info = @()

 $details | %{
    $info += new-object psobject -Property @{
    "title" = $Title
    "Status" = $_
    }
    $ID++
    }
return $info
}

#####################################
##########################################################################
#####################################
function FormatString {
    param(
        [String] $String)
    # removed: #-replace '/', '\/' `
    # This is returned 
    $String -replace '\\', '\\' -replace '\n', '\n' `
        -replace '\u0008', '\b' -replace '\u000C', '\f' -replace '\r', '\r' `
        -replace '\t', '\t' -replace '"', '\"'
}

function GetNumberOrString {
    param(
        $InputObject)
    if ($InputObject -is [System.Byte] -or $InputObject -is [System.Int32] -or `
        ($env:PROCESSOR_ARCHITECTURE -imatch '^(?:amd64|ia64)$' -and $InputObject -is [System.Int64]) -or `
        $InputObject -is [System.Decimal] -or $InputObject -is [System.Double] -or `
        $InputObject -is [System.Single] -or $InputObject -is [long] -or `
        ($Script:CoerceNumberStrings -and $InputObject -match $Script:NumberRegex)) {
        Write-Verbose -Message "Got a number as end value."
        "$InputObject"
    }
    else {
        Write-Verbose -Message "Got a string as end value."
        """$(FormatString -String $InputObject)"""
    }
}

function ConvertToJsonInternal {
    param(
        $InputObject, # no type for a reason
        [Int32] $WhiteSpacePad = 0)
    [String] $Json = ""
    $Keys = @()
    Write-Verbose -Message "WhiteSpacePad: $WhiteSpacePad."
    if ($null -eq $InputObject) {
        Write-Verbose -Message "Got 'null' in `$InputObject in inner function"
        $null
    }
    elseif ($InputObject -is [Bool] -and $InputObject -eq $true) {
        Write-Verbose -Message "Got 'true' in `$InputObject in inner function"
        $true
    }
    elseif ($InputObject -is [Bool] -and $InputObject -eq $false) {
        Write-Verbose -Message "Got 'false' in `$InputObject in inner function"
        $false
    }
    elseif ($InputObject -is [HashTable]) {
        $Keys = @($InputObject.Keys)
        Write-Verbose -Message "Input object is a hash table (keys: $($Keys -join ', '))."
    }
    elseif ($InputObject.GetType().FullName -eq "System.Management.Automation.PSCustomObject") {
        $Keys = @(Get-Member -InputObject $InputObject -MemberType NoteProperty |
            Select-Object -ExpandProperty Name)
        Write-Verbose -Message "Input object is a custom PowerShell object (properties: $($Keys -join ', '))."
    }
    elseif ($InputObject.GetType().Name -match '\[\]|Array') {
        Write-Verbose -Message "Input object appears to be of a collection/array type."
        Write-Verbose -Message "Building JSON for array input object."
        #$Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + "[`n" + (($InputObject | ForEach-Object {
        $Json += "[`n" + (($InputObject | ForEach-Object {
            if ($null -eq $_) {
                Write-Verbose -Message "Got null inside array."
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + "null"
            }
            elseif ($_ -is [Bool] -and $_ -eq $true) {
                Write-Verbose -Message "Got 'true' inside array."
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + "true"
            }
            elseif ($_ -is [Bool] -and $_ -eq $false) {
                Write-Verbose -Message "Got 'false' inside array."
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + "false"
            }
            elseif ($_ -is [HashTable] -or $_.GetType().FullName -eq "System.Management.Automation.PSCustomObject" -or $_.GetType().Name -match '\[\]|Array') {
                Write-Verbose -Message "Found array, hash table or custom PowerShell object inside array."
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + (ConvertToJsonInternal -InputObject $_ -WhiteSpacePad ($WhiteSpacePad + 4)) -replace '\s*,\s*$' #-replace '\ {4}]', ']'
            }
            else {
                Write-Verbose -Message "Got a number or string inside array."
                $TempJsonString = GetNumberOrString -InputObject $_
                " " * ((4 * ($WhiteSpacePad / 4)) + 4) + $TempJsonString
            }
        #}) -join ",`n") + "`n],`n"
        }) -join ",`n") + "`n$(" " * (4 * ($WhiteSpacePad / 4)))],`n"
    }
    else {
        Write-Verbose -Message "Input object is a single element (treated as string/number)."
        GetNumberOrString -InputObject $InputObject
    }
    if ($Keys.Count) {
        Write-Verbose -Message "Building JSON for hash table or custom PowerShell object."
        $Json += "{`n"
        foreach ($Key in $Keys) {
            # -is [PSCustomObject]) { # this was buggy with calculated properties, the value was thought to be PSCustomObject
            if ($null -eq $InputObject.$Key) {
                Write-Verbose -Message "Got null as `$InputObject.`$Key in inner hash or PS object."
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": null,`n"
            }
            elseif ($InputObject.$Key -is [Bool] -and $InputObject.$Key -eq $true) {
                Write-Verbose -Message "Got 'true' in `$InputObject.`$Key in inner hash or PS object."
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": true,`n"            }
            elseif ($InputObject.$Key -is [Bool] -and $InputObject.$Key -eq $false) {
                Write-Verbose -Message "Got 'false' in `$InputObject.`$Key in inner hash or PS object."
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": false,`n"
            }
            elseif ($InputObject.$Key -is [HashTable] -or $InputObject.$Key.GetType().FullName -eq "System.Management.Automation.PSCustomObject") {
                Write-Verbose -Message "Input object's value for key '$Key' is a hash table or custom PowerShell object."
                $Json += " " * ($WhiteSpacePad + 4) + """$Key"":`n$(" " * ($WhiteSpacePad + 4))"
                $Json += ConvertToJsonInternal -InputObject $InputObject.$Key -WhiteSpacePad ($WhiteSpacePad + 4)
            }
            elseif ($InputObject.$Key.GetType().Name -match '\[\]|Array') {
                Write-Verbose -Message "Input object's value for key '$Key' has a type that appears to be a collection/array."
                Write-Verbose -Message "Building JSON for ${Key}'s array value."
                $Json += " " * ($WhiteSpacePad + 4) + """$Key"":`n$(" " * ((4 * ($WhiteSpacePad / 4)) + 4))[`n" + (($InputObject.$Key | ForEach-Object {
                    #Write-Verbose "Type inside array inside array/hash/PSObject: $($_.GetType().FullName)"
                    if ($null -eq $_) {
                        Write-Verbose -Message "Got null inside array inside inside array."
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + "null"
                    }
                    elseif ($_ -is [Bool] -and $_ -eq $true) {
                        Write-Verbose -Message "Got 'true' inside array inside inside array."
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + "true"
                    }
                    elseif ($_ -is [Bool] -and $_ -eq $false) {
                        Write-Verbose -Message "Got 'false' inside array inside inside array."
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + "false"
                    }
                    elseif ($_ -is [HashTable] -or $_.GetType().FullName -eq "System.Management.Automation.PSCustomObject" `
                        -or $_.GetType().Name -match '\[\]|Array') {
                        Write-Verbose -Message "Found array, hash table or custom PowerShell object inside inside array."
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + (ConvertToJsonInternal -InputObject $_ -WhiteSpacePad ($WhiteSpacePad + 8)) -replace '\s*,\s*$'
                    }
                    else {
                        Write-Verbose -Message "Got a string or number inside inside array."
                        $TempJsonString = GetNumberOrString -InputObject $_
                        " " * ((4 * ($WhiteSpacePad / 4)) + 8) + $TempJsonString
                    }
                }) -join ",`n") + "`n$(" " * (4 * ($WhiteSpacePad / 4) + 4 ))],`n"
            }
            else {
                Write-Verbose -Message "Got a string inside inside hashtable or PSObject."
                # '\\(?!["/bfnrt]|u[0-9a-f]{4})'
                $TempJsonString = GetNumberOrString -InputObject $InputObject.$Key
                $Json += " " * ((4 * ($WhiteSpacePad / 4)) + 4) + """$Key"": $TempJsonString,`n"
            }
        }
        $Json = $Json -replace '\s*,$' # remove trailing comma that'll break syntax
        $Json += "`n" + " " * $WhiteSpacePad + "},`n"
    }
    $Json
}

function ConvertTo-Json2 {
    [CmdletBinding()]
    #[OutputType([Void], [Bool], [String])]
    param(
        [AllowNull()]
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
        $InputObject,
        [Switch] $Compress,
        [Switch] $CoerceNumberStrings = $false)
    begin{
        $JsonOutput = ""
        $Collection = @()
        # Not optimal, but the easiest now.
        [Bool] $Script:CoerceNumberStrings = $CoerceNumberStrings
        [String] $Script:NumberRegex = '^-?\d+(?:(?:\.\d+)?(?:e[+\-]?\d+)?)?$'
        #$Script:NumberAndValueRegex = '^-?\d+(?:(?:\.\d+)?(?:e[+\-]?\d+)?)?$|^(?:true|false|null)$'
    }
    process {
        # Hacking on pipeline support ...
        if ($_) {
            Write-Verbose -Message "Adding object to `$Collection. Type of object: $($_.GetType().FullName)."
            $Collection += $_
        }
    }
    end {
        if ($Collection.Count) {
            Write-Verbose -Message "Collection count: $($Collection.Count), type of first object: $($Collection[0].GetType().FullName)."
            $JsonOutput = ConvertToJsonInternal -InputObject ($Collection | ForEach-Object { $_ })
        }
        else {
            $JsonOutput = ConvertToJsonInternal -InputObject $InputObject
        }
        if ($null -eq $JsonOutput) {
            Write-Verbose -Message "Returning `$null."
            return $null # becomes an empty string :/
        }
        elseif ($JsonOutput -is [Bool] -and $JsonOutput -eq $true) {
            Write-Verbose -Message "Returning `$true."
            [Bool] $true # doesn't preserve bool type :/ but works for comparisons against $true
        }
        elseif ($JsonOutput-is [Bool] -and $JsonOutput -eq $false) {
            Write-Verbose -Message "Returning `$false."
            [Bool] $false # doesn't preserve bool type :/ but works for comparisons against $false
        }
        elseif ($Compress) {
            Write-Verbose -Message "Compress specified."
            (
                ($JsonOutput -split "\n" | Where-Object { $_ -match '\S' }) -join "`n" `
                    -replace '^\s*|\s*,\s*$' -replace '\ *\]\ *$', ']'
            ) -replace ( # these next lines compress ...
                '(?m)^\s*("(?:\\"|[^"])+"): ((?:"(?:\\"|[^"])+")|(?:null|true|false|(?:' + `
                    $Script:NumberRegex.Trim('^$') + `
                    ')))\s*(?<Comma>,)?\s*$'), "`${1}:`${2}`${Comma}`n" `
              -replace '(?m)^\s*|\s*\z|[\r\n]+'
        }
        else {
            ($JsonOutput -split "\n" | Where-Object { $_ -match '\S' }) -join "`n" `
                -replace '^\s*|\s*,\s*$' -replace '\ *\]\ *$', ']'
        }
    }
}

function ConvertTo-Json20([object] $item){
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer
    return $ps_js.Serialize($item)
}

function ConvertFrom-Json20([object] $item){ 
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer

    #The comma operator is the array construction operator in PowerShell
    return ,$ps_js.DeserializeObject($item)
}


function HashTable_Array_JSON{
Param($HeadingUnder_dataObject_Array,$Array,$taskName,$status,$Code,$stdout,$stderr,$objects,$result)

if($psversiontable.PSVersion.Major -eq 2)
{
    if($stderr -eq $null){
    $axa = ConvertTo-Json2 -InputObject @{taskName = "$taskName";status = "$status";Code = "$Code";stdout = @("$stdout");objects = "$objects";result = "$result"
    dataObject = @{"$HeadingUnder_dataObject_Array" = @($Array)}
    }
    }

    if($stderr -ne $null){
    $axa = ConvertTo-Json2 -InputObject @{taskName = "$taskName";status = "$status";Code = "$Code";stdout = @("$stdout");result = "$result"
        stderr = @($stderr)
    }
    }
}else
{
#write-host 'its not Version 2'
    if($stderr -eq $null){
     $HashTable = [ordered]@{taskName = "$taskName";status = "$status";Code = "$Code";stdout = @("$stdout");objects = "$objects";result = "$result"
        dataObject = @{"$HeadingUnder_dataObject_Array" = @($Array)}
        }
    $axa = ConvertTo-Json -InputObject $HashTable -Depth 100
    }

    if($stderr -ne $null){
    $HashTable = [ordered]@{taskName = "$taskName";status = "$status";Code = "$Code";result = "$result";stdout = @("$stdout")
        stderr = @($stderr)
    }
    $axa = ConvertTo-Json -InputObject $HashTable -Depth 100
    }
}
#$BackTOHasTable = ConvertFrom-Json20 $axa
#$BackTOHasTable
$axa
}
######################################### Convert to JSON --END



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
######################################################################
#################################################################################################

$ErrorActionPreference = 'silentlycontinue'
$All_Adapters = Gwmi win32_networkadapter | where {$_.NetConnectionID -ne $null} | select NetConnectionID,index

$Configured_DHCP = @()
$No_DHCP_Configured = @()

foreach($All_Adapters1 in $All_Adapters)
{
$adapterSettings = Get-WmiObject win32_networkAdapterConfiguration | where {$_.index -eq $All_Adapters1.index}

$AdapterName = $All_Adapters1.NetConnectionID

            if($adapterSettings.DHCPEnabled)
            {
              
              $Configured_DHCP1 += new-object PSObject -property @{ 
              "DHCP Status" = 'Enabled'
              "SubnetMask" = ($adapterSettings.IPSubnet)[0]
              "Default Gateway" = ($adapterSettings.DefaultIPGateway)[0]
               DHCPServer = $adapterSettings.DHCPServer
              "DNSServer" = $adapterSettings | % {$_.DNSServerSearchOrder -join ','}
              "WINSPrimaryServer" = $adapterSettings.WINSPrimaryServer 
              "WINSSecondaryServer" = $adapterSettings.WINSSecondaryServer 
              "DHCPLeaseExpires" = "$($adapterSettings | % {$_.ConvertToDateTime($_.DHCPLeaseExpires)})"
              "Adapter Name" = "$AdapterName"
              } | select "Adapter Name","DHCP Status",DHCPServer,DHCPLeaseExpires,"SubnetMask","Default Gateway",DNSServer,WINSPrimaryServer,WINSSecondaryServer
              
              
              $Global:STDOUT += "Adapter Name: $($Configured_DHCP1.'Adapter Name')`r`nDHCP Status: $($Configured_DHCP1.'DHCP Status')`r`nDHCPServer: $($Configured_DHCP1.'DHCPServer')`r`nDHCPLeaseExpires: $($Configured_DHCP1.'DHCPLeaseExpires')`r`nSubnetMask: $($Configured_DHCP1.'SubnetMask')`r`nDefault Gateway: $($Configured_DHCP1.'Default Gateway')`r`nDNSServer: $($Configured_DHCP1.'DNSServer')`r`nWINSPrimaryServer: $($Configured_DHCP1.'WINSPrimaryServer')`r`nWINSSecondaryServer: $($Configured_DHCP1.'WINSSecondaryServer')`r`n"
              
              $Configured_DHCP += $Configured_DHCP1
            }
}

if($Configured_DHCP.count -gt 0)
{   write-host "`n##################################################"
    write-host "Network Adapter information Which enabled with DHCP"
    write-host "####################################################"
    $Configured_DHCP
    
    $ObjectCount = $Configured_DHCP.count
    $Global:HashData = HashTable_Array_JSON -HeadingUnder_dataObject_Array "Adapters configuration Information" -Array $Configured_DHCP -taskName 'Check DHCP Configuration Parameters' -status 'Success' -Code '0' -stdout $Global:STDOUT -objects "$ObjectCount" -result 'Success: Retrived DHCP enabled network adapter information'


}
if($Configured_DHCP.count -eq 0)
{
    write-host "`n`nNo DHCP servers are providing configuration parameters." -ForegroundColor red

     $Global:Error_Msg  = "No DHCP servers are providing configuration parameters"
     $Global:STDErr = Get_stderr -Title 'No Adapter found enabled with DHCP' -details "$Global:Error_Msg"  

     $Global:HashData = HashTable_Array_JSON -taskName 'Check DHCP Configuration Parameters' -status 'Failed' -Code '1' -stdout "no adapter found enabled with DHCP" -result 'Error: no adapter found enabled with DHCP' -stderr $Global:STDErr
    
}
$Global:HashData