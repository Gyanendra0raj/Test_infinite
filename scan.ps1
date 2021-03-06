Function Initiate-DefenderScan{
    [CmdletBinding()]
    Param()
    schtasks.exe /delete /tn "Windows Defender Scan" /f
    $FilePath = "C:\San"
    if($OperationType -eq "Custom Scan"){
        if($FilePath -ne $null){
            $getdate = (get-date).AddMinutes(1).ToString("HH:mm")
        $cmd = 'cmd.exe /c'
        $command = "'%ProgramFiles%\Windows Defender\MpCmdRun.exe' -Scan -ScanType 1 -File $FilePath"
        schtasks.exe /CREATE /SC ONCE /ST $getdate /ru "SYSTEM" /TN "Windows Defender Scan" `
        /TR "$cmd $command" | Out-Null
        }
        else{
            "The File path is required for Custom Scan."
        }
    }

    elseif($OperationType -eq "Full Scan"){
        $getdate = (get-date).AddMinutes(1).ToString("HH:mm")
        $cmd = 'cmd.exe /c'
        $command = "'%ProgramFiles%\Windows Defender\MpCmdRun.exe' -Scan -ScanType 1"
        schtasks.exe /CREATE /SC ONCE /ST $getdate /ru "SYSTEM" /TN "Windows Defender Scan" `
        /TR "$cmd $command" | Out-Null
    }
    elseif($OperationType -eq "Quick Scan"){
        $getdate = (get-date).AddMinutes(1).ToString("HH:mm")
        $cmd = 'cmd.exe /c'
        $command = "'%ProgramFiles%\Windows Defender\MpCmdRun.exe' -Scan -ScanType 1"
        schtasks.exe /CREATE /SC ONCE /ST $getdate /ru "SYSTEM" /TN "Windows Defender Scan" `
        /TR "$cmd $command" | Out-Null
    }
    elseif($OperationType -eq "Stop Scan"){
        Stop-Service windefend
        Start-Service   
    }
}


$testPath1 = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$testPath2 = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Defender"
if($testPath1){
    $Defender_Status = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" | Select-Object -ExpandProperty DisableAntiSpyware
}
else{
    if($testPath2){
        $Defender_Status = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" | Select-Object -ExpandProperty DisableAntiSpyware
    }
    else{
        $global:code = 2
        $global:ErrorMessageArray = "Unable to find the status of Windows Defender."
    }
}

if($Defender_Status -eq 0){
    $defender_service = Get-Service Windefend | select -ExpandProperty Status
    if($defender_service -match "Stop"){
        Write-Host "The Windows Service is Stopped"
        Start-Service Windefend -ErrorAction SilentlyContinue -ErrorVariable startser
        $test = Get-Service Windefend | select -ExpandProperty Status
        if($test -eq "Stopped"){
            Write-Host "Error:$startser"
        }
        if($test -match "Run"){
            Initiate-DefenderScan -ErrorAction SilentlyContinue
        }
    }
    elseif($defender_service -match "Run"){
        Initiate-DefenderScan -ErrorAction SilentlyContinue
    }
}
elseif($Defender_Status -eq 1){
    "It is Disabled"
}



