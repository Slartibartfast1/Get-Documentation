# ======================================= #
#            Get-Documentation            #
# ======================================= #
# Author: Mark Durham
# Date: 06/04/2017
#
# ======================================= #
#               Changelog                 #
# ======================================= #
# v0.1 - Created script
# v0.2 - Added some error handling to clean up output
# v0.3 - Now a cmdlet
# v1.0 - Added help text scrubbed identifying data
#
#
# ======================================= #
#              Begin Script               #
# ======================================= #

function global:Get-Documentation{
    
    <#
        .SYNOPSIS
        Create documentaion for all servers within an OU and child OUs.

        .DESCRIPTION
        Retrieves hardware and software configuration settings from all computers within a root OU and it's child OUs 
        then writes them to a file for each computer.

        .PARAMETER OU

        Specifies the root OU to use as the searchbase. Default= OU=TEST,DC=EXAMPLE,DC=LOCAL

        .PARAMETER Folder

        Sets the destination path for the completed documentation. The files will be stored in their own folder structure of \ocumentation\Servers\ within the specified path. Default= C:\

        .EXAMPLE
        Get-Documentation 'OU=Servers,DC=DOMAIN,DC=LOCAL'

        Scans all servers within and below the Servers OU in the DOMAIN.LOCAL domain. Then stores the created files in C:\Documentation\Servers


        .EXAMPLE
        Get-Documentation -OU 'OU=Servers,OU=GB,DC=EXAMPLE,DC=LOCAL' -Folder 'C:\Administration\'
        
        Scans all servers within and below the Servers OU in the EXAMPLE.LOCAL domain. Then stores the created files in C:\Administration\Documentation\Servers  
    
    #>

    # ======================================= #
    #           Binding/Parameters            #
    # ======================================= #

    [CmdletBinding(
    DefaultParameterSetName="OU"
    )]

    PARAM(
    [parameter(Mandatory=$true,
    Position=0,
    ValueFromPipeline=$false,
    HelpMessage="Root Organizational Unit containting all computer accounts to be scanned.")]
    [STRING[]]$OU = "OU=TEST,DC=EXAMPLE,DC=LOCAL",

    [parameter(Mandatory=$false,
    Position=1,
    ValueFromPipeline=$false,
    HelpMessage="Destination folder for completed documentation files.")]
    [STRING[]]$Folder = "C:\"
    )

    # ======================================= #
    #               Variables                 #
    # ======================================= #

    Begin {
        $destination = New-item -path $folder[0] -ItemType directory -name "Documentation\Servers"
    }

    Process {
        $servers = Get-ADComputer -searchbase $OU[0] -filter * -Properties Name, OperatingSystem, MemberOf, Description, CanonicalName, DistinguishedName
    

        # ======================================= #
        #               Functions                 #
        # ======================================= #

        # Get general system details
        function Get-SystemDetails ($target)
        {
            $hostname = $target.Name
            $OSVersion = $target.OperatingSystem
            $description = $target.description
            try {
                $roles = Get-windowsfeature -ComputerName $target.DNSHostName -ErrorAction Stop | Where {($_.Installed -eq $true) -and ($_.featuretype -eq 'Role')} | Select-Object -Property Name
            } Catch {
                $errTarget = $target.Name
                Write-Warning "Get-WindowsFeature Failed on $errTarget"
            }
            "==========="
            "`r`nSystem"
            "`r`n==========="
            "`r`nHostname: $hostname"
            "`r`nOS: $OSVersion"
            "`r`nDescription: $description"
            "`r`nRoles: "
            $roles | Out-String
        }

        # Get general hardware details
        function Get-HardwareDetails ($target)
        {
            "==========="
            "`r`nHardware"
            "`r`n==========="
            try {
                $system = Get-wmiobject -Class "Win32_Computersystem" -namespace "root\CIMV2" -computername $target.name -ErrorAction Stop
            } catch {
                $errTarget = $target.Name
                Write-Warning "Get-WmiObject failed on $errTarget"
            }
            $manufacturer = $system.Manufacturer
            $model = "NULL"
            $model = $system.Model
            if ($manufacturer -eq "Gigabyte Technology Co., Ltd." -and $model -eq "To be filled by O.E.M.") {
                $model = "Zoostorm"
                "`r`nModel: $model"
            } else {
                "`r`nManufacturer: $manufacturer"
                "`r`nModel: $model"
            }
        }

        # Get AD details
        function Get-ADDetails ($target)
        {
            $cn = $target.CanonicalName
            $domain = $cn.Substring(0,$cn.IndexOf('/')) # manipulate string to store everything up to the 1st '/'
            $dn = $servers[7].DistinguishedName
            $dnComma = $dn.IndexOf(',')
            $OU = $dn.substring($dnComma+1) # manipulate string to store everything after the 1st ','
            $groups = $target.MemberOf
            "==========="
            "`r`nAD"
            "`r`n==========="
            "`r`nDomain: $domain"
            "`r`nOU: $OU"
            "`r`nGroups: $groups"
        }

        # Returns RAM details
        function Get-MemoryDetails ($target)
        {
            try {
                $colSlots = Get-WmiObject -Class "win32_PhysicalMemoryArray" -namespace "root\CIMV2" -computerName $target.name -ErrorAction Stop
            } catch {
                $errTarget = $target.Name
                Write-Warning "Get-WmiObject failed on $errTarget"
            }
            try {
                $colRAM = Get-WmiObject -Class "win32_PhysicalMemory" -namespace "root\CIMV2" -computerName $target.name -ErrorAction Stop
            } catch {
                $errTarget = $target.Name
                Write-Warning "Get-WmiObject failed on $errTarget"
            }
            $totalSlots = 0
            $totalSticks = 0
            $totalInstalled = 0

            "==========="
            "`r`nRAM"
            "`r`n==========="

            Foreach ($objRAM In $colRAM) {
                ""
                "`r`nSlot: " + $objRAM.DeviceLocator
                "`r`n------------"
                $formFactor =  $objRAM.FormFactor
                switch ($formFactor) {
                    0 {"`r`n    Form Factor: Unknown"}
                    1 {"`r`n    Form Factor: Other"}
                    6 {"`r`n    Form Factor: Proprietary"}
                    8 {"`r`n    Form Factor: DIMM"}
                    12 {"`r`n    Form Factor: SODIMM"}
                    Default {"`r`n    ERROR: Memory Form Factor Could not be Determined"}
                }

                $prefix = "NULL"
                $memoryType = $objRAM.MemoryType
                switch ($memoryType) {
                   0 {"`r`n    Type: Unknown"; $prefix = "??-"}
                   1 {"`r`n    Type: Other"}
                   2 {"`r`n    Type: DRAM"}
                   3 {"`r`n    Type: Synchronous DRAM"}
                   4 {"`r`n    Type: Cache DRAM"}
                   5 {"`r`n    Type: EDO"}
                   6 {"`r`n    Type: EDRAM"}
                   7 {"`r`n    Type: VRAM"}
                   8 {"`r`n    Type: SRAM"}
                   9 {"`r`n    Type: RAM"}
                   10 {"`r`n    Type: ROM"}
                   11 {"`r`n    Type: Flash"}
                   12 {"`r`n    Type: EEPROM"}
                   13 {"`r`n    Type: FEPROM"}
                   14 {"`r`n    Type: EDPROM"}
                   15 {"`r`n    Type: CDRAM"}
                   16 {"`r`n    Type: 3DRAM"}
                   17 {"`r`n    Type: SDRAM"}
                   18 {"`r`n    Type: SGRAM"}
                   19 {"`r`n    Type: RDRAM"}
                   20 {"`r`n    Type: DDR"; $prefix = "PC-"}
                   21 {"`r`n    Type: DDR2"; $prefix = "PC2-"}
                   22 {"`r`n    Type: DDR2 FB-DIMM"}
                   24 {"`r`n    Type: DDR3"; $prefix = "PC3-"}
                   25 {"`r`n    Type: FBD2"}
                   Default {"`r`n    ERROR: Memory Type Could not be Determined"}
                }

                "`r`n    Size: " + ($objRAM.Capacity / 1GB) + " GB"
                "`r`n    Speed: " + ($objRAM.Speed) + " MHz"
                "`r`n------------"
                $totalSticks = $totalSticks + 1
                $totalInstalled = $totalInstalled + ($objRAM.Capacity / 1GB)
                ""
            }
            ""
            "`r`nTotal Installed: $totalInstalled GB"
            ""
            Foreach ($objSlot In $colSlots){
                "`r`nTotal Slots: " + $objSlot.MemoryDevices
                $totalSlots = $objSlot.MemoryDevices
            }    
            $freeSlots = $totalSlots - $totalSticks
            "`r`nFree Slots: $freeSlots"
        }

        # Get CPU details
        function Get-CPUDetails ($target)
        {
            try {
                $CPUWMI = Get-WmiObject -Class win32_processor -namespace "root\CIMV2" -ComputerName $target.Name -ErrorAction Stop
            } catch {
                $errTarget = $target.Name
                Write-Warning "Get-WmiObject failed on $errTarget"
            }
            $CPUint = 1
            "==========="
            "`r`nCPU"
            "`r`n==========="
            foreach ($CPU in $CPUWMI) {
                "`r`nSocket {0}: " -f $CPUint
                "`r`n      Model: {0}" -f $CPU.Name
                "`r`n      Cores: {0}" -f $CPU.numberofcores
                "`r`n      Threads: {0}" -f $CPU.numberoflogicalprocessors
                "`r`n      Speed: " + ($CPU.maxclockspeed / 1000) + " GHz"
                $CPUint += 1
            }
        }

        # Get storage details
        function Get-StorageDetails ($target)
        {
            try {
                $diskDrives = Get-WmiObject -Class win32_diskdrive -namespace "root\CIMV2" -ComputerName $target.Name -ErrorAction Stop
            } catch {
                $errTarget = $target.Name
                Write-Warning "Get-WmiObject failed on $errTarget"
            }
            "==========="
            "`r`nStorage"
            "`r`n==========="
            $driveInt = 1
            Foreach ($objDrive In $diskDrives){
                 #"Drive: " + $objDrive.Name
                 $diskSize = [Math]::Floor($objDrive.Size / 1000000000)
                 "`r`nDrive {0}: {1} GB     {2}" -f $driveInt, $diskSize, $objDrive.Model
                 $driveInt += 1
            }
        }

        # Get networking details
        function Get-NetworkDetails ($target)
        {
            "==========="
            "`r`nNetwork"
            "`r`n==========="
            try {
                $NICs = Get-WMIObject -Class Win32_NetworkAdapter -ComputerName $target.name -filter "netconnectionstatus = 2" -ErrorAction Stop | Select-Object netconnectionid, MACAddress, Speed
            } catch {
                $errTarget = $target.Name
                Write-Warning "Get-WmiObject failed on $errTarget"
            }
            foreach ($NIC in $NICs) {
                try {
                    $IPAddress= Invoke-command -ComputerName $target.Name -ScriptBlock {param($remoteNIC) Get-NetIPAddress -InterfaceAlias $remoteNIC.netconnectionid} -ArgumentList $NIC -ErrorAction Stop
                } catch {
                    $errTarget = $target.Name
                    Write-Warning "Invoke-Command failed on $errTarget trying to run Get-NetIPAddress"
                }
            "`r`nConnection: {0}" -f $NIC.netconnectionid
                "`r`n        IP: {0}" -f $IPAddress.IPAddress
                "`r`n       MAC: {0}" -f $NIC.MACAddress
            }
        }

        # Returns installed application details
        function Get-AppDetails ($target)
        {
            try {
                $applications = Invoke-Command -computername $target.Name -scriptblock {Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Format-Table –AutoSize} -ErrorAction Stop
            } catch {
                $errTarget = $target.Name
                Write-Warning "Invoke-Command failed on $errTarget trying to run Get-ItemProperty"
            }
            "==========="
            "`r`nApplications"
            "`r`n==========="
            "`r`nInstalled Software:"
            $applications | Out-String
        }

        # Creates a file and write details to it
        function Write-Documentation ($target, $path=$destination, $systemArg=$systemDetails, $hardwareArg=$hardwareDetails, $ADArg=$addetails, $memoryArg=$memoryDetails, $CPUArg=$CPUDetails, $storageArg=$storageDetails, $networkArg=$networkDetails, $AppArg=$AppDetails)
        {
            $date = Get-Date
            #Create file
            $dest = "$path\{0}.txt" -f $target.name
            $file = New-Item -Type file -Path $dest -value "Created automatically with Get-Documentation script`r`nLast updated: $date"
            # Append System info
            Add-Content $file "`r`n$systemArg"
            # Append hardware info
            Add-content $file "`r`n$hardwareArg"
            # Append AD info
            Add-Content $file "`r`n$adArg"
            # Append memory info
            Add-Content $file "`r`n$memoryArg"
            # Append CPU info
            Add-content $file "`r`n$CPUArg"
            # Append storage info
            Add-Content $file "`r`n$storageArg"
            # Append network info
            Add-Content $file "`r`n$networkArg"
            # Append application info
            Add-Content $file "`r`n$AppArg"
        }

        # ======================================= #
        #               Main Loop                 #
        # ======================================= #

        # Main loop
        foreach ($server in $servers) {
            if (Test-Connection -ComputerName $server.DNSHostName -Count 2 -Quiet) {
                $systemDetails = Get-SystemDetails -target $server
                $hardwareDetails = Get-HardwareDetails -target $server
                $ADDetails = get-addetails -target $server
                $memoryDetails = Get-MemoryDetails -target $server
                $CPUDetails = Get-CPUDetails -target $server
                $storageDetails = Get-StorageDetails -target $server
                $networkDetails = Get-NetworkDetails -target $server
                $AppDetails = Get-AppDetails -target $server

                Write-Documentation -target $server
            } else {
            $errTarget = $server.Name
                Write-Warning "$errTarget did not respond"
            }
        }
    }

    End {}
}