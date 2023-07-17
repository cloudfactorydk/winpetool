#Find me here: GIT/PSScripts/WINPE VirtIO injection ISO/winpetools.ps1
#region functions

Function Get-DismTargetDir {
    $Driveletters = Get-Volume | ? drivetype -ne "CD-ROM" | select -ExpandProperty DriveLetter
    $WindowsDirs = foreach ($Driveletter in $Driveletters) {
        Get-ChildItem "$($Driveletter):\"  | ? name -eq "Windows" | select -ExpandProperty FullName 
    }

    switch ($WindowsDirs | Measure-Object | select -ExpandProperty count) {
        0 { throw "Cant find windows installation" }
        1 { $WindowsDir = $WindowsDirs }
        default {
            $WindowsDir = Select-FromStringArray -title "Select Target OS Path" -options $WindowsDirs
        }
    }
    Get-Item  $WindowsDir | select -ExpandProperty psdrive | select -ExpandProperty root
   

}


function Select-FromStringArray {
    param(
        $title = "please select",
        [string[]]$options = ("test1", "Test2")
    )
    $prompt = "`n"
    $i = 0
    foreach ($option in $options) {
        $prompt += "$i - $option`n"
        $i++
    }
    $prompt += "Select option"
    $MenuChoice = Read-Host -Prompt $prompt
    $choice = $options[$MenuChoice]
    if ($null -eq $choice) {
        throw "Invalid choice"
        
    }
    else {
        return $choice
    }
    

}
function Convert-BcdeditOutputToObject {
    param(
        $bcdeditOutput
    )
    $bcdeditOutput = bcdedit

    $VerbosePreference = "silentlyContinue"
    # Split the output into lines using both Unix-style and Windows-style line endings
    $lines = $bcdeditOutput -split "(\r?\n|\r)"

    # Initialize an array to hold the objects
    $objects = @()

    # Initialize a hash table to hold the current object's properties
    $properties = @{}

    foreach ($line in $lines) {
        Write-Verbose $line
        # Ignore header lines and separators
        if ($line -eq "" -or $line -match "-{6,}") {
            Write-Verbose "skipping line"
            continue
        }
        #Create a new object if the line is a new entry
        if ($line -match "^Windows Boot (Manager|Loader)$") {
            Write-Verbose "New object"
            if ($properties.Count -gt 0) {
                $objects += New-Object -TypeName PSObject -Property $properties
                $properties = @{}
                Write-Verbose "Old properties added to object"
            }
        }
        
        # If the line contains a property, add it to the current properties
        elseif ($line -match "(?<key>[^\s]+)\s+(?<value>.*)") {
            Write-Verbose "Adding property"
            $properties[$matches.key] = $matches.value
        }

    }

    # Add the last object if it wasn't already added
    if ($properties.Count -gt 0) {
        $objects += New-Object -TypeName PSObject -Property $properties
        Write-Verbose "Last properties added to object"

    }

    return $objects
}
    
function Test-BCD {
    
    $bcdeditOutput = bcdedit


    $bcdeditOutputAsObject = Convert-BcdeditOutputToObject -bcdeditOutput $bcdeditOutput
    


    #check if object is present with identifier {bootmgr}
    $BootMgr = $bcdeditOutputAsObject | ? identifier -eq "{bootmgr}"

    if ($null -eq $BootMgr) {
        write-warning "Bootmgr not found in BCD"
        return $false
    }

    Write-Host "Bootmgr found in BCD."
    
    write-host "Check bootmgr for device value"
    $device = $BootMgr | select -ExpandProperty device
    if ($null -eq $device) {
        write-warning "Device value not found in BCD BootMgr entry"
        return $false
    }

    write-host "Check for default value"
    $default = $BootMgr | select -ExpandProperty default
    if ($null -eq $default) {
        write-warning "Default value not found in BCD"
        return $false
    }
    
    Write-Host "Default value found in BCD. Check for OS entry"
    $OS = $bcdeditOutputAsObject | ? identifier -eq $default
    if ($null -eq $OS) {
        write-warning "OS entry not found in BCD"
        return $false
    }

    write-host "Checking OS for values in device, path, osdevice, systemroot"
    $device = $OS | select -ExpandProperty device
    if ($null -eq $device) {
        write-warning "Device value not found in BCD OS entry"
        return $false
    }

    $path = $OS | select -ExpandProperty path
    if ($null -eq $path) {
        write-warning "Path value not found in BCD OS entry"
        return $false
    }

    $osdevice = $OS | select -ExpandProperty osdevice
    if ($null -eq $osdevice) {
        write-warning "OSDevice value not found in BCD OS entry"
        return $false
    }

    $systemroot = $OS | select -ExpandProperty systemroot
    if ($null -eq $systemroot) {
        write-warning "SystemRoot value not found in BCD OS entry"
        return $false
    }

    write-host "All values found in BCD OS entry. BCD is valid"
    write-host "Also, guest os is running in UEFI: $(IsUEFI)"
    return $true

}

function IsUEFI {
    $BootMode = bcdedit | Select-String "path.*efi"
    if ($null -eq $BootMode) {
        # I think non-uefi is \Windows\System32\winload.exe
        $BootMode = "Legacy"
        write-host "Computer is running in $BootMode boot mode."
        return $false
    }
    else {
        # UEFI is: 
        #path                    \EFI\MICROSOFT\BOOT\BOOTMGFW.EFI
        #path                    \Windows\system32\winload.efi
        $BootMode = "UEFI"
        write-host "Computer is running in $BootMode boot mode."
        return $true
    }

    Write-Host "Computer is running in $BootMode boot mode."
}
Function Repair-BCD-OLD {
    # Create a new BCD store
    bcdedit /createstore bcd

    # Import the BCD store
    bcdedit /import bcd

    # Delete the temporary BCD file
    Remove-Item -Path "bcd"

    # Create the Boot Manager object
    bcdedit /create { bootmgr }

    # Configure Boot Manager options
    bcdedit /set { bootmgr } device boot
    bcdedit /timeout 30

    # Create the OS entry object
    $osGuid = (bcdedit /create /d "Windows" /application osloader | Select-String -Pattern '{.*}' -AllMatches).Matches.Value

    # Set the default OS entry
    bcdedit /default $osGuid

    # Configure OS entry values
    bcdedit /set { default } device partition=C:
    bcdedit /set { default } path \windows\system32\boot\winload.efi
    bcdedit /set { default } osdevice partition=C:
    bcdedit /set { default } systemroot \Windows
    bcdedit /set { default } detecthal yes

    # Set the OS entry display order
    bcdedit /displayorder $osGuid /addlast

}
function Repair-BCD {


    Write-Output "Getting OS path"
    $OSDriveletter = Get-DismTargetDir
    $OSPath = Join-Path -Path $OSDriveletter -ChildPath "Windows"

    
    #Drivetype 5 is CD-ROM
    Write-Output "Getting all drive letters"
    $Driveletters = get-psdrive | ? { $_.provider.name -eq "Filesystem" } | Select-Object -ExpandProperty root
    Write-Output "Found driveletters: $($Driveletters -join ", ")"
    Write-Output "Repairing BCD on all volumes"
    foreach ($Driveletter in $Driveletters) {

        "bcdboot $OSPath /s $Driveletter /f ALL"
        bcdboot $OSPath /s $Driveletter /f ALL
    } 
}

function IsVirtioInstalled {
    $DismTargetDir = Get-DismTargetDir
   
    $vioscsi = Dism /Image:$DismTargetDir /Get-Drivers | Select-String "vioscsi"
    if ($null -eq $vioscsi) {
        return $false
    }
    else {
        return $true
    }
    
}
function Inject-VirtIO {
    param (
        $OSVersion
    )
    $VirtioDriverRoot = join-path -Path $ScriptRoot -ChildPath "VirtIO_Drivers"
    
    if ($OSVersion) {
        #use parameter if given.
        $VirtioTargetSelected = Map-OSVersionToFolderName -OSVersion $OSVersion
    }
    else {
        #else ask for it
        $VirtioOptions = Get-ChildItem  $VirtioDriverRoot -Directory | select -ExpandProperty name
        $VirtioTargetSelected = Select-FromStringArray -title "Select Target OS" -options $VirtioOptions
    }
    
    $VirtioTargetPath = Join-Path -Path $VirtioDriverRoot -ChildPath $VirtioTargetSelected

    $DismTargetDir = Get-DismTargetDir
   
    Dism /Image:$DismTargetDir /Add-Driver /Driver:$VirtioTargetPath /Recurse /ForceUnsigned
    


}
function Inject-VirtIOKBFor2008R2 {
    $PackagePath = join-path -Path $ScriptRoot -ChildPath "VirtIO2008R2KB"
    $DismTargetDir = Get-DismTargetDir
    Dism /Image:$DismTargetDir /Add-Package /PackagePath:$PackagePath /IgnoreCheck /PreventPending 
}

function Exit-to-CLI {
    exit
}
function Reboot {

    Write-Host -ForegroundColor "Green" "Thank you for using Cloud Factory. Rebooting now."
    Start-Sleep -Seconds 3
    wpeutil reboot
}


function Mount-Install-WIM {

    $Letters = Get-Volume | ? drivetype -eq "CD-ROM" | select -expand DriveLetter
    $ErrorActionPreference = "SilentlyContinue"
    $Wimpaths = $Letters | % { get-childitem -Path "$($_):\" -Recurse  -include "install.wim" } | select -ExpandProperty fullname
    
    $Wimpath = $Wimpaths | select -first 1
    if ($Wimpath -eq $null) {
        write-warning "Cant find mounted iso with install.wim"

        $OSDriveletter = Get-DismTargetDir
        $DownloadFolder = Join-Path -Path $OSDriveletter -ChildPath "CloudFactory"

        Write-Output "Check if install.wim is present in $DownloadFolder"
        $Wimpath = Join-Path  $DownloadFolder "install.wim"
        if (test-path $wimpath) {
            write-host "Found install.wim in $DownloadFolder"
        }
        else {
            Write-Host "Cant find install.wim in $DownloadFolder"
            Write-Host "Downloading install.wim from dropbox"
            Download-Windows-ISO
            if (!(test-path $wimpath)) {
                throw "Cant find install.wim in $DownloadFolder. Download failed"
            }
            else {
                write-host "Download complete"

            }
        }

    }
    
    $Mountpath = Join-Path $OSDriveletter "wim"
    if (!(test-path $Mountpath)) {
        mkdir $Mountpath
    }
    Write-Output "Unmounting $Mountpath if mounted"
    try {
        Dismount-WindowsImage -Path $Mountpath -Discard
    }
    catch {}
    $ErrorActionPreference = "Stop"
    Write-Output "Mounting $Wimpath to $Mountpath"
    Mount-WindowsImage -Path $Mountpath -ImagePath $Wimpath -Index 1 -ReadOnly

}
function Mount-And-Repair-From-Wim {
    Mount-Install-WIM
    $osdriveletter = Get-DismTargetDir
    $ospath = Join-Path -Path $osdriveletter -ChildPath "Windows"
    $Mountpath = Join-Path $OSDriveletter "wim"
    $downloadfolder = Join-Path $OSDriveletter "CloudFactory"
    Test-Path  $Mountpath
    mkdir $downloadfolder -ErrorAction SilentlyContinue
    write-host "Removing pending.xml if present. To resolve pending reboot issues"
    remove-item "c:\windows\winsxs\pending.xml" -Force -Confirm:$false -ErrorAction SilentlyContinue
    
    Write-Host "Running first SFC scan"
    $FileNameSuffix = get-date -Format "yyyyMMdd-HHmmss"
    sfc /scannow /offbootdir=$osdriveletter /offwindir=$ospath /OFFLOGFILE=$downloadfolder\SFC$FileNameSuffix.txt
    
    Write-Host "Running DISM scan"
    $FileNameSuffix = get-date -Format "yyyyMMdd-HHmmss"
    Repair-WindowsImage -RestoreHealth -Source "$mountpath\windows\winsxs", "$mountpath\windows" -Path "$osdriveletter" -LogPath "$downloadfolder\DISM$FileNameSuffix.log"
    
    Write-Host "Running second SFC scan"
    $FileNameSuffix = get-date -Format "yyyyMMdd-HHmmss"
    sfc /scannow /offbootdir=$osdriveletter /offwindir=$ospath /OFFLOGFILE=$downloadfolder\SFC$FileNameSuffix.txt
}
function Copy-SysFiles {
    $Mountpath = "c:\wim"
    $Sysfile = read-host -Prompt "Indtast filnavn feks: vmbus.sys"
    $Sourcefile = Get-ChildItem -Path $Mountpath -Recurse -Include $sysfile -Force -ErrorAction SilentlyContinue | select -first 1
    $destfile = $Sourcefile.FullName -replace "\\wim", ""
    Copy-Item -Path $Sourcefile -Destination $destfile -Force -Confirm:$false
}
function Map-OSVersionToFolderName {
    param(
        [string]$OSVersion
    )
    #map os version string to foldername.
    
    #string examples:
    #Windows Server 2022 Standard
    #Windows Server 2022 Enterprise
    #Windows Server 2022 Datacenter
    #Windows Server 2019 Standard
    #Windows Server 2016 Standard
    #Windows Server 2012 R2 Standard
    #windows 10 pro
    #windows 10 enterprise

    #Foldernames
    #Windows 7 (Legacy)
    #Windows 8
    #Windows 8.1
    #Windows 10
    #Windows 11
    #Windows Server 2008 (Fedora ISO)
    #Windows Server 2008 R2 (Legacy)
    #Windows Server 2012
    #Windows Server 2012 R2
    #Windows Server 2016
    #Windows Server 2019
    #Windows Server 2022

    # Define the mapping
    $mapping = @{
        "Windows Server 2022"    = "Windows Server 2022"
        "Windows Server 2019"    = "Windows Server 2019"
        "Windows Server 2016"    = "Windows Server 2016"
        "Windows Server 2012 R2" = "Windows Server 2012 R2"
        "Windows Server 2012"    = "Windows Server 2012"
        "Windows Server 2008 R2" = "Windows Server 2008 R2 (Legacy)"
        "Windows Server 2008"    = "Windows Server 2008 (Fedora ISO)"
        "windows 10"             = "Windows 10"
        "windows 8.1"            = "Windows 8.1"
        "windows 8"              = "Windows 8"
        "windows 7"              = "Windows 7 (Legacy)"
    }

    # Iterate over the keys in the mapping
    foreach ($key in $mapping.Keys) {
        # Check if the OS version string contains the key
        if ($OSVersion -match $key) {
            # Return the corresponding folder name
            return $mapping[$key]
        }
    }

    # If no match is found, return a default value
    return "Unknown OS Version"
}
function Get-InstalledWindowsVersion {
    $DismTargetDir = Get-DismTargetDir
    $SoftwarePath = Join-Path -Path $DismTargetDir -ChildPath "Windows\system32\config\SOFTWARE"
    reg load HKLM\TEMPHIVE $SoftwarePath
    $Version = (Get-ItemProperty -Path "HKLM:\TEMPHIVE\Microsoft\Windows NT\CurrentVersion" -Name "ProductName").ProductName
    reg unload HKLM\TEMPHIVE
    return $Version
}

function Get-LinkFromOSVersion {
    param (
        $OSVersion
    )
    
    #more specific names first. Like 2012 R2 before 2012
    $Mapping = @{
        2022      = "https://www.dropbox.com/scl/fi/hc2oupby2evxxqqnjxkox/install.wim?rlkey=y42rwfmetz0y9ms1e1zcl8p3n&dl=1"
        2019      = "https://www.dropbox.com/scl/fi/0k79s60h8d5verq17ai23/install.wim?rlkey=7bqru2cdsxd4zj3laafr0eu2g&dl=1"
        2016      = "https://www.dropbox.com/scl/fi/cafgqkcd6rzrhnc565nfj/install.wim?rlkey=rsqw6k371on3gj8hucr2wpw1g&dl=1"
        '2012 R2' = "https://www.dropbox.com/scl/fi/owdrhifw2p6f3jjoc4hmj/install.wim?rlkey=ct24e3loqq6ri7sytggzsgyvz&dl=1"
        2012      = "https://www.dropbox.com/scl/fi/l8a260ovdsmrm6j78dp4z/install.wim?rlkey=5gxnivcil1q8xqskpdk8elj4i&dl=1"

    }

    # Iterate over the keys in the mapping
    foreach ($key in $mapping.Keys) {
        # Check if the OS version string contains the key
        if ($OSVersion -match $key) {
            # Return the corresponding folder name
            return $mapping[$key]
        }
    }
    throw "Cant find link for OS version: $OSVersion"
}


function Download-Windows-ISO {
    $WindowsVersion = Get-InstalledWindowsVersion
    write-host "Installed Windows version: $WindowsVersion"
    $URI = Get-LinkFromOSVersion -OSVersion $WindowsVersion
    
    $OSDriveletter = Get-DismTargetDir
    $DownloadFolder = Join-Path -Path $OSDriveletter -ChildPath "CloudFactory"
    if (!(test-path $DownloadFolder)) {
        mkdir $DownloadFolder
    }
    $wimpath = Join-Path  $DownloadFolder "install.wim"
    write-host "Downloading from $URI"
    write-host "Saving to $wimpath"
    Write-Host "Please have patience. This can take a while."
    
    #download iso to $isofolder using webclient
    # Start the download as a job
    $job = Start-Job -ScriptBlock {
        param($URI, $wimpath)
        $WebClient = New-Object System.Net.WebClient
        $WebClient.DownloadFile($URI, $wimpath)
        $WebClient.Dispose()
    } -ArgumentList $URI, $wimpath
    
    # Initialize previous file size and time
    $prevFileSize = 0
    $prevTime = Get-Date
    
    # Wait for the download to finish and show progress
    while ($job.State -eq 'Running') {
        try {
            if (Test-Path $wimpath) {
                $fileSize = (Get-Item $wimpath).Length
                $currentTime = Get-Date
    
                # Calculate download speed in Mbps
                $deltaSize = $fileSize - $prevFileSize
                $deltaTime = $currentTime - $prevTime
                [int]$downloadSpeed = ($deltaSize * 8) / ($deltaTime.TotalSeconds * 1MB)
                Write-Host "Current download speed: $downloadSpeed Mbps" -NoNewline 

                #Show total downloaded MB
                [int]$totalDownloaded = $fileSize / 1MB
                Write-Host " - Total downloaded: $totalDownloaded MB"
    
                # Update previous file size and time
                $prevFileSize = $fileSize
                $prevTime = $currentTime
            }
        }
        catch { "Waiting for download to start" }
        Start-Sleep -Seconds 5
    }
    
    # Remove the job after it's done
    Remove-Job -Job $job
}
    
#mount iso




    
        

#endregion

$ErrorActionPreference = "Stop"
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot }else { "x:\tools" }
#$WINPERoot = Split-Path (split-path (Get-Location).path)
#$ScriptRoot = join-path -Path $WINPERoot -ChildPath "Tools"

#region selfheal
Write-Output "Assigning drive letters to all volumes"
$DiskpartScript = @()
$DiskpartScript += "select vol 0"
$DiskpartScript += "assign"
$DiskpartScript += "select vol 1"
$DiskpartScript += "assign"
$DiskpartScript += "select vol 2"
$DiskpartScript += "assign"
$DiskpartScript += "select vol 3"
$DiskpartScript += "assign"
$DiskpartScript += "select vol 4"
$DiskpartScript += "assign"
$DiskpartScript += "select vol 5"
$DiskpartScript += "assign"
$DiskpartScript += "select vol 6"
$DiskpartScript += "assign"
$DiskpartScript += "select vol 7"
$DiskpartScript += "assign"
$DiskpartScript += "select vol 8"
$DiskpartScript += "assign"
$DiskpartScript += "select vol 9"
$DiskpartScript += "assign"
$DiskpartScript += "list vol"
$DiskpartScript += "exit"
$DiskpartScript | diskpart

Write-Output "Checking if virtio is installed"

$VirtioInstalled = IsVirtioInstalled

if ($VirtioInstalled) {
    Write-host -ForegroundColor "Green" "Virtio is installed"
}
else {
    try {
        Write-host -ForegroundColor "Yellow" "Virtio is not installed."
        Write-Output "Getting Windows version"

        $InstalledOSVersion = Get-InstalledWindowsVersion
        write-output "Installed Windows version: $InstalledOSVersion"
        Write-Output "injecting virtio"
        Inject-VirtIO -OSVersion $InstalledOSVersion
    }
    catch {
        write-warning "Auto install of virtio failed."
        Write-Warning $_ | Out-String
    }
}
try {
    write-output "Validating BCD store"
    $BCDValid = Test-BCD
    if ($BCDValid) {
        write-host -ForegroundColor "Green" "BCD store is valid"
    }
    else {
        write-host -ForegroundColor "yellow" "BCD store is not valid"
        write-host -ForegroundColor "Green" "Repairing BCD store"
        Repair-BCD
        write-host -ForegroundColor "Green" "BCD store is repaired."
    }
}
catch {
    write-warning "BCD store validation failed."
    Write-Warning $_ | Out-String
}
#endregion
#region main loop
while ($true) {
    try {
        $Action = Select-FromStringArray -title "Choose Action" -options @(
            "Inject-VirtIO"
            "Inject-VirtIOKBFor2008R2"
            "Mount-Install-WIM"
            "Mount-And-Repair-From-Wim"
            "Repair-BCD"
            "Reboot"
            "Exit-to-CLI"
            

        )
        $ActionSB = ([scriptblock]::Create($action))
        Invoke-Command -ScriptBlock $ActionSB
    }
    catch {
        Write-Warning $_ | Out-String
    }
}

#endregion

