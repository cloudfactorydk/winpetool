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

function IsUEFI {
    $BootMode = bcdedit | Select-String "path.*efi"
    if ($null -eq $BootMode) {
        # I think non-uefi is \Windows\System32\winload.exe
        $BootMode = "Legacy"
        return $false
    }
    else {
        # UEFI is: 
        #path                    \EFI\MICROSOFT\BOOT\BOOTMGFW.EFI
        #path                    \Windows\system32\winload.efi
        $BootMode = "UEFI"
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
    $DiskpartScript += "list vol"
    $DiskpartScript += "exit"
    $DiskpartScript | diskpart

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
    wpeutil reboot
}


function Mount-Install-WIM {
    $Letters = Get-Volume | ? drivetype -eq "CD-ROM" | select -expand DriveLetter
    $ErrorActionPreference = "SilentlyContinue"
    $Wimpaths = $Letters | % { get-childitem -Path "$($_):\" -Recurse  -include "install.wim" } | select -ExpandProperty fullname
    
    $Wimpath = $Wimpaths | select -first 1
    if ($Wimpath -eq $null) {
        throw "Cant find install.wim. Remember to mount the ISO"
    }
    $Mountpath = "c:\wim"
    mkdir $Mountpath
    Dismount-WindowsImage -Path $Mountpath -Discard
    $ErrorActionPreference = "Stop"
    Mount-WindowsImage -Path $Mountpath -ImagePath $Wimpath -Index 1 -ReadOnly

}
function Mount-And-Repair-From-Wim {
    Mount-Install-WIM
    $Mountpath = "c:\wim"
    Test-Path  $Mountpath
    mkdir "c:\temp" -ErrorAction SilentlyContinue
    remove-item "c:\windows\winsxs\pending.xml" -Force -Confirm:$false -ErrorAction SilentlyContinue
    
    $FileNameSuffix = get-date -Format "yyyyMMdd-HHmmss"
    sfc /scannow /offbootdir=C:\ /offwindir=C:\Windows /OFFLOGFILE=c:\temp\SFC$FileNameSuffix.txt
    
    $FileNameSuffix = get-date -Format "yyyyMMdd-HHmmss"
    Repair-WindowsImage -RestoreHealth -Source "c:\wim\windows\winsxs", "c:\wim\windows" -Path "c:\" -LogPath "c:\temp\DISM$FileNameSuffix.log" -LimitAccess
    
    $FileNameSuffix = get-date -Format "yyyyMMdd-HHmmss"
    sfc /scannow /offbootdir=C:\ /offwindir=C:\Windows /OFFLOGFILE=c:\temp\SFC$FileNameSuffix.txt
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
#endregion

$ErrorActionPreference = "Stop"
#$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot }else { "C:\WinPE_amd64_CF\mount\Tools" }
$WINPERoot = Split-Path (split-path (Get-Location).path)
$ScriptRoot = join-path -Path $WINPERoot -ChildPath "Tools"
Write-Output "Checking if virtio is installed"

$VirtioInstalled = IsVirtioInstalled

if ($VirtioInstalled) {
    Write-Output "Virtio is installed"
}
else {
    Write-Output "Virtio is not installed."
    Write-Output "Getting Windows version"
    $InstalledOSVersion = Get-InstalledWindowsVersion
    write-output "Installed Windows version: $InstalledOSVersion"
    Write-Output "injecting virtio"
    Inject-VirtIO -OSVersion $InstalledOSVersion

}

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



