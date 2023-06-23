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

    Write-Output "Repairing BCD on all volumes"
    #Drivetype 5 is CD-ROM
    $Driveletters = Get-WmiObject -Class Win32_Volume | ? drivetype -ne 5 | select -ExpandProperty DriveLetter 
    "running commands:"
    foreach ($Driveletter in $Driveletters) {

        
        "bcdboot $OSPath /s $Driveletter /f ALL"
        bcdboot $OSPath /s $Driveletter /f ALL
    } 
}


function Inject-VirtIO {

    $VirtioDriverRoot = join-path -Path $ScriptRoot -ChildPath "VirtIO_Drivers"
    $VirtioOptions = Get-ChildItem  $VirtioDriverRoot -Directory | select -ExpandProperty name
    $VirtioTargetSelected = Select-FromStringArray -title "Select Target OS" -options $VirtioOptions
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
#endregion

$ErrorActionPreference = "Stop"
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot }else { "C:\WinPE_amd64_CF\mount\Tools" }
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
        Write-Warning $_ |Out-String
    }
}



