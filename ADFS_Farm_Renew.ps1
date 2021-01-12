param($result)
Import-Module ADFS

####################
### INSTRUCTIONS ###
####################
# In order for this script to work, you must create a service admin account
# that has local admin rights on all servers involved. You must make sure that
# CertifyTheWeb runs the script as your service user and that remote PowerShell
# access is enabled.
#
# This script will renew the certificate and then copy it to all dependent servers
# before importing it to the local Certificate store on each participating computer.
# Once Imported, it will initiate the Renewal on the Primary ADFS server which will
# propegate changes to all other nodes.

##Variables
### Fill out the variables for all ADFS servers
$adfsHostname = "adfs.company.com"
$adfsServers = @(
    "srv1adfs1"
    "srv1adfs2"
)
### Fill out the variables for all ADFS Proxy servers
$wapServers = @(
    "srv1wap1"
    "srv1wap2"
)

## Script paramaters
$pfxFile = Get-ChildItem $result.ManagedItem.CertificatePath
$pfxName = $pfxFile.Name
$pfxFile = [string]$pfxFile
$pfxThumbprint = $result.ManagedItem.CertificateThumbprintHash

Function Certificate-Copy {
    param([string]$pfxFile, [string]$remoteDestinationPath)
    If(!(test-path "filesystem::$remoteDestinationPath"))
        { New-Item -ItemType Directory -Force -Path $remoteDestinationPath }
    Copy-Item -Path $pfxFile -Destination $remoteDestinationPath -force
}

Function Certificate-Import {
    param([string]$server, [string]$localPFX)
    $session = New-PSSession -computername "$server"
    #$certName = "$certPath" + "$pfxName"
    Invoke-Command -Session $session -ScriptBlock {
        param([string]$localPFX)
        Import-PfxCertificate -filepath "$localPFX" -CertStoreLocation Cert:\LocalMachine\My
        } -Args $localPFX
    Remove-PsSession $session
}

Function Check-ADFSHeirarchy {
    param([string]$server)
    $session = New-PSSession -computername "$server"
    Invoke-Command -Session $session -ScriptBlock {
        param([string]$server)
        Get-AdfsSyncProperties
        } -Args $server
    Remove-PsSession $session
}

Function ADFS-Certificate-Bind {
    param($pfxThumbprint)
    Set-AdfsSslCertificate -Thumbprint $pfxThumbprint
    Restart-Service adfssrv
}
Function WAP-Certificate-Bind {
    param($pfxThumbprint)
    #Set-WebApplicationProxySslCertificate -Thumbprint $thumbPrint
    #Restart-Service adfssrv
}

## Run script for ADFS Proxy Servers
foreach ($server in $wapServers) {
    $remoteDestinationPath = '\\' + "$server" + "\c$\ProgramData\Certify\assets\$adfsHostname\"
    $localPath = "C:\ProgramData\Certify\assets\$adfsHostname\"
    $localPFX = "$localPath" + "$pfxName"
    Certificate-Copy $pfxFile $remoteDestinationPath
    Certificate-Import $server $localPFX
    WAP-Certificate-Bind $pfxThumbprint
}

## Run script for ADFS Servers
### Reorder ADFS Servers to place Primary at bottom of the list
$adfsSecondary = @()
foreach ($server in $adfsServers) {
    $adfsRole = Check-ADFSHeirarchy $server
    if ($adfsRole.Role -eq "PrimaryComputer") {
        $adfsPrimary = $server
    } Else {
        $adfsSecondary += $server
    }
    $adfsSortedList = $adfsSecondary + $adfsPrimary
}
### Run through ADFS servers in new order
foreach ($server in $adfsSortedList) {
    $adfsRole = Check-ADFSHeirarchy $server
    if ($adfsRole.Role -eq "PrimaryComputer") {
        ADFS-Certificate-Bind $pfxThumbprint
    } Else {
    $remoteDestinationPath = '\\' + "$server" + "\c$\ProgramData\Certify\assets\$adfsHostname\"
    $localPath = "C:\ProgramData\Certify\assets\$adfsHostname\"
    $localPFX = "$localPath" + "$pfxName"
    Certificate-Copy $pfxFile $remoteDestinationPath
    Certificate-Import $server $localPFX
    }
}
