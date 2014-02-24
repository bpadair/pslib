Function New-DNSRecord {
    [CmdletBinding()]
    Param(
            [Parameter(Mandatory=$True,Position=1)]
            [string]$hostName,
            [Parameter(Mandatory=$True,Position=2)]
            [string]$ip
    )

    Add-DnsServerResourceRecordA -ZoneName ad.microcenter.com -Name $hostName -IPv4Address $ip -CreatePTR -ComputerName 10.10.1.56
    Add-DnsServerResourceRecordCName -ZoneName microcenter.com -Name $hostName -HostNameAlias "$hostName.ad.microcenter.com" -ComputerName 10.10.1.56

}

function New-RandomPass {
    [CmdletBinding()]
    Param(
            [Parameter(Mandatory=$True,Position=1)]
            [int]$numChars
    )

    $chars = @("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")")
    $pass = @()

    $pass = $chars | Get-Random -count $numChars

    $pass = -join $pass

    return $pass

}

function Disable-TCPOffloadEngine {
    [CmdletBinding()]
    Param(
            [Parameter(Mandatory=$True,Position=1)]
            [string]$computerName
    )

    Invoke-Command -ComputerName $computerName -ScriptBlock {netsh int tcp set global chimney=disabled}

}

Write-Host "Creating aliases..."

#Command aliases
New-Alias -Force -Name ic -Value Invoke-Command

#Administrative Tools aliases
New-Alias -Force -Name aduc -Value $env:SystemRoot\system32\dsa.msc -Description "UtilityLib.ps1"
New-Alias -Force -Name adss -Value $env:SystemRoot\system32\dssite.msc -Description "UtilityLib.ps1"
New-Alias -Force -Name addt -Value $env:SystemRoot\system32\domain.msc -Description "UtilityLib.ps1"
New-Alias -Force -Name gpmc -Value $env:SystemRoot\system32\gpmc.msc -Description "UtilityLib.ps1"
New-Alias -Force -Name adsi -Value $env:SystemRoot\system32\adsiedit.msc -Description "UtilityLib.ps1"
New-Alias -Force -Name dns -Value $env:SystemRoot\system32\dnsmgmt.msc -Description "UtilityLib.ps1"
New-Alias -Force -Name fcm -Value $env:SystemRoot\system32\Cluadmin.msc -Description "UtilityLib.ps1"
New-Alias -Force -Name dhcp -Value $env:SystemRoot\system32\dhcpmgmt.msc -Description "UtilityLib.ps1"
New-Alias -Force -Name srvman -Value $env:SystemRoot\system32\ServerManager.exe -Description "UtilityLib.ps1"
New-Alias -Force -Name wsus -Value "C:\Program Files\Update Services\administrationsnapin\wsus.msc" -Description "UtilityLib.ps1"
New-Alias -Force -Name emc -Value "C:\Program Files\Microsoft\Exchange Server\V14\Bin\Exchange Management Console.msc" -Description "UtilityLib.ps1"
New-Alias -Force -Name centrify -Value "C:\Program Files (x86)\Centrify\Centrify DirectControl\centrifydc.msc" -Description "UtilityLib.ps1"
New-Alias -Force -Name netbackup -Value "C:\Program Files\Veritas\NetBackup\bin\NBConsole.EXE" -Description "UtilityLib.ps1"

#Allows output to be piped to the system clipboard
New-Alias -Force -Name Set-Clipboard -Value $env:SystemRoot\System32\clip.exe -Description "UtilityLib.ps1"

#List aliases from this library
function Get-LibAlias
{
	Get-Alias | Where-Object {$_.Description -match "UtilityLib\.ps1"}
}

#Sets the properties of the console window based on the current user account
function Set-Env
{
    Write-Host "Setting UI properties..."
	if ($currentPrincipal.Identity.Name -eq $SAIdentityName)
	{
		(get-host).UI.RawUI.Backgroundcolor = $profileSABackgroundColor
		$host.UI.RawUI.WindowTitle = "PowerShell" + $profileSAWindowTitleSuffix
	}
	elseif ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ))
    {
        (get-host).UI.RawUI.Backgroundcolor = $profileLocalAdminBackgroundColor
		$host.UI.RawUI.WindowTitle = "PowerShell" + $profileLocalAdminWindowTitleSuffix
    }
}

function Set-WindowTitle ($title)
{
	$host.UI.RawUI.WindowTitle = $title
	if ($currentPrincipal.Identity.Name -eq $currentIdentityName)
	{
		$host.UI.RawUI.WindowTitle = $host.UI.RawUI.WindowTitle + $profileSAWindowTitleSuffix
	}
	elseif ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ))
    {
		$host.UI.RawUI.WindowTitle = $host.UI.RawUI.WindowTitle + $profileLocalAdminWindowTitleSuffix
	}
}

function New-Email ($relay, $from, $to, $cc, $bcc, $subject, $body, $attachment, $html = $TRUE)
{
    $message = New-Object System.Net.Mail.MailMessage
    $message.From = $from
    $message.To.Add($to)
    if ($cc -gt "")
    {
        $message.CC.Add($cc)
    }
    if ($bcc -gt "")
    {
        $message.Bcc.Add($bcc)
    }
    
    $message.Subject = $subject
    
    $message.IsBodyHtml = $html
    $message.Body = $body
    if ($attachment -gt "")
    {
        $attachmentTemp = New-Object System.Net.Mail.Attachment -ArgumentList $attachment
        $message.Attachments.Add($attachmentTemp)
    }
    $smtp = New-Object System.Net.Mail.SMTPClient -ArgumentList $relay
    $smtp.Send($message)
}

#Load a file in Notepad++
function npp ($file)
{
	#if ($language) {$language = "-l" + $language}
	& 'C:\Program Files (x86)\Notepad++\notepad++.exe' $file
}

#Start a new PowerShell session using SA account
function New-SASession
{
	runas /user:$SAIdentityName "cmd /c start powershell"
}

#Run VMware vSphere Client as SA
function New-vCenterSession ($Computer)
{
	& runas /user:$SAIdentityName "C:\Program Files (x86)\VMware\Infrastructure\Virtual Infrastructure Client\Launcher\VpxClient.exe -passthroughAuth -s $Computer"
}

function New-Symlink 
{
    Param(
        [Parameter(Mandatory=$true,Position=1)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$false)][switch]$Hard,
        [Parameter(Mandatory=$false)][switch]$Junction
    )

    <#
    .SYNOPSIS
    Creates a symbolic, hard, or juction link.

    .DESCRIPTION
    Creates a symbolic, hard, or juction link.
    
    .PARAMETER Name
    The path of the link.
    
    .PARAMETER Target
    The relative or absolute path to the target of the link.

    .PARAMETER Hard
    Specifies that the link should be a hard link. By default a soft (symbolic) link is created.

    .PARAMETER Junction
    Specifies that the link should be a junction.  By default a soft (symbolic) link is created.
    #>

    if (($Hard -eq $true) -and ($Junction -eq $true))
    {
        Write-Error -Message "ERROR: The link cannot be both a hard and juction type!" -ErrorAction Stop
    }
    elseif ($Hard -eq $true)
    {
        cmd /c mklink /h $Path $Target
    }
    elseif ($Junction -eq $true)
    {
        cmd /c mklink /j $Path $Target
    }
    else
    {
        cmd /c mklink /d $Path $Target
    }
}

function Install-Zabbix
{
    Param(
        [Parameter(Mandatory=$true,Position=1)][string]$Server
    )

    cp \\ad\software\retail\zabbix\win32\* \\$Server\c$\
    cp \\ad\software\retail\zabbix\* \\$Server\c$\
    Invoke-Command -ComputerName $Server -ScriptBlock { c:\zabbix_agentd.exe -i }
    Invoke-Command -ComputerName $Server -ScriptBlock { c:\zabbix_agentd.exe -s }
}

function Remove-2012Gui
{
	Param(
		[Parameter(Mandatory=$true,Position=1)][string]$server
	)

	Get-WindowsFeature -Name *gui* -ComputerName $server | Remove-WindowsFeature -computerName $server
	Restart-Computer -ComputerName $server
}

function Install-2012Gui
{

	Param(
		[Parameter(Mandatory=$true,Position=1)][string]$server
	)

	Get-WindowsFeature -name *gui* -ComputerName $server | Add-WindowsFeature -computerName $server
	Restart-Computer -ComputerName $server
}
