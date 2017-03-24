<#PSScriptInfo
.GUID
	d572020a-7583-4867-a845-bb9737b1ecd8
.VERSION 
	1.0.0.4
.AUTHOR 
	Michael Haken
.COMPANYNAME 
	BAMCIS
.COPYRIGHT 
	(c) 2016 BAMCIS. All rights reserved.
.TAGS 
	WMI InstallData Version
.LICENSEURI 
	https://github.com/bamcisnetworks/OSInstallData/LICENSE
.PROJECTURI
	https://github.com/bamcisnetworks/OSInstallData
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
	Provided minor bug fixes.
#>

<#
	.SYNOPSIS
		Creates the Win32_OSInstallData WMI class on the local computer or a remote computer.

	.DESCRIPTION
		The cmdlet creates a custom WMI class for enumerating information about when an OS image was deployed. It creates a temporary mof file on the SystemDrive and calls mofcomp.exe to add the WMI class.

	.PARAMETER Increment
		The sequential increment number for the version during the current quarter. Valid range is 0 to 999.
		
	.PARAMETER ComputerName
		The computer to create the custom WMI classes on. This defaults to localhost. If the target is a remote computer, Invoke-Command is used to execute the underlying function.

	.PARAMETER TempFilePath
		Where the temporary mof file is stored, this defaults to %SYSTEMDRIVE%\OSInstallData_$([System.Guid]::NewGuid()).mof.

	.PARAMETER Credential
		The credential to use to connect to a remote computer. This parameter is ignored if the ComputerName is localhost, ".", or 127.0.0.1.

    .EXAMPLE
		Set-OSInstallData

		Creates the custom WMI class on the local computer with an increment number of 0 which results in 16.1.000 if it was the first quarter of 2016.

	.EXAMPLE
		Set-OSInstallData -Increment 12

		Creates the custom WMI class on the local computer with an increment number of 12 which results in 16.1.012 if it was the first quarter of 2016.

	.EXAMPLE
		Set-OSInstallData -ComputerName server1.contoso.com -Credential (Get-Credential)

		Creates the custom WMI class on server1.contoso.com with an increment number of 0 which results in 16.1.000 if it was the first quarter of 2016..

	.INPUTS
		System.Int32, System.String, System.String

	.OUTPUTS
		None

	.NOTES
		AUTHOR: Michael Haken
		LAST UPDATE: 1/15/2017
#>

Param
(
	[Parameter(Position = 0, ValueFromPipeline = $true)]
	[ValidateScript({$_ -ge 0 -and $_ -le 999})]
    [System.Int32]$Increment = 0,

    [Parameter(Position = 1)]
    [System.String]$ComputerName = [System.String]::Empty,

	[Parameter(Position = 2)]
	[System.String]$TempFilePath = "$env:SYSTEMDRIVE\OSInstallData_$([System.Guid]::NewGuid()).mof",

    [Parameter()]
	[ValidateNotNull()]   
    [System.Management.Automation.Credential()]
    [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty
)

Function Set-OSInstallDataWMIClass
{
	<#
		.SYNOPSIS
			Creates the Win32_OSInstallData WMI class on the local computer or a remote computer.

		.DESCRIPTION
			The cmdlet creates a custom WMI class for enumerating information about when an OS image was deployed. It creates a temporary mof file on the SystemDrive and calls mofcomp.exe to add the WMI class.

		.PARAMETER Increment
			The sequential increment number for the version during the current quarter. Valid range is 0 to 999.
		
		.PARAMETER TempFilePath
			Where the temporary mof file is stored, this defaults to %SYSTEMDRIVE%\OSInstallData_$([System.Guid]::NewGuid()).mof.

		.PARAMETER RegistryKeyName
			The name of the registry key to create in HKLM:\Software to store the install data. This defaults to OSInstallData.

		.EXAMPLE
			Set-OSInstallDataWMIClass

			Creates the custom WMI class on the local computer with an increment number of 0 which results in 16.1.000 if it was the first quarter of 2016.

		.EXAMPLE
			Set-OSInstallDataWMIClass -Increment 12

			Creates the custom WMI class on the local computer with an increment number of 12 which results in 16.1.012 if it was the first quarter of 2016.

		.INPUTS
			System.Int32

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 1/15/2017
	#>
    Param 
    (
        [Parameter(Position=0, ValueFromPipeline = $true)]
		[ValidateScript({$_ -ge 0 -and $_ -le 999})]
        [System.Int32]$Increment = 0,

		[Parameter(Position=1)]
		[System.String]$TempFilePath = "$env:SYSTEMDRIVE\OSInstallData_$([System.Guid]::NewGuid()).mof",

		[Parameter(Position=2)]
		[System.String]$RegistryKeyName = "OSInstallData"		
    )
    Begin
    {
        if (!([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        {
			throw "Script must be run with administrator privileges."
		}

		if ([System.String]::IsNullOrEmpty($RegistryKeyName)) {
			$RegistryKeyName = "OSInstallData"
		}
        
		$Path = "HKLM:\SOFTWARE\$RegistryKeyName"
        $WmiClass = "Win32_OSInstallData"

        $FileContent = @"
#pragma namespace("\\\\.\\root\\cimv2")
#PRAGMA AUTORECOVER

[DYNPROPS]
Class $WmiClass
{
    [key] string KeyName;
    Uint32 InstallDate;
    Uint32 VersionMajor;
    Uint32 VersionMinor;
    Uint32 VersionIncrement;
    String DisplayVersion;
    String DisplayInstallDate;
};

[DYNPROPS]
Instance of $WmiClass
{
    KeyName="OS Install Data";
    [PropertyContext("Local|HKEY_LOCAL_MACHINE\\SOFTWARE\\$RegistryKeyName|InstallDate"),Dynamic,Provider("RegPropProv")] InstallDate;
    [PropertyContext("Local|HKEY_LOCAL_MACHINE\\SOFTWARE\\$RegistryKeyName|VersionMajor"),Dynamic,Provider("RegPropProv")] VersionMajor;
    [PropertyContext("Local|HKEY_LOCAL_MACHINE\\SOFTWARE\\$RegistryKeyName|VersionMinor"),Dynamic,Provider("RegPropProv")] VersionMinor;
    [PropertyContext("Local|HKEY_LOCAL_MACHINE\\SOFTWARE\\$RegistryKeyName|VersionIncrement"),Dynamic,Provider("RegPropProv")] VersionIncrement;
    [PropertyContext("Local|HKEY_LOCAL_MACHINE\\SOFTWARE\\$RegistryKeyName|DisplayVersion"),Dynamic,Provider("RegPropProv")] DisplayVersion;
    [PropertyContext("Local|HKEY_LOCAL_MACHINE\\SOFTWARE\\$RegistryKeyName|DisplayInstallDate"),Dynamic,Provider("RegPropProv")] DisplayInstallDate;
};
"@
    }

    Process
    {
		if ([System.String]::IsNullOrEmpty($TempFilePath)) {
			$TempFilePath = "$env:SYSTEMDRIVE\OSInstallData_$([System.Guid]::NewGuid()).mof"
		}

        New-Item -Path $Path -Force | Out-Null
        [DateTime]$Date = (Get-Date).ToUniversalTime()
        New-ItemProperty -Path $Path -Name "InstallDate" -Value (Get-Date -Date $Date -UFormat "%s") -PropertyType ([Microsoft.Win32.RegistryValueKind]::DWord) -Force | Out-Null
        New-ItemProperty -Path $Path -Name "DisplayInstallDate" -Value (Get-Date).ToShortDateString() -PropertyType ([Microsoft.Win32.RegistryValueKind]::String) -Force | Out-Null

        switch ($Date.Month)
        {
            default {$Quarter = 1}
            1 {$Quarter = 1}
            2 {$Quarter = 1}
            3 {$Quarter = 1}
            4 {$Quarter = 2}
            5 {$Quarter = 2}
            6 {$Quarter = 2}
            7 {$Quarter = 3}
            8 {$Quarter = 3}
            9 {$Quarter = 3}
            10 {$Quarter = 4}
            11 {$Quarter = 4}
            12 {$Quarter = 4}
        }

        New-ItemProperty -Path $Path -Name "VersionMajor" -Value $Date.Year.ToString().Substring(2) -PropertyType ([Microsoft.Win32.RegistryValueKind]::DWord) -Force | Out-Null
        New-ItemProperty -Path $Path -Name "VersionMinor" -Value $Quarter -PropertyType ([Microsoft.Win32.RegistryValueKind]::DWord) -Force | Out-Null
        New-ItemProperty -Path $Path -Name "VersionIncrement" -Value $Increment -PropertyType ([Microsoft.Win32.RegistryValueKind]::DWord) -Force | Out-Null
        $IncrementString = $Increment.ToString()

        while ($IncrementString.Length -lt 3)
        {
            $IncrementString = "0" + $IncrementString
        }

        New-ItemProperty -Path $Path -Name "DisplayVersion" -Value ($Date.Year.ToString().Substring(2) + "." + $Quarter + "." + $IncrementString) -Force | Out-Null
        Set-Content -Path $TempFilePath -Value $FileContent | Out-Null

        $Wmi = Get-CimInstance -ClassName $WmiClass -Namespace "root/cimv2" -ErrorAction SilentlyContinue
        
		if ($Wmi -ne $null)
        {
            Remove-CimInstance -InputObject $Wmi
        }

		$InstallType = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType | Select-Object -ExpandProperty InstallationType

		if ($InstallType -eq "Nano Server") 
		{
			Start-Process -FilePath ($env:SystemRoot + "\system32\wbem\mofcomp.exe") -ArgumentList @($TempFilePath) -Wait | Out-Null
		}
		else 
		{
			Start-Process -FilePath ($env:SystemRoot + "\system32\wbem\mofcomp.exe") -ArgumentList @($TempFilePath) -WindowStyle Hidden -Wait | Out-Null
		}

		$Counter = 0

		while ($Counter -lt 30) 
		{
			try 
			{
				Remove-Item -Path $TempFilePath -ErrorAction Stop -Force | Out-Null
				break
			}
			catch [Exception] 
			{
				$Counter++

				if ($Counter -ge 30) 
				{
					Write-Warning "Timeout waiting to delete the temporary mof file, delete manually."
					break
				}

				Start-Sleep -Seconds 1
			}
		}

		$Wmi = Get-CimClass -ClassName $WMIClass -Namespace "root/cimv2" -ErrorAction SilentlyContinue

        if ($Wmi -ne $null)
        {
            Write-Host "Creating the WMI class was successful." -ForegroundColor Green
        }
        else
        {
            Write-Host "There was an error creating the class." -ForegroundColor Red
        }
    }

    End {
	}
}

[bool]$Local = [System.String]::IsNullOrEmpty($ComputerName) -or `
	$ComputerName -eq "." -or `
	$ComputerName.ToLower() -eq "localhost" -or `
	$ComputerName.ToLower() -eq $ENV:COMPUTERNAME.ToLower() -or `
	$ComputerName -eq "127.0.0.1"

if ($Local)
{
	Set-OSInstallDataWMIClass -Increment $Increment -TempFilePath $TempFilePath   
}
else
{
    Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:Set-OSInstallDataWMIClass} -ArgumentList @($Increment, $TempFilePath) -Credential $Credential 
}