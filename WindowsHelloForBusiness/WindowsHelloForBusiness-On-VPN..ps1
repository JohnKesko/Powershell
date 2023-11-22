<#
.SYNOPSIS
    Script intended to start Windows Hello for Business provisioning if the current user is connected via Cisco AnyConnect.
   
.DESCRIPTION
    Main Loop
    A script that detects if the logged on user is using Cisco AnyConnect and start Windows Hello for Business provisioning with a 10 second interval.
    If the script runs longer than 10 minutes, it will log and exit.
    If Windows Hello for Business is already configured, it will log and exit.

    If the user is connected to VPN, we do multiple checks:
    - Is user connected to VPN and the interface is UP and have a valid IP-address from a DHCP scope
    - Can reach internet and multiple Microsoft M365 services
    - Client is Azure Hybrid-Joined

    If all these conditions are met, we start Windows Hello for Business provisioning.

    NOTE:
    Use https://www.analyticsmarket.com/freetools/ipregex/ to specify your subnet range pattern you want to check.
    For example if yo have multiple large DHCP scopes, let's say 10.10.240.10/22 to 10.10.248.254/22
    Use the regex link to get the regex pattern.

.NOTES
    Filename: WindowsHelloForBusiness-On-VPN.ps1
    Version: 1.0
    Author: Andreas Ohlstrom (JohnKesko @github)
    Credit: Martin Bengtsson for Windows Hello for Business Detection
#> 

$logFile = "C:\temp\WindowsHelloForBusiness-On-VPN.txt"
$scriptStart = Get-Date
$networkCheckInterval = 10 # Seconds
$networkCheckTimeout = 600 # 10 min  - If validations are not met within 10 min, exit the script
$ciscoInterfaceName = "Cisco AnyConnect"
$subnetPattern = "^10\.10\.(240\.([1-9]\d|[12]\d\d)|248\.([1-9]?\d|1\d\d|2[0-4]\d|25[0-4])|24[1-7]\.([1-9]?\d|[12]\d\d))$"
$domainName = "mydomain.local"

# Logging
function WriteToLog {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$timestamp] [$Level] $Message"
}

# Check if Windows Hello for Business is configured on a client
function Detect-WindowsHelloForBusiness
{
    # Logged on user SID
    $loggedOnUserSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

    # Registry path for the PIN credential provider
    $credentialProvider = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}"

    if (Test-Path -Path $credentialProvider) 
    {
        $userSIDs = Get-ChildItem -Path $credentialProvider
        $items = $userSIDs | Foreach-Object { Get-ItemProperty $_.PsPath }
    }
    else 
    {
        WriteToLog -Message "Registry path for PIN credential provider not found. Exiting script with status 1" -Level ERROR
        exit 1
    }

    if (-not[string]::IsNullOrEmpty($loggedOnUserSID)) 
    {
        # If multiple SID's are found in registry, look for the SID belonging to the logged on user
        if ($items.GetType().IsArray) 
        {
            # LogonCredsAvailable needs to be set to 1, indicating that the credential provider is in use
            if ($items.Where({$_.PSChildName -eq $loggedOnUserSID}).LogonCredsAvailable -eq 1) 
            {
                WriteToLog -Message "[Multiple SIDs]: All good. PIN credential provider found for LoggedOnUserSID. This indicates that user is enrolled into WHfB." -Level INFO
                exit 0
            }
            # If LogonCredsAvailable is not set to 1, this will indicate that the PIN credential provider is not in use
            elseif ($items.Where({$_.PSChildName -eq $loggedOnUserSID}).LogonCredsAvailable -ne 1) 
            {
                WriteToLog -Message "[Multiple SIDs]: Not good. PIN credential provider NOT found for LoggedOnUserSID. This indicates that the user is not enrolled into WHfB." -Level WARNING
                return $false
            }
            else 
            {
                WriteToLog -Message "[Multiple SIDs]: Something is not right about the LoggedOnUserSID and the PIN credential provider. Needs investigation." -Level ERROR
                exit 1
            }
        }
        # Looking for the SID belonging to the logged on user is slightly different if there's not mulitple SIDs found in registry
        else 
        {
            if (($items.PSChildName -eq $loggedOnUserSID) -and ($items.LogonCredsAvailable -eq 1)) 
            {
                WriteToLog -Message "[Single SID]: All good. PIN credential provider found for LoggedOnUserSID. This indicates that user is enrolled into WHfB." -Level INFO
                exit 0
            }
            elseif (($items.PSChildName -eq $loggedOnUserSID) -and ($items.LogonCredsAvailable -ne 1)) 
            {
                WriteToLog -Message "[Single SID]: Not good. PIN credential provider NOT found for LoggedOnUserSID. This indicates that the user is not enrolled into WHfB." -Level WARNING
                return $false
            }
            else 
            {
                WriteToLog -Message "[Single SID]: Something is not right about the LoggedOnUserSID and the PIN credential provider. Needs investigation." -Level ERROR
                exit 1
            }
        }
    }
    else 
    {
        WriteToLog -Message "Could not retrieve SID for the logged on user. Exiting script with status 1" -Level ERROR
        exit 1
    }
}

# Check connectivity to Microsoft services
function Test-ConnectivityToMicrosoft
{
    $urls = @("https://login.microsoftonline.com", "https://login.microsoft.com", "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc")
    foreach ($url in $urls) 
    {
        try 
        {
            $response = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 5 -ErrorAction Stop
            if ($response.StatusCode -ne 200)
            {
                WriteToLog -Message "Failed to connect to $url with status code: $($response.StatusCode)" -Level ERROR
                return $false
            }
            WriteToLog -Message "Successful connection to $url" -Level INFO
        } 
        catch 
        {
            WriteToLog -Message "Failed Invoke-WebRequest to $url. Error: $_" -Level ERROR
            return $false
        }
    }

    WriteToLog -Message "Successful connection to all Microsoft services" -Level INFO
    return $true
}

# Check domain connectivity
function Test-DomainConnectivity {
    param (
        [Parameter(Mandatory=$true)]
        [string]$pattern,
        [string]$clientIp
    )

    if ($clientIp -match $pattern) 
    {
        WriteToLog -Message "Client IP is within the DHCP scope. The IP was: $($clientIp)" -Level INFO
        WriteToLog -Message "Testing connectivity to the domain using nltest" -Level INFO

        try 
        {
            $nltestOutput = nltest /sc_verify:$domainName | Out-String

            if ($nltestOutput -match "The command completed successfully") 
            {
                WriteToLog -Message "Successfully verified secure channel to the domain controller" -Level INFO
                return $true
            } 
            else 
            {
                WriteToLog -Message "Failed to verify secure channel to the domain controller. nltest output: $nltestOutput" -Level WARNING
                return $false
            }
        } 
        catch 
        {
            WriteToLog -Message "An error occurred while executing nltest: $_" -Level ERROR
            return $false
        }
    } 
    else 
    {
        WriteToLog -Message "Client IP is NOT within the DHCP scope. The IP was: $($clientIp)" -Level ERROR
        return $false
    }
}

# Check if Cisco AnyConnect Tunnel is established
function Test-IsCiscoTunnelEstablished 
{
    $interface = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match $ciscoInterfaceName -and $_.AdminStatus -eq "Up" }
    
    if ($null -ne $interface) 
    {
        $interfaceIp = Get-NetIPAddress -InterfaceIndex $interface.ifIndex | Select-Object -ExpandProperty IPAddress
        WriteToLog -Message "Found interface: $($interface.Name) with IP: $interfaceIp and description: $($interface.InterfaceDescription)" -Level INFO

        if (Test-DomainConnectivity -pattern $subnetPattern -clientIp $interfaceIp)
        {
            WriteToLog -Message "Domain connectivity successful" -Level INFO
            return $true
        }
    }

    WriteToLog -Message "Cisco AnyConnect Tunnel is not 'Up' yet - Waiting..." -Level WARNING
    return $false
}

# Check Hybrid-Join Device State
function Test-IsDeviceHybridAzureADJoined 
{
    try 
    {
        $dsregcmdOutput = dsregcmd /status | Out-String
        if ($dsregcmdOutput -match "AzureAdJoined\s*:\s*YES") 
        {
            WriteToLog -Message "Device is Azure AD Joined" -Level INFO
            WriteToLog -Message $dsregcmdOutput
            return $true
        } 
        else 
        {
            WriteToLog -Message "Device is not Azure AD Joined" -Level WARNING
            return $false
        }
    } catch 
    {
        WriteToLog -Message "Failed to execute dsregcmd /status" -Level ERROR
        return $false
    }
}

# Log startup time
WriteToLog -Message "Script start: $scriptStart" -Level INFO

# Main loop
$elapsed = 0
while ($elapsed -lt $networkCheckTimeout) 
{
    if ((Test-IsCiscoTunnelEstablished) -and (Test-ConnectivityToMicrosoft) -and (Test-IsDeviceHybridAzureADJoined) -and (Detect-WindowsHelloForBusiness -eq $false))
    {
        WriteToLog -Message "All conditions met for Windows Hello for Business Provisioning" -Level INFO
        WriteToLog -Message "Starting Windows Hello for Business Provisioning" -Level INFO
        Start-Process "ms-cxh-full://nthaad"
        break
    }

    Start-Sleep -Seconds $networkCheckInterval
    $elapsed += $networkCheckInterval
}

if ($elapsed -ge $networkCheckTimeout) 
{
    WriteToLog -Message "Failed to meet all conditions for Windows Hello for Business Provisioning within the timeout period" -Level ERROR
    exit 1
}