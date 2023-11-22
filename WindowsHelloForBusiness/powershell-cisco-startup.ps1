$logFile = "C:\temp\VPNConnectivityLog-Startup.txt"
$startupTime = Get-Date
$networkCheckInterval = 10 # Seconds
$networkCheckTimeout = 600 # 10 min  - If all validation is not met within 10 min, exit the script
$ciscoInterfaceName = "Cisco AnyConnect"

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

# Function to check if Cisco AnyConnect Management Tunnel is established
function IsCiscoTunnelEstablished 
{
    $interface = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match $ciscoInterfaceName -and $_.AdminStatus -eq "Up" }
    
if ($null -ne $interface) 
{
    $interfaceIp = Get-NetIPAddress -InterfaceIndex $interface.ifIndex | Select-Object -ExpandProperty IPAddress
    WriteToLog -Message "Found interface: $($interface.Name) with IP: $interfaceIp and description: $($interface.InterfaceDescription)" -Level INFO
    return $true
}

    
    WriteToLog -Message "Cisco AnyConnect Management Tunnel is not 'Up' yet - Waiting..." -Level WARNING
    return $false
}

# Function to connectivity to Microsoft
# Function to check connectivity to Microsoft services
function ConnectivityToMicrosoft
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

# Check Hybrid-Join Device State
function IsDeviceHybridAzureADJoined 
{
    try 
    {
        $dsregcmdOutput = dsregcmd /status | Out-String
        if ($dsregcmdOutput -match "AzureAdJoined\s*:\s*YES" -and $dsregcmdOutput -match "OnPremTgt\s*:\s*YES" -and $dsregcmdOutput -match "CloudTgt\s*:\s*YES") 
        {
            WriteToLog -Message "Device is Azure AD Joined" -Level INFO
            WriteToLog -Message $dsregcmdOutput
            return $true
        } 
        else 
        {
            WriteToLog -Message "Device is not correctly Azure AD Joined" -Level WARNING
            return $false
        }
    } catch 
    {
        WriteToLog -Message "Failed to execute dsregcmd /status" -Level ERROR
        return $false
    }
}

# Log startup time
WriteToLog -Message "Computer startup at: $startupTime" -Level INFO

# Main loop
$elapsed = 0
while ($elapsed -lt $networkCheckTimeout) 
{
    if ((IsCiscoTunnelEstablished) -and (ConnectivityToMicrosoft) -and (IsDeviceHybridAzureADJoined))
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
}