function VerifyConnection()
{
    $ok = $false

    $urls = @("https://enrollment.manage.microsoft.com/EnrollmentServer/Discovery.svc", "https://manage.microsoft.com/")
    foreach ($url in $urls)
    {
        $res = Invoke-WebRequest -Uri $url

        if ($res.StatusCode -eq 200)
        {
            Write-Host "Successfully lookup to: $url"
            $ok = $true
        }
        else
        {
            Write-Host "Could not reach $url"
        }
    }

    return $ok
}

function VerifyEnrollment()
{
    $key = 'SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\*'
    $keyinfo = Get-Item "HKLM:\$key"
    $tenantId = $keyinfo.name
    $id = $tenantId.Split("\")[-1]
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\$id"
    $mdmEnrollmentUrl = ($path | Get-ItemProperty -Name "MdmEnrollmentUrl")
    $mdmTermsUrl = ($path | Get-ItemProperty -Name "MdmTermsOfUseUrl")
    $mdmComplianceUrl = ($path | Get-ItemProperty -Name "MdmComplianceUrl")

    try
    {
        if (VerifyConnection)
        {    
            if ([string]::IsNullOrEmpty($mdmEnrollmentUrl))
            {
                New-ItemProperty -LiteralPath $path -Name 'MdmEnrollmentUrl' -Value 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc' -PropertyType String -Force -ea SilentlyContinue
            }
            elseif ([string]::IsNullOrEmpty($mdmTermsUrl))
            {
                New-ItemProperty -LiteralPath $path -Name 'MdmTermsOfUseUrl' -Value 'https://portal.manage.microsoft.com/TermsofUse.aspx' -PropertyType String -Force -ea SilentlyContinue
            }
            elseif ([string]::IsNullOrEmpty($mdmComplianceUrl))
            {
                New-ItemProperty -LiteralPath $path -Name 'MdmComplianceUrl' -Value 'https://portal.manage.microsoft.com/?portalAction=Compliance' -PropertyType String -Force -ea SilentlyContinue;
            }
            else
            {
                Write-Host "All Urls is set."
            }
        }
    }
    catch
    {
        Write-Host $_
    }
}

VerifyEnrollment