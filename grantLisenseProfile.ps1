$p = $person | ConvertFrom-Json;
$aRef = $accountReference | ConvertFrom-Json;
$pRef = $permissionReference | ConvertFrom-Json;
$c = $configuration | ConvertFrom-Json;

$success = $false;
$auditLogs = [Collections.Generic.List[PSCustomObject]]::New();

#region functions
function Get-LisaAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $TenantId,

        [Parameter(Mandatory = $true)]
        [string]
        $ClientId,

        [Parameter(Mandatory = $true)]
        [string]
        $ClientSecret,

        [Parameter(Mandatory = $true)]
        [string]
        $Scope
    )

    try {
        $headers = [System.Collections.Generic.Dictionary[[String],[String]]]::New()
        $headers.Add("Content-Type", "application/x-www-form-urlencoded")

        $body = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = $Scope
        }

        $splatRestMethodParameters = @{
            Uri     = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token/"
            Method  = 'POST'
            Headers = $headers
            Body    = $body
        }
        Invoke-RestMethod @splatRestMethodParameters
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions

if (-not($dryRun -eq $true)) {
    try {
        $splatGetTokenParams = @{
            TenantId     = $c.AADtenantID
            ClientId     = $c.AADAppId
            ClientSecret = $c.AADAppSecret
            Scope        = $c.Scope
        }

        $accessToken = (Get-LisaAccessToken @splatGetTokenParams).access_token
        $authorizationHeaders = [System.Collections.Generic.Dictionary[[String],[String]]]::New()
        $authorizationHeaders.Add("Authorization", "Bearer $accessToken")
        $authorizationHeaders.Add("Content-Type", "application/json")
        $authorizationHeaders.Add("Mwp-Api-Version", "1.0")

        $body = @{
            licenseProfileId = $pRef.Reference
        }

        $splatParams = @{
            Uri     = "$($c.BaseUrl)/Users/$($aRef)/LicenseProfiles"
            Headers = $authorizationHeaders
            Method  = 'POST'
            body    = ($body | ConvertTo-Json)
        }

        $results = (Invoke-RestMethod @splatParams) #If 200 it returns a Empty String

        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission";
                Message = "Account $($aRef) added to Permission $($pRef.Name) [$($pRef.Reference)]";
                IsError = $(-Not $success);
            });
    } 
    catch 
    {
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission";
                Message = "Failed to add account $($aRef) to permission $($pRef.Reference)";
                IsError = $(-Not $success);
            });
    }
}
else
{
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission";
                Message = "Dry-Run";
                IsError = $(-Not $success);
            });    
}

# Send results
$result = [PSCustomObject]@{
    Success   = $success;
    AuditLogs = $auditLogs;
    Account   = [PSCustomObject]@{ };
};

Write-Output $result | ConvertTo-Json -Depth 10;