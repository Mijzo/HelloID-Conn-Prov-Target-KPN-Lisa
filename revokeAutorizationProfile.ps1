$p = $person | ConvertFrom-Json;
$aRef = $accountReference | ConvertFrom-Json;
$pRef = $permissionReference | ConvertFrom-Json;
$c = $configuration | ConvertFrom-Json;
$success = $False;
$auditLogs = [Collections.Generic.List[PSCustomObject]]::New()

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

if (-Not($dryRun -eq $true)) {
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

        $body = $aRef

        $splatParams = @{
            Uri     = "$($c.BaseUrl)//AuthorizationProfiles/$($pRef.Reference)/members"
            Headers = $authorizationHeaders
            Method  = 'DELETE'
            body    = ($body | ConvertTo-Json)
        }

        $results = (Invoke-RestMethod @splatParams) #If 200 it returns a Empty String

        $success = $True;
        $auditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission";
                Message = "Account $($aRef) removed from Permission $($pRef.Reference)";
                IsError = $False;
            });
    } catch {
        Write-Verbose $($_) -Verbose
        $Err =  $([regex]::escape($Error[0].ErrorDetails)).replace("\","")

        $auditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission";
                Message = "Failed to remove account $($aRef) from permission $($pRef.Reference) Error: $($Err)";
                IsError = $true;
            });
    }
}
else
{
        $auditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission";
                Message = "Params $($splatParams)";
                IsError = $False;
            });    
    
}
# Send results
$result = [PSCustomObject]@{
    Success   = $success;
    AuditLogs = $auditLogs;
    Account   = [PSCustomObject]@{ };
};

Write-Output $result | ConvertTo-Json -Depth 10;