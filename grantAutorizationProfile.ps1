$p = $person | ConvertFrom-Json;
$aRef = $accountReference | ConvertFrom-Json;
$pRef = $permissionReference | ConvertFrom-Json;
$c = $configuration | ConvertFrom-Json;
$success = $False;
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

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $HttpErrorObj = @{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            InvocationInfo        = $ErrorObject.InvocationInfo.MyCommand
            TargetObject          = $ErrorObject.TargetObject.RequestUri
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $HttpErrorObj['ErrorMessage'] = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $stream = $ErrorObject.Exception.Response.GetResponseStream()
            $stream.Position = 0
            $streamReader = New-Object System.IO.StreamReader $Stream
            $errorResponse = $StreamReader.ReadToEnd()
            $HttpErrorObj['ErrorMessage'] = $errorResponse
        }
        Write-verbose -verbose "'$($HttpErrorObj.ErrorMessage)', TargetObject: '$($HttpErrorObj.TargetObject), InvocationCommand: '$($HttpErrorObj.InvocationInfo)"
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

        $body = @{
            members = @($aRef)
        }

        $splatParams = @{
            Uri     = "$($c.BaseUrl)//AuthorizationProfiles/$($pRef.Reference)/members"
            Headers = $authorizationHeaders
            Method  = 'PATCH'
            body    = ($body | ConvertTo-Json)
        }

        try {
            $results = (Invoke-RestMethod @splatParams) #If 200 it returns a Empty String which represents 'success'

            $success = $True;
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "GrantPermission";
                    Message = "Permission $($pRef.Reference) added to account $($aRef)";
                    IsError = $False;
            });            
        } catch {
            # Dig into the exception to get the Response details.
            $status = ($_ | convertfrom-json).error
            switch ($status.code)
            {
                "AlreadyMemberOfGroup"
                {
                    $success = $True;
                    $auditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission";
                        Message = "Permission $($pRef.Reference) already added to account $($aRef)";
                        IsError = $False;
                    });
                    break
                }
                default 
                {
                    Write-Verbose -verbose "$results"
                    break
                }
            }
        }
    } catch {
        Write-Verbose $($_) -Verbose
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission";
                Message = "Failed to add account $($aRef) to permission $($pRef.Reference)";
                IsError = $true;
            });
    }
}
else
{
        $auditLogs.Add([PSCustomObject]@{
                Action  = "GrantPermission";
                Message = "Dry-Run";
                IsError = $False;
            });    
    
}

# Send results
$result = [PSCustomObject]@{
    Success   = $success;
    AuditLogs = $auditLogs;
    Account   = $p;
};

Write-Output $result | ConvertTo-Json -Depth 10;