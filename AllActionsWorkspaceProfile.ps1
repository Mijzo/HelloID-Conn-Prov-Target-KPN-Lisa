$p = $person | ConvertFrom-Json;
$m = $manager | ConvertFrom-Json;
$aRef = $accountReference | ConvertFrom-Json;
$mRef = $managerAccountReference | ConvertFrom-Json;
$c = $configuration | ConvertFrom-Json;

# Operation is a script parameter which contains the action HelloID wants to perform for this permission
# It has one of the following values: "grant", "revoke", "update"
$o = $operation | ConvertFrom-Json;

# The permissionReference contains the Identification object provided in the retrieve permissions call
$pRef = $permissionReference | ConvertFrom-Json;

$success = $False;
$auditLogs = [Collections.Generic.List[PSCustomObject]]::New()

# The entitlementContext contains the sub permissions
$eRef = $entitlementContext | ConvertFrom-Json;

# Determine all the sub-permissions that needs to be Granted/Updated/Revoked
$subPermissions = [Collections.Generic.List[PSCustomObject]]::New()

#start region functions
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
        } elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $stream = $ErrorObject.Exception.Response.GetResponseStream()
            $stream.Position = 0
            $streamReader = New-Object System.IO.StreamReader $Stream
            $errorResponse = $StreamReader.ReadToEnd()
            $HttpErrorObj['ErrorMessage'] = $errorResponse
        }
        Write-Output "'$($HttpErrorObj.ErrorMessage)', TargetObject: '$($HttpErrorObj.TargetObject), InvocationCommand: '$($HttpErrorObj.InvocationInfo)"
    }
}
#end region functions

$currentPermissions = @{};
foreach ($permission in $eRef.CurrentPermissions)
{
    $currentPermissions[$permission.Reference.Id] = $permission.DisplayName;
}

$desiredPermissions = @{ };
if (-Not($o -eq "revoke"))
{
    foreach ($contract in $p.Contracts)
    {
        if ($contract.Context.InConditions)
        {
            $desiredPermissions[$contract.Department.ExternalId] = $contract.Department.DisplayName;
        }
    }
}
else
{
    if (-Not($dryRun -eq $true))
    {
        $success = $true
        $auditLogs.Add([PSCustomObject]@{
                Action  = "RevokePermission";
                Message = "There is no proces to revoke a workspaceprofile!";
                IsError = $False;
            });    
    }
}

# Compare desired with current permissions and grant permissions
foreach ($permission in $desiredPermissions.GetEnumerator())
{
    $subPermissions.Add([PSCustomObject]@{
        DisplayName = $permission.Value;
        Reference = [PSCustomObject]@{ Id = $permission.Name };
    });

    if (-Not $currentPermissions.ContainsKey($permission.Name))
    {
        if (-Not($dryRun -eq $True))
        {
            try 
            {
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

                $body = $pRef.Reference

                $splatParams = @{
                    Uri     = "$($c.BaseUrl)/Users/$($aRef)/workspaceprofiles" 
                    Headers = $authorizationHeaders
                    Method  = 'PUT'
                    body    = ($body | ConvertTo-Json)
                }

                try {
                    $results = (Invoke-RestMethod @splatParams) #If 200 it returns a Empty String which represents 'success'
                
                    $success = $True;
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "GrantPermission";
                            Message = "Account $($aRef) moved to workspaceprofile $($pRef.Reference)";
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
                                Message = "Workspaceprofile $($pRef.Reference) already added to account $($aRef)";
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
            } 
            catch 
            {
                Write-Verbose $($_) -Verbose
                $auditLogs.Add([PSCustomObject]@{
                        Action  = "GrantPermission";
                        Message = "Failed to assign account $($aRef) to workspaceprofile $($pRef.Reference)";
                        IsError = $true;
                    });
            }
        }
        else 
        {
            $auditLogs.Add([PSCustomObject]@{
                Action = "GrantPermission";
                Message = "Dry-run for workspaceprofile $($permission.Value)";
                IsError = $False;
            });
        }
    }
}

# Compare current with desired permissions and revoke permissions
$newCurrentPermissions = @{ };
foreach ($permission in $currentPermissions.GetEnumerator())
{
    if (-Not $desiredPermissions.ContainsKey($permission.Name))
    {
        if (-Not($dryRun -eq $True))
        {
            # Write permission revoke logic here
        }

        $auditLogs.Add([PSCustomObject]@{
            Action = "RevokePermission";
            Message = "Revoked workspaceprofile $($permission.Value)";
            IsError = $False;
        });
    }
    else
    {
        $newCurrentPermissions[$permission.Name] = $permission.Value;
    }
}

# Update current permissions
if ($o -eq "update")
{
    foreach ($permission in $newCurrentPermissions.GetEnumerator())
    {
        if (-Not($dryRun -eq $True))
        {
            $success = $True;
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "RevokePermission";
                    Message = "There is no proces to update a workspaceprofile!";
                    IsError = $False;
                }); 
        }

        $auditLogs.Add([PSCustomObject]@{
            Action = "UpdatePermission";
            Message = "Updated workspaceprofile $($permission.Value)";
            IsError = $False;
        });
    }
}

# Send results
$result = [PSCustomObject]@{
    Success = $success;
    SubPermissions = $subPermissions;
    AuditLogs = $auditLogs;
};

Write-Output $result | ConvertTo-Json -Depth 10;