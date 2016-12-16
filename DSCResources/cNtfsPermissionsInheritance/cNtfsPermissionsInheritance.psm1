#region HEADER_JC_DOC
# ------------------------------------------------------------
# Filename    : cNTFSPermissionsInheritance.psm1
# Keywords    : DSC, ACLs, PERMISSIONS, INHERITANCE
# Description : DSC - Apply permissions to folders, files, and inheritance
# Version     : 2.0.0 Based on 'https://github.com/SNikalaichyk/cNtfsAccessControl'
#               http://github.com/juancrl
# Date        : 16-Dec-2016
# ------------------------------------------------------------
# by Juan Carlos Ruiz, juancarlosruizlopez@outlook.com
# ------------------------------------------------------------
#
#endregion


#requires -Version 4.0
Set-StrictMode -Version Latest

#region GET
# -------------------------------------------------------------------------------------------- GET ----------------------------------------

# -----------------------------------------------------------------------------------
Function Get-TargetResource
# -----------------------------------------------------------------------------------
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]        [String]        $Path,
        [Parameter(Mandatory = $false)]        [Boolean]        $Enabled = $true,
        [Parameter(Mandatory = $false)]        [Boolean]        $PreserveInherited = $true
    )

<#
    $PSBoundParameters.GetEnumerator() |
    ForEach-Object -Begin {
        $Width = $PSBoundParameters.Keys.Length | Sort-Object | Select-Object -Last 1
    } -Process {
        "{0,-$($Width)} : '{1}'" -f $_.Key, ($_.Value -join ', ') |
        Write-Verbose
    }
#>

    $RealPath = TranslateEnvs $Path

	$Acl = $null
	try { $Acl = Get-Acl -Path $RealPath } catch {}

    if (!$Acl)
    {
        return  @{}
    }
                                          

    [bool]$EnabledResult = -not ($Acl.AreAccessRulesProtected)

    if ($EnabledResult)
    {
        Write-Verbose -Message "Permissions inheritance is enabled on path '$RealPath'."
    }
    else
    {
        Write-Verbose -Message "Permissions inheritance is disabled on path '$RealPath'."
    }

    $ReturnValue = @{
        Path = $RealPath
        Enabled = $EnabledResult
        PreserveInherited = $PreserveInherited
    }

    return $ReturnValue
}

#endregion




#region TEST
# -------------------------------------------------------------------------------------------- TEST ---------------------------------------

# -----------------------------------------------------------------------------------
Function Test-TargetResource
# -----------------------------------------------------------------------------------
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]   [String]  $Path,
        [Parameter(Mandatory = $false)]  [Boolean] $Enabled = $true,
        [Parameter(Mandatory = $false)]  [Boolean] $PreserveInherited = $true
    )

    $TargetResource = Get-TargetResource @PSBoundParameters

    [bool]$InDesiredState = $TargetResource.Enabled

    if ($InDesiredState)
    {
        Write-Verbose -Message 'The target resource is already in the desired state. No action is required.'
    }
    else
    {
        Write-Verbose -Message 'The target resource is not in the desired state.'
    }

    return $InDesiredState
}
#endregion


#region SET
# --------------------------------------------------------------------------------------------- SET ---------------------------------------
# -----------------------------------------------------------------------------------
Function Set-TargetResource
# -----------------------------------------------------------------------------------
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]   [String]   $Path,
        [Parameter(Mandatory = $false)]  [Boolean]  $Enabled = $true,
        [Parameter(Mandatory = $false)]  [Boolean]  $PreserveInherited = $true
    )

	$RealPath = TranslateEnvs $Path                                                        # JC. Allow ENVVARS inside of path 
	$Exists = Test-Path $RealPath


	$Acl = $null
	try { $Acl = Get-Acl -Path $RealPath } catch {}                                          

    if (! $Acl) {
                  Write-Error "$RealPath not found" 
                  return 
                }


    if ($Enabled -eq $false)
    {
        Write-Verbose -Message "Disabling permissions inheritance on path '$RealPath'."

        if ($PreserveInherited -eq $true)
        {
            Write-Verbose -Message 'Inherited permissions will be converted into explicit permissions.'
        }
        else
        {
            Write-Verbose -Message 'Inherited permissions will be removed.'
        }

        $Acl.SetAccessRuleProtection($true, $PreserveInherited)
    }
    else
    {
        Write-Verbose -Message "Enabling permissions inheritance on path '$RealPath'."

        $Acl.SetAccessRuleProtection($false, $false)
    }

    Set-FileSystemAccessControl -Path $RealPath -Acl $Acl
}

#endregion


#region Helper Functions
# --------------------------------------------------------------------------------------------- HELPERS -----------------------------------

# -----------------------------------------------------------------------------------
Function Set-FileSystemAccessControl
# -----------------------------------------------------------------------------------
{
    <#
    .SYNOPSIS
        Applies access control entries (ACEs) to the specified file or directory.

    .DESCRIPTION
        The Set-FileSystemAccessControl function applies access control entries (ACEs) to the specified file or directory.

    .PARAMETER Path
        Specifies the path to the file or directory.

    .PARAMETER Acl
        Specifies the access control list (ACL) object with the desired access control entries (ACEs)
        to apply to the file or directory described by the Path parameter.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.AccessControl.FileSystemSecurity]
        $Acl
    )

    $PathInfo = Resolve-Path -Path $Path -ErrorAction Stop

    if ($PSCmdlet.ShouldProcess($Path))
    {
        if ($Acl -is [System.Security.AccessControl.DirectorySecurity])
        {
            [System.IO.Directory]::SetAccessControl($PathInfo.ProviderPath, $Acl)
        }
        else
        {
            [System.IO.File]::SetAccessControl($PathInfo.ProviderPath, $Acl)
        }
    }
}


# -----------------------------------------------------------------------------------
Function TranslateEnvs ([string]$PossiblePath)                                      # JC. 16-Dec-2016 - Allowing ENVVARS inside of path 
# -----------------------------------------------------------------------------------
{
	# The Path received from caller can be '%windir%\logs', for example... 
	
	## TBD Catch possible errors

	return [system.environment]::ExpandEnvironmentVariables($PossiblePath)
 
}


# -----------------------------------------------------------------------------------
#endregion



# ---------------------------------------------------------------------------------------------------------------------------------------
Export-ModuleMember -Function *-TargetResource

