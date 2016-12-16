#region HEADER_JC_DOC
# ------------------------------------------------------------
# Filename    : cNTFSPermissionEntry.psm1
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



#requires -Version 4.0 -Modules CimCmdlets
Set-StrictMode -Version Latest

#region GET
# -------------------------------------------------------------------------------------------- GET ----------------------------------------

# -----------------------------------------------------------------------------------
Function Get-TargetResource
# -----------------------------------------------------------------------------------
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]   [System.String]        $Path,
        [parameter(Mandatory = $true)]   [System.String]        $Principal,
        [parameter(Mandatory = $false)]  [System.Boolean]        $AllowInexistent,
        [parameter(Mandatory = $false)]  [System.String]        $LoggingFile
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."
    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."


    <#
    $returnValue = @{
    Ensure = [System.String]
    Path = [System.String]
    ItemType = [System.String]
    Principal = [System.String]
    AccessControlInformation = [Microsoft.Management.Infrastructure.CimInstance[]]
    AllowInexistent = [System.Boolean]
    LoggingFile = [System.String]
    }

    $returnValue
    #>


    $ReturnValue = @{
						Ensure = "Absent"
						Path = $Path
                                                ItemType = "Unknown"
						Principal = $Principal
                    }


        $ItemType = "Unknown"

	$RealPath = TranslateEnvs $Path                                                        # JC. Allow ENVVARS inside of path 
	$Exists = Test-Path $RealPath
	
	if (!$Exists)
	{
           ##  If the PATH does not exist, you cannot GET-  no matter if allow inexistent
                            $ReturnValue.Itemtype = "$Path Not Found"
			    
                            if ($host.version.major -le 4) { return @{} } else { return $ReturnValue }
 
	}

        if ($LoggingFile) { "GET :: Folder $RealPath exists. Let's check ACLs" >> $LoggingFile }

	$Acl = $null
	try { $Acl = Get-Acl -Path $RealPath } catch {}                                          

        if ($Acl -is [System.Security.AccessControl.DirectorySecurity] )  { $ItemType = 'Directory' }
	if ($Acl -is [System.Security.AccessControl.FileSecurity]      )  { $ItemType = 'File' }

        if ($LoggingFile) { "GET :: Folder $RealPath exists. ACLs checked, it is a $ItemType" >> $LoggingFile }



	# Future : Registry, Services ...
	# http://blogs.msmvps.com/erikr/2007/09/26/set-permissions-on-a-specific-service-windows/
	# sc.exe : sc sdshow serviceName

	

        $Identity = Resolve-IdentityReference -Identity $Principal  -AllowInexistent $AllowInexistent -LoggingFile $LoggingFile 
	if (-not $Identity)
	{

		## User or group was not found

                if ($LoggingFile) { "GET :: The user $Principal does not exist. Returning" >> $LoggingFile }

                $ReturnValue.Itemtype = "$Principal not found"

                # if ($host.version.major -le 4) { return @{} } else { return $ReturnValue }
                return $ReturnValue 

	}


	## // Both found.

    [System.Security.AccessControl.FileSystemAccessRule[]]$AccessRules = @(
             $Acl.Access |  Where-Object { (-not $_.IsInherited) -and  ($_.IdentityReference -eq $Identity.Name)
        }
    )

    Write-Verbose -Message "Current permission entry count : $($AccessRules.Count)"

    $CimAccessRules = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    if ($AccessRules.Count -eq 0)
    {
        $EnsureResult = 'Absent'
    }
    else
    {
        $EnsureResult = 'Present'

        $AccessRules |
        ConvertFrom-FileSystemAccessRule -ItemType $ItemType |
        ForEach-Object -Process {

            $CimAccessRule = New-CimInstance -ClientOnly `
                -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                -ClassName cNtfsAccessControlInformation `
                -Property @{
                    AccessControlType = $_.AccessControlType
                    FileSystemRights = $_.FileSystemRights
                    Inheritance = $_.Inheritance
                    NoPropagateInherit = $_.NoPropagateInherit
                }

            $CimAccessRules.Add($CimAccessRule)

        }
    }

    $ReturnValue = @{
        Ensure = $EnsureResult
        Path = $Path
        ItemType = $ItemType
        Principal = $Principal
        
        # This property fails in WMF4 ! TBD

        AccessControlInformation = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessRules)
    }

    if ($host.version.major -le 4) { $ReturnValue.AccessControlInformation = $null }

                # if ($host.version.major -le 4) { return @{} } else { return $ReturnValue }
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
    [OutputType([System.Boolean])]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [ValidateSet("Directory","File")]
        [System.String]
        $ItemType,

        [parameter(Mandatory = $true)]
        [System.String]
        $Principal,

        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlInformation,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $AllowInexistent,

        [parameter(Mandatory = $false)]
        [System.String]
        $LoggingFile
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."

 
    if ($PSBoundParameters.ContainsKey('ItemType'))
    {
        Write-Verbose -Message 'The ItemType property is deprecated and will be ignored.'
    }

    $InDesiredState = $true


	if ($LoggingFile) { "Test-TargetResource. Received $Path" > $LoggingFile }

	$RealPath = TranslateEnvs $Path                                                        # JC. Allow ENVVARS inside of path 

        if ($LoggingFile) { "Test-TargetResource. Translated to $RealPath"  >> $LoggingFile}

	$Exists = Test-Path $RealPath
	
	if (!$Exists)
	{
		        ##  If the PATH does not exist, no matter if allow inexistent
			   return $False
 
	}

	if ($LoggingFile) { "Test-TargetResource. OK, $RealPath exists" >> $LoggingFile }


	$Acl = $null
	try { $Acl = Get-Acl -Path $RealPath } catch {}                                          

        if ($Acl -is [System.Security.AccessControl.DirectorySecurity] )  { $ItemType = 'Directory' }
	if ($Acl -is [System.Security.AccessControl.FileSecurity]      )  { $ItemType = 'File' }



    $Identity = Resolve-IdentityReference -Identity $Principal  -AllowInexistent $AllowInexistent -LoggingFile $LoggingFile

    if (-not $Identity)
	{
	    ## User or group was not found
            ## Decidir
	    return $false
	}

    [System.Security.AccessControl.FileSystemAccessRule[]]$AccessRules = @(
        $Acl.Access | Where-Object { (-not $_.IsInherited) -and ($_.IdentityReference -eq $Identity.Name) }
    )

    Write-Verbose -Message "Current permission entry count : $($AccessRules.Count)"

    [PSCustomObject[]]$ReferenceRuleInfo = @()

    if ($PSBoundParameters.ContainsKey('AccessControlInformation'))
    {
        foreach ($Instance in $AccessControlInformation)
        {
            $AccessControlType = $Instance.CimInstanceProperties.Where({$_.Name -eq 'AccessControlType'}).ForEach({$_.Value})
            $FileSystemRights = $Instance.CimInstanceProperties.Where({$_.Name -eq 'FileSystemRights'}).ForEach({$_.Value})
            $Inheritance = $Instance.CimInstanceProperties.Where({$_.Name -eq 'Inheritance'}).ForEach({$_.Value})
            $NoPropagateInherit = $Instance.CimInstanceProperties.Where({$_.Name -eq 'NoPropagateInherit'}).ForEach({$_.Value})

            if (-not $AccessControlType)    {                $AccessControlType = 'Allow'            }
            if (-not $FileSystemRights)     {                $FileSystemRights = 'ReadAndExecute'            }
            if (-not $NoPropagateInherit)   {                $NoPropagateInherit = $false            }

            $ReferenceRuleInfo += [PSCustomObject]@{
                AccessControlType = $AccessControlType
                FileSystemRights = $FileSystemRights
                Inheritance = $Inheritance
                NoPropagateInherit = $NoPropagateInherit
            }
        }
    }
    else
    {
        Write-Verbose -Message 'The AccessControlInformation property is not specified.'

        if ($Ensure -eq 'Present')
        {
            Write-Verbose -Message 'The default permission entry will be used as the reference permission entry.'

            $ReferenceRuleInfo += [PSCustomObject]@{
                AccessControlType = 'Allow'
                FileSystemRights = 'ReadAndExecute'
                Inheritance = $null
                NoPropagateInherit = $false
            }
        }
    }

    if ($Ensure -eq 'Absent' -and $AccessRules.Count -ne 0)
    {
        if ($ReferenceRuleInfo.Count -ne 0)
        {
            $ReferenceRuleInfo |
            ForEach-Object -Begin {$Counter = 0} -Process {

                $Entry = $_

                $ReferenceRule = New-FileSystemAccessRule `
                    -ItemType $ItemType `
                    -Principal $Identity.Name `
                    -AccessControlType $Entry.AccessControlType `
                    -FileSystemRights $Entry.FileSystemRights `
                    -Inheritance $Entry.Inheritance `
                    -NoPropagateInherit $Entry.NoPropagateInherit `
                    -ErrorAction Stop

                $MatchingRule = $AccessRules |
                    Where-Object -FilterScript {
                        ($_.AccessControlType -eq $ReferenceRule.AccessControlType) -and
                        ($_.FileSystemRights -eq $ReferenceRule.FileSystemRights) -and
                        ($_.InheritanceFlags -eq $ReferenceRule.InheritanceFlags) -and
                        ($_.PropagationFlags -eq $ReferenceRule.PropagationFlags)
                    }

                if ($MatchingRule)
                {
                    ("Permission entry was found ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
                    ("> IdentityReference : '{0}'" -f $MatchingRule.IdentityReference),
                    ("> AccessControlType : '{0}'" -f $MatchingRule.AccessControlType),
                    ("> FileSystemRights  : '{0}'" -f $MatchingRule.FileSystemRights),
                    ("> InheritanceFlags  : '{0}'" -f $MatchingRule.InheritanceFlags),
                    ("> PropagationFlags  : '{0}'" -f $MatchingRule.PropagationFlags) |
                    Write-Verbose

                    $InDesiredState = $false
                }
                else
                {
                    ("Permission entry was not found ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
                    ("> IdentityReference : '{0}'" -f $ReferenceRule.IdentityReference),
                    ("> AccessControlType : '{0}'" -f $ReferenceRule.AccessControlType),
                    ("> FileSystemRights  : '{0}'" -f $ReferenceRule.FileSystemRights),
                    ("> InheritanceFlags  : '{0}'" -f $ReferenceRule.InheritanceFlags),
                    ("> PropagationFlags  : '{0}'" -f $ReferenceRule.PropagationFlags) |
                    Write-Verbose
                }

            }
        }
        else
        {
            # All explicit permissions associated with the specified principal should be removed.
            $InDesiredState = $false
        }
    }

    if ($Ensure -eq 'Present')
    {
        Write-Verbose -Message "Desired permission entry count : $($ReferenceRuleInfo.Count)"

        if ($AccessRules.Count -ne $ReferenceRuleInfo.Count)
        {
            Write-Verbose -Message 'The number of current permission entries is different from the number of desired permission entries.'
            $InDesiredState = $false
        }

        $ReferenceRuleInfo |
        ForEach-Object -Begin {$Counter = 0} -Process {

            $Entry = $_

            $ReferenceRule = New-FileSystemAccessRule `
                -ItemType $ItemType `
                -Principal $Identity.Name `
                -AccessControlType $Entry.AccessControlType `
                -FileSystemRights $Entry.FileSystemRights `
                -Inheritance $Entry.Inheritance `
                -NoPropagateInherit $Entry.NoPropagateInherit `
                -ErrorAction Stop

            $MatchingRule = $AccessRules |
                Where-Object -FilterScript {
                    ($_.AccessControlType -eq $ReferenceRule.AccessControlType) -and
                    ($_.FileSystemRights -eq $ReferenceRule.FileSystemRights) -and
                    ($_.InheritanceFlags -eq $ReferenceRule.InheritanceFlags) -and
                    ($_.PropagationFlags -eq $ReferenceRule.PropagationFlags)
                }

            if ($MatchingRule)
            {
                ("Permission entry was found ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
                ("> IdentityReference : '{0}'" -f $MatchingRule.IdentityReference),
                ("> AccessControlType : '{0}'" -f $MatchingRule.AccessControlType),
                ("> FileSystemRights  : '{0}'" -f $MatchingRule.FileSystemRights),
                ("> InheritanceFlags  : '{0}'" -f $MatchingRule.InheritanceFlags),
                ("> PropagationFlags  : '{0}'" -f $MatchingRule.PropagationFlags) |
                Write-Verbose
            }
            else
            {
                ("Permission entry was not found ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
                ("> IdentityReference : '{0}'" -f $ReferenceRule.IdentityReference),
                ("> AccessControlType : '{0}'" -f $ReferenceRule.AccessControlType),
                ("> FileSystemRights  : '{0}'" -f $ReferenceRule.FileSystemRights),
                ("> InheritanceFlags  : '{0}'" -f $ReferenceRule.InheritanceFlags),
                ("> PropagationFlags  : '{0}'" -f $ReferenceRule.PropagationFlags) |
                Write-Verbose

                $InDesiredState = $false
            }

        }
    }

    if ($InDesiredState -eq $true)
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
    [CmdletBinding()]
    param
    (
        [ValidateSet("Present","Absent")]
        [System.String]
        $Ensure,

        [parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [ValidateSet("Directory","File")]
        [System.String]
        $ItemType,

        [parameter(Mandatory = $true)]
        [System.String]
        $Principal,

        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlInformation,

        [parameter(Mandatory = $false)]
        [System.Boolean]
        $AllowInexistent,

        [parameter(Mandatory = $false)]
        [System.String]
        $LoggingFile
    )

    #Write-Verbose "Use this cmdlet to deliver information about command processing."

    #Write-Debug "Use this cmdlet to write debug information while troubleshooting."

    #Include this line if the resource requires a system reboot.
    #$global:DSCMachineStatus = 1


	$RealPath = TranslateEnvs $Path                                                        # JC. Allow ENVVARS inside of path 

	$Exists = Test-Path -Path $RealPath
	
	if (!$Exists)
	{
	    write-Error "Folder $RealPath does not exist"
	    return 
	}

	$Acl = $null
	try { $Acl = Get-Acl -Path $RealPath } catch {}                                          

        if ($Acl -is [System.Security.AccessControl.DirectorySecurity] )  { $ItemType = 'Directory' }
	if ($Acl -is [System.Security.AccessControl.FileSecurity]      )  { $ItemType = 'File' }


    $Identity = Resolve-IdentityReference -Identity $Principal  -AllowInexistent $AllowInexistent -LoggingFile $LoggingFile 
    if (-not $Identity)
	{
		## User or group was not found
	        if (! $AllowInexistent) 
		{
		   Write-Error "User $Principal does not exist"
	        }
		return @{}                  # Should return nothing
		 
	}



	# Found


    [System.Security.AccessControl.FileSystemAccessRule[]]$AccessRules = @(
        $Acl.Access | Where-Object { (-not $_.IsInherited) -and ($_.IdentityReference -eq $Identity.Name)
        }
    )

    Write-Verbose -Message "Current permission entry count : $($AccessRules.Count)"

    [PSCustomObject[]]$ReferenceRuleInfo = @()

    if ($PSBoundParameters.ContainsKey('AccessControlInformation'))
    {
        foreach ($Instance in $AccessControlInformation)
        {
            $AccessControlType = $Instance.CimInstanceProperties.Where({$_.Name -eq 'AccessControlType'}).ForEach({$_.Value})
            $FileSystemRights = $Instance.CimInstanceProperties.Where({$_.Name -eq 'FileSystemRights'}).ForEach({$_.Value})
            $Inheritance = $Instance.CimInstanceProperties.Where({$_.Name -eq 'Inheritance'}).ForEach({$_.Value})
            $NoPropagateInherit = $Instance.CimInstanceProperties.Where({$_.Name -eq 'NoPropagateInherit'}).ForEach({$_.Value})

            if (-not $AccessControlType)     {   $AccessControlType = 'Allow'         }
            if (-not $FileSystemRights)      {   $FileSystemRights = 'ReadAndExecute' }
            if (-not $NoPropagateInherit)    {   $NoPropagateInherit = $false         }

            $ReferenceRuleInfo += [PSCustomObject]@{
                AccessControlType = $AccessControlType
                FileSystemRights = $FileSystemRights
                Inheritance = $Inheritance
                NoPropagateInherit = $NoPropagateInherit
            }
        }
    }
    else
    {
        Write-Verbose -Message 'The AccessControlInformation property is not specified.'

        if ($Ensure -eq 'Present')
        {
            Write-Verbose -Message 'The default permission entry will be added.'

            $ReferenceRuleInfo += [PSCustomObject]@{
                AccessControlType = 'Allow'
                FileSystemRights = 'ReadAndExecute'
                Inheritance = $null
                NoPropagateInherit = $false
            }
        }
    }

    if ($Ensure -eq 'Absent' -and $AccessRules.Count -ne 0)
    {
        if ($ReferenceRuleInfo.Count -ne 0)
        {
            $ReferenceRuleInfo |
            ForEach-Object -Begin {$Counter = 0} -Process {

                $Entry = $_

                $ReferenceRule = New-FileSystemAccessRule `
                    -ItemType $ItemType `
                    -Principal $Identity.Name `
                    -AccessControlType $Entry.AccessControlType `
                    -FileSystemRights $Entry.FileSystemRights `
                    -Inheritance $Entry.Inheritance `
                    -NoPropagateInherit $Entry.NoPropagateInherit `
                    -ErrorAction Stop

                $MatchingRule = $AccessRules |
                    Where-Object -FilterScript {
                        ($_.AccessControlType -eq $ReferenceRule.AccessControlType) -and
                        ($_.FileSystemRights -eq $ReferenceRule.FileSystemRights) -and
                        ($_.InheritanceFlags -eq $ReferenceRule.InheritanceFlags) -and
                        ($_.PropagationFlags -eq $ReferenceRule.PropagationFlags)
                    }

                if ($MatchingRule)
                {
                    ("Removing permission entry ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
                    ("> IdentityReference : '{0}'" -f $MatchingRule.IdentityReference),
                    ("> AccessControlType : '{0}'" -f $MatchingRule.AccessControlType),
                    ("> FileSystemRights  : '{0}'" -f $MatchingRule.FileSystemRights),
                    ("> InheritanceFlags  : '{0}'" -f $MatchingRule.InheritanceFlags),
                    ("> PropagationFlags  : '{0}'" -f $MatchingRule.PropagationFlags) |
                    Write-Verbose

                    $Modified = $null
                    $Acl.ModifyAccessRule('RemoveSpecific', $MatchingRule, [Ref]$Modified)
                }
            }
        }
        else
        {
            "Removing all explicit permissions for principal '{0}'." -f $($AccessRules[0].IdentityReference) |
            Write-Verbose

            $Modified = $null
            $Acl.ModifyAccessRule('RemoveAll', $AccessRules[0], [Ref]$Modified)
        }
    }

    if ($Ensure -eq 'Present')
    {
        if ($AccessRules.Count -ne 0)
        {
            "Removing all explicit permissions for principal '{0}'." -f $($AccessRules[0].IdentityReference) |  Write-Verbose

            $Modified = $null
            $Acl.ModifyAccessRule('RemoveAll', $AccessRules[0], [Ref]$Modified)
        }

        $ReferenceRuleInfo |
        ForEach-Object -Begin {$Counter = 0} -Process {

            $Entry = $_

            $ReferenceRule = New-FileSystemAccessRule `
                -ItemType $ItemType `
                -Principal $Identity.Name `
                -AccessControlType $Entry.AccessControlType `
                -FileSystemRights $Entry.FileSystemRights `
                -Inheritance $Entry.Inheritance `
                -NoPropagateInherit $Entry.NoPropagateInherit `
                -ErrorAction Stop

            ("Adding permission entry ({0} of {1}) :" -f (++$Counter), $ReferenceRuleInfo.Count),
            ("> IdentityReference : '{0}'" -f $ReferenceRule.IdentityReference),
            ("> AccessControlType : '{0}'" -f $ReferenceRule.AccessControlType),
            ("> FileSystemRights  : '{0}'" -f $ReferenceRule.FileSystemRights),
            ("> InheritanceFlags  : '{0}'" -f $ReferenceRule.InheritanceFlags),
            ("> PropagationFlags  : '{0}'" -f $ReferenceRule.PropagationFlags) |
            Write-Verbose

            $Acl.AddAccessRule($ReferenceRule)

        }
    }

    Set-FileSystemAccessControl -Path $RealPath -Acl $Acl

}
#endregion


#region Helper Functions
# --------------------------------------------------------------------------------------------- HELPERS -----------------------------------

# -----------------------------------------------------------------------------------
Function ConvertFrom-FileSystemAccessRule
# -----------------------------------------------------------------------------------
{
    <#
    .SYNOPSIS
        Converts a FileSystemAccessRule object to a custom object.

    .DESCRIPTION
        The ConvertFrom-FileSystemAccessRule function converts a FileSystemAccessRule object to a custom object.

    .PARAMETER ItemType
        Specifies whether the item is a directory or a file.

    .PARAMETER InputObject
        Specifies the FileSystemAccessRule object to convert.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)] [ValidateSet('Directory', 'File')]  [String]        $ItemType,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]          [System.Security.AccessControl.FileSystemAccessRule]        $InputObject
    )
    process
    {
        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = $InputObject.InheritanceFlags
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags = $InputObject.PropagationFlags

        $NoPropagateInherit = $PropagationFlags.HasFlag([System.Security.AccessControl.PropagationFlags]::NoPropagateInherit)

        if ($NoPropagateInherit)
        {
            [System.Security.AccessControl.PropagationFlags]$PropagationFlags =
                $PropagationFlags -bxor [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
        }

        if ($InheritanceFlags -eq 'None' -and $PropagationFlags -eq 'None')
        {
            if ($ItemType -eq 'Directory')      {   $Inheritance = 'ThisFolderOnly'        }
            else                                {   $Inheritance = 'None'                  }
        }
        elseif ($InheritanceFlags -eq 'ContainerInherit, ObjectInherit' -and $PropagationFlags -eq 'None')
        {
            $Inheritance = 'ThisFolderSubfoldersAndFiles'
        }
        elseif ($InheritanceFlags -eq 'ContainerInherit' -and $PropagationFlags -eq 'None')
        {
            $Inheritance = 'ThisFolderAndSubfolders'
        }
        elseif ($InheritanceFlags -eq 'ObjectInherit' -and $PropagationFlags -eq 'None')
        {
            $Inheritance = 'ThisFolderAndFiles'
        }
        elseif ($InheritanceFlags -eq 'ContainerInherit, ObjectInherit' -and $PropagationFlags -eq 'InheritOnly')
        {
            $Inheritance = 'SubfoldersAndFilesOnly'
        }
        elseif ($InheritanceFlags -eq 'ContainerInherit' -and $PropagationFlags -eq 'InheritOnly')
        {
            $Inheritance = 'SubfoldersOnly'
        }
        elseif ($InheritanceFlags -eq 'ObjectInherit' -and $PropagationFlags -eq 'InheritOnly')
        {
            $Inheritance = 'FilesOnly'
        }

        $OutputObject = [PSCustomObject]@{
            ItemType = $ItemType
            Principal = [String]$InputObject.IdentityReference
            AccessControlType = [String]$InputObject.AccessControlType
            FileSystemRights = [String]$InputObject.FileSystemRights
            Inheritance = $Inheritance
            NoPropagateInherit = $NoPropagateInherit
        }

        return $OutputObject
    }
}

# -----------------------------------------------------------------------------------
Function New-FileSystemAccessRule
# -----------------------------------------------------------------------------------
{
    <#
    .SYNOPSIS
        Creates a FileSystemAccessRule object.

    .DESCRIPTION
        The New-FileSystemAccessRule function creates a FileSystemAccessRule object
        that represents an abstraction of an access control entry (ACE).

    .PARAMETER ItemType
        Specifies whether the item is a directory or a file.

    .PARAMETER Principal
        Specifies the identity of the principal.

    .PARAMETER AccessControlType
        Specifies whether the ACE to be used to allow or deny access.

    .PARAMETER FileSystemRights
        Specifies the access rights to be granted to the principal.

    .PARAMETER Inheritance
        Specifies the inheritance type of the ACE.

    .PARAMETER NoPropagateInherit
        Specifies that the ACE is not propagated to child objects.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.FileSystemAccessRule])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]  [ValidateSet('Directory', 'File')] [String]  $ItemType,
	    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]  [String]   $Principal,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]  [ValidateSet('Allow', 'Deny')]  [String] $AccessControlType,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]  [System.Security.AccessControl.FileSystemRights]  $FileSystemRights,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)] [ValidateSet(
            $null,
            'None',
            'ThisFolderOnly',
            'ThisFolderSubfoldersAndFiles',
            'ThisFolderAndSubfolders',
            'ThisFolderAndFiles',
            'SubfoldersAndFilesOnly',
            'SubfoldersOnly',
            'FilesOnly'
        )]
        [String]        $Inheritance = 'ThisFolderSubfoldersAndFiles',
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]        [Boolean]        $NoPropagateInherit = $false
    )
    process
    {
        if ($ItemType -eq 'Directory')
        {
            switch ($Inheritance)
            {
                {$_ -in @('None', 'ThisFolderOnly')}
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'None'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
                }

                'ThisFolderSubfoldersAndFiles'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ContainerInherit', 'ObjectInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
                }

                'ThisFolderAndSubfolders'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ContainerInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
                }

                'ThisFolderAndFiles'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ObjectInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
                }

                'SubfoldersAndFilesOnly'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ContainerInherit', 'ObjectInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'InheritOnly'
                }

                'SubfoldersOnly'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ContainerInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'InheritOnly'
                }

                'FilesOnly'
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ObjectInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'InheritOnly'
                }

                default
                {
                    [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'ContainerInherit', 'ObjectInherit'
                    [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
                }
            }

            if ($NoPropagateInherit -eq $true -and $InheritanceFlags -ne 'None')
            {
                [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'NoPropagateInherit'
            }
        }
        else
        {
            [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags = 'None'
            [System.Security.AccessControl.PropagationFlags]$PropagationFlags = 'None'
        }

        $OutputObject = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
            -ArgumentList $Principal, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType

        return $OutputObject
    }
}

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
        [Parameter(Mandatory = $true)] [ValidateScript({Test-Path -Path $_})]  [String]        $Path,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()]              [System.Security.AccessControl.FileSystemSecurity]        $Acl
    )


    $PathInfo = Resolve-Path -Path $Path -ErrorAction Stop       # Stop ?

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
Function Resolve-IdentityReference
# -----------------------------------------------------------------------------------
{
    <#
    .SYNOPSIS
        Resolves the identity of the principal (user or group)

    .DESCRIPTION
        The Resolve-IdentityReference function resolves the identity of the principal
        and returns its down-level logon name and security identifier (SID).

    .PARAMETER Identity
        Specifies the identity of the principal.

	.PARAMETER AllowInexistent
	    If TRUE, we allow inexistent identities (avoid errors)

	.PARAMETER LoggingFile
	    Errors are sent to this file if not $null

    #>
    [CmdletBinding()]
    param
    (
      [Parameter(Mandatory = $true, ValueFromPipeline = $true)]        [ValidateNotNullOrEmpty()]        [String]        $Identity,
	  [Parameter(Mandatory = $false)]                             [bool]    $AllowInexistent=$false,      # JC. If Principal do not exist, IGNORE, NO ERRORS.
	  [Parameter(Mandatory = $false)]                             [string]  $LoggingFile=$null            # JC. If provided, a filename where to log errors (besides DSC log)
		
    )
    process
    { 
            Write-Verbose -Message "Resolving identity reference '$Identity'."

            if ($Identity -match '^S-\d-(\d+-){1,14}\d+$')
            {
				## Domain SID passed
                [System.Security.Principal.SecurityIdentifier]$Identity = $Identity
            }
            else
            {
				## Others
                [System.Security.Principal.NTAccount]$Identity = $Identity
            }


			$ok = $true
			try
			{
              $SID = $Identity.Translate([System.Security.Principal.SecurityIdentifier])
              $NTAccount = $SID.Translate([System.Security.Principal.NTAccount])
			}
			catch
			{
               $TranslateErrorMessage = $_.Exception.Message
               $ok = $false
			}
		

	    if ($ok)
	    {
			
            $OutputObject = [PSCustomObject]@{
                                                 Name = $NTAccount.Value
                                                 SID = $SID.Value
                                             }
			return $OutputObject
        }
        else
        {
            $ErrorMessage = "Could not resolve identity reference '{0}': '{1}'." -f $Identity, $TranslateErrorMessage
        }
	   
	    if ($AllowInexistent) { return }


	    # If errors must be reported
        Write-Error -Exception $_.Exception -Message $ErrorMessage
        return
        }
	 
    
}



# -----------------------------------------------------------------------------------
Function TranslateEnvs ([string]$PossiblePath)                                      # JC. 16-Dec-2016 - Allowing ENVVARS inside of path 
# -----------------------------------------------------------------------------------
{
	# The Path received from caller must be '%windir%\logs', for example...  

	## TBD Catch possible errors

	return [system.environment]::ExpandEnvironmentVariables($PossiblePath)
 
}


# -----------------------------------------------------------------------------------
#endregion



# ---------------------------------------------------------------------------------------------------------------------------------------
Export-ModuleMember -Function *-TargetResource



