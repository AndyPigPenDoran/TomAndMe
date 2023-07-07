<#   
.SYNOPSIS   
    This script allows a user of SL1 to configure a Windows computer for using Windows Remote Management with the provided 
    Windows local user account or Active Directory domain user account, and it gives that account permission to read and
    query the status of all Windows services, query Performance Monitor counters, and read Windows Event Log records.
  
.DESCRIPTION 
    Provides an automated and silent manner to configure SL1 credential permissions to Windows servers where data is to be collected.
    This script must be run by a user in the local Administrator group or Domain Administrators group to allow the changes to be applied
    to the server.  Logging for all changes made will be written to %TEMP%\silo_winrm_config.log.

.PARAMETER user
    The Active Directory (domain) user account, specified as domain\user or user@domain, or a local computer user account, that 
    should be configured for SL1 to use as the credential to the server. A local or domain security group name can be used here as well. 

.PARAMETER silent
    Runs the configuration script without user interaction.

.PARAMETER unencrypted
    Configures WinRM for unencrypted communication between SL1 and the Windows computer. The default is to use encrypted
    communications. If Group Policy has set the AllowUnencrypted value, we will not change it, and this flag is ignored.

.PARAMETER server
    The Windows computer where configuration will be performed. The localhost is the default.  NOTE: this is NOT  used at this time.
    It will be used in a future version of this script.

.PARAMETER log_path
    A valid Windows folder path and filename where output of the execution will be written.

.PARAMETER max_requests
    Sets the maximum number of WinRM requests the Windows server can process simultaneously.

.PARAMETER http_port
    The HTTP port for unencrypted communication to be configured, if not using encrypted communication.

.PARAMETER https_port
    The HTTPS port for encrypted communication to be configured, if encrypted communication is desired.

.PARAMETER ps_version
    This integer value will note the minimum required version of Windows PowerShell for this script to perform its security 
    configuration settings. The default is 1, which means this script will execute on any Windows server.  A portion of
    SL1 PowerPacks using PowerShell require version 3.0 and later, so if there is a desire to only setup Windows
    Remote Management and/or non-Administrator credential configuration for such versions, use that major version
    value in this parameter.

.PARAMETER services_only
    Limits the configuration to setting of permissions for monitoring Windows services.

.PARAMETER skip_services
    Skips the setting of permissions for monitoring Windows services.
 
.PARAMETER cluster_only
    Limits the configuration to the granting of read permissions on the Windows Failover Cluster that resides
    on the local computer.  Necessary for use of the Microsoft: Windows Server Cluster PowerPack.

.PARAMETER winrm_only
    Limits the configuration to setting of WinRM quick configuration, as in "winrm quickconfig". Note this basic
    configuration of WinRM only runs when this flag is set (eg. and not by default).  Use this if the Windows
    computer has never been setup for Windows Remote Management before.

.PARAMETER wmi_only
    Limits the configuration to setting of permissions to use WMI remotely to the computer.  WMI settings can
    only be performed if a user account is provided on the command-line.

.PARAMETER skip_wmi
    Skips setting of permissions for the user to access the computer with WMI queries.
 
.PARAMETER sql_only
    Limits the configuration to setting of permissions for SL1 to monitor all Microsoft SQL Server instances and
    databases on the server.  This can only be performed if a user account is provided on the command-line.
    Also, this script must be run with this flag for this permission set to be granted (it doesn't run using any other
    set of arguments or default execution).  Necessary for use of the Microsoft: SQL Server Enhanced PowerPack.

.PARAMETER debug_all
    Writes the most verbose (all) logging information to the logfile; rarely necessary for debugging most issues.

.PARAMETER stdout
    Writes configuration output to the console as well as the logfile.

.PARAMETER idle_timeout
    Specify the IdleTimeout (in seconds) for WinRM processes. If specified, the minimum is 300 (5 minutes) and the 
    maximum is 14400 (4 hours)

.PARAMETER set_timeout
    If running in silent mode, this switch must be set in order for the IdleTimeout to be changed. If it is not 
    specified then when running in silent mode the timeout will not be altered. When not runinng in silent mode,
    you will be prompted for whether or not a change should be made.
    
.EXAMPLE
    .\winrm_configuration_wizard.ps1
    Runs the configuration utility with user interaction, allowing for manual entry of all available configuration
    options.  Logging is written to %TEMP%\silo_winrm_config.log.  If your SL1 credential is in the Administrators
    group on this computer already, you can use this option.

.EXAMPLE
    .\winrm_configuration_wizard.ps1 -user MYDOMAIN\MYUSER -silent
    Configures security for domain account MYDOMAIN\MYUSER on the local Windows computer and does so
    without user interaction. Logging is written to %TEMP%\silo_winrm_config.log.  This would be the most 
    common use of the utility for configuring a user account silently on a Windows host for SL1 monitoring.

.EXAMPLE
    .\winrm_configuration_wizard.ps1 -user MYDOMAIN\myuser -silent
    Configures security for domain account MYDOMAIN\myuser on the local Windows computer and does so
    without user interaction. Logging is written to %TEMP%\silo_winrm_config.log.  This would be the most 
    common use of the utility for configuring a user account on a Windows host silently.
 
.EXAMPLE
    .\winrm_configuration_wizard.ps1 -user USER1 -stdout
    Configures security for local account USER1 on the Windows computer and does so without user interaction,
    writing output to the console.
 
.EXAMPLE
    .\winrm_configuration_wizard.ps1 -user MYDOMAIN\myuser -sql_only
    Configures security for monitoring Microsoft SQL Server for domain account MYDOMAIN\myuser on the
    Windows computer and does so without user interaction.  This runs silently, without user interaction. Ensure
    the user running the script with this option has rights to create a new login on each local SQL Server instance
    and grant permissions to master and ms_db databases on each instance.

.NOTES 
    Copyright (c) 2022, ScienceLogic, Inc.  
    Version 3.2: May 2022

.LINK

#>



# #############################################################################
#
# Copyright (c) 2022, ScienceLogic, LLC
#
# This software is the copyrighted work of ScienceLogic, LLC.
#
# Use of the Software  is  governed  by  the  terms  of  the  software  license
# agreement, which accompanies or  is  included  with  the  Software  ("License
# Agreement").  An end user is not permitted to install any  Software  that  is
# accompanied by or includes a License Agreement, unless he or she first  agree
# to the License Agreement terms. The Software is made available solely for use
# by end users  according  to  the  License  Agreement.   Any  reproduction  or
# redistribution of the Software not in accordance with the  License  Agreement
# is expressly prohibited by law, and may result in severe civil  and  criminal
# penalties. Violators will be prosecuted to the maximum extent possible.
#
# WITHOUT LIMITING THE FOREGOING, COPYING OR REPRODUCTION OF  THE  SOFTWARE  TO
# ANY OTHER SERVER OR LOCATION FOR FURTHER REPRODUCTION  OR  REDISTRIBUTION  IS
# EXPRESSLY PROHIBITED.
#
# THE SOFTWARE IS WARRANTED, IF AT ALL, ONLY ACCORDING  TO  THE  TERMS  OF  THE
# LICENSE AGREEMENT. EXCEPT AS WARRANTED IN THE LICENSE AGREEMENT, SCIENCELOGIC
# LLC.  HEREBY DISCLAIMS ALL WARRANTIES  AND  CONDITIONS  WITH  REGARD  TO  THE
# SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES AND CONDITIONS OF MERCHANTABILITY,   
# FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT.
#
# #############################################################################

# #############################################################################
#
#  Name    :  WinRM Configuration Wizard
#  Version :  3.3
# 
#  History:
#       2015     v1.0  Initial version to add WinRM configuration through dialogs
#  11/2018     v2.0  Add silent execution capability
#    2/2019     v2.1  Add more command-line options, use of service control permission settings,
#                             set WMI permissions for user specified, and add account to user groups, mostly
#                             updates for full non-admin account configuration
#    3/2019     v2.2  Add registry permissions, check for valid user account provided, save more 
#                             settings to preservation file, add minimum Powershell version requirement
#    5/2019     v2.3  Add increase of other max conncurrent and per user settings; fix HTTPS listener
#                             creation when digital thumbprint detected; allow user account to be specified
#                             with user@domain format.
#   1/2020      v3.0  Compile warnings and errors to output at end of log file and std output for
#                             improved readability; ensure -skip options are properly honored in every case;
#                             Added cluster_only argument for granting permissions for cluster monitoring; 
#                             added sql_only argument for granting permissions for MS SQL Server
#                             monitoring.
#   7/2021      v3.1  Update hostname matching logic when automatically selecting certificate for the HTTPS
#                             listener. Add configuration step for WinRM IdleTimeout.
#   5/2022      v3.2  Modified FinishCleanup function to restart services that are dependent upon WinMgmt service.
#                     Created function SetItemIfNotGPO to verify if a config quota is set through a GPO before trying to
#                             set a new value, in order to avoid exceptions that should not stop the script
#   5/2023      v3.3  Modified ConfigureWinRM function to delete the existing HTTPS listener if it exists.
#                     It will be created again with correct values.
# 
# #############################################################################
[CmdletBinding()]
Param ( 
    [parameter(Mandatory = $false, Position = 0)]
    [Alias('group')]
    [string] $user,
    [parameter(Mandatory = $false)]
    [Alias('quiet')]
    [switch] $silent = $false,
    [parameter(Mandatory = $false)]
    [Alias('noencrypt')]
    [switch] $unencrypted = $false,
    [parameter(Mandatory = $false)]
    [Alias('hostname')]
    [string] $server = $null,
    [parameter(Mandatory = $false)]
    [Alias('log')]
    [string] $log_path = $null,
    [parameter(Mandatory = $false)]
    [Alias('connections')]
    [int32] $max_requests = 500,
    [parameter(Mandatory = $false)]
    [Alias('http')]
    [int32] $http_port = 5985,
    [parameter(Mandatory = $false)]
    [Alias('https')]
    [int32] $https_port = 5986,
    [parameter(Mandatory = $false)]
    [Alias('psver')]
    [int32] $ps_version = 3,
    [parameter(Mandatory = $false)]
    [switch] $services_only = $false,
    [parameter(Mandatory = $false)]
    [switch] $skip_services = $false,
    [parameter(Mandatory = $false)]
    [switch] $wmi_only = $false,
    [parameter(Mandatory = $false)]
    [switch] $skip_wmi = $false,
    [parameter(Mandatory = $false)]
    [switch] $winrm_only = $false,
    [parameter(Mandatory = $false)]
    [switch] $cluster_only = $false,
    [parameter(Mandatory = $false)]
    [switch] $sql_only = $false,
    [parameter(Mandatory = $false)]
    [switch] $debug_all = $false,
    [parameter(Mandatory = $false)]
    [Alias('log_to_console')]
    [switch] $stdout = $false,
    [parameter(Mandatory = $false)]
    [ValidateRange(300, 14400)]
    [int] $idle_timeout = 7200,
    [parameter(Mandatory = $false)]
    [switch] $set_timeout = $false
)


# Log: Write to console or logfile
Function Log($trace) {
    $current_time = Get-Date
    try {
        if ($stdout) {
            Write-Host "$current_time $trace"
        } 
        # Write to logfile
        Add-Content $script:log_filepath "[$current_time] $trace"
    }
    catch {
        if ($stdout) {
            Write-Host "[$current_time] Log(): Error occurred while using logfile - detail - $_"
        }
    }
}

# LogDebug: Write to console or logfile only if debug flag on
Function LogDebug($trace) {
    if ($debug_all -ne $false) {
        Log $trace
    }
}



# SaveOriginal: Save the original setting of a property before applying a change to it
# for reverting if necessary
Function SaveOriginal($prop_name, $prop_val) {
    $current_time = Get-Date
    try {
        Log "SaveOriginal: Saving original value `"$prop_val`" for property `"$prop_name`""
        # Save to backup file
        Add-Content $script:original_settings_path "[$current_time]  `"$prop_name`" ==> `"$prop_val`" "
    }
    catch {
        Log "[$current_time] SaveOriginal: Error occurred while saving original setting for `"$prop_name`" - detail - $_"
    }
}


# IsRunByAdmin: Ensure the user executing the script has Administrator rights - this is not requiring the account used in the configuration
# to be in the Administrator group
Function IsRunByAdmin() {
    $bAdmin = $false
    Log "IsRunByAdmin: Checking if user running this utility in an Administrator context ..."
    try {
        $bAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    }
    catch {
        Log "IsRunByAdmin: Exception caught while retrieving current user role - detail - $_"
    }

    if ($bAdmin -eq $false) {
        if ($silent) {
            Log "IsRunByAdmin: Error - this script is not being run by a member of the Administrator's group on this computer.  It must be run under an administrative account to be successful."
        }
        else {
            Log "IsRunByAdmin: Error - this script is not being run by a member of the Administrator's group on this computer.  It must be run under an administrative account to be successful."
            [System.Windows.Forms.MessageBox]::Show("You do not have Administrator rights to run this script! Please re-run this script as an Administrator.", "Error", $script:okButton)
        }
    }
    return $bAdmin
}


# IsAccountInAdminGroup: Check the Administrators group for inclusion of a given user account
Function IsAccountInAdminGroup($account_name) {
    $bInAdminGrp = $false
    $bPrependDomainToLocalUser = $true
    $members = @()
    if (($account_name -ne $null) -and ($account_name.Length -gt 0)) {
        $groupObj = [ADSI]"WinNT://./Administrators,group"
        $membersObj = @($groupObj.psbase.Invoke("Members"))

        # First try ADSpath so we have domain\user format
        Log "IsAccountInAdminGroup: Querying ADS path for Administrators members"
        $members = ($membersObj | ForEach-Object { $_.GetType().InvokeMember('ADspath', 'GetProperty', $null, $_, $null).Replace('WinNT://', '').Replace("/", "\") })
        if ($members.Count -eq 0) {
            # Get user names only in the Administrators group for comparison
            $members = ($membersObj | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) })
            $bPrependDomainToLocalUser = $false  # Do not match on usernames with domain prepended since Name property does not contain domain names
        }

        # Fix $account_name based on whether our list has domain names or not
        if (($bPrependDomainToLocalUser -eq $true) -and (-not $account_name.Contains('\'))) {
            $account_name = $script:localhost_name + '\' + $account_name
        }

        # Check members array for the user account
        Log "IsAccountInAdminGroup: Looking for user `"$account_name`" in Administrators group"
        if ($members -Contains $account_name) {
            Log "IsAccountInAdminGroup: User `"$account_name`" is in the Administrators group, so returning True."
            $bInAdminGrp = $true
        }
        else {
            Log "IsAccountInAdminGroup: User `"$account_name`" is *not* in the Administrators group, so returning False."
        }
    }
    else {
        Log "IsAccountInAdminGroup: A null or empty account name was passed in, so we cannot determine group membership."
    }
    return $bInAdminGrp
}


# GetAccountSID: Retrieves the S-xxx security identifier for the user account chosen for use for configuration and returns 
# either a SecurityIdentifier object or the SID string representation (if return_string is true)
Function GetAccountSID($user_account, $return_string) {
    $objUser = $null
    $sid = $null
    $user = $null
    $domain = $null
    $sid_obj = $null


    if ($user_account.Contains('\')) {
        $domainaccount = $user_account.Split('\')
        $domain = $domainaccount[0]
        $user = $domainaccount[1]
    }
    elseif ($user_account.Contains('@')) {
        $user, $domain = $user_account.Split('@') # both results will be send to the appropriate variable
    }
    else {
        $user = $user_account
    }

    try {
        if (($domain -ne $null) -and ($domain.Length -gt 0)) {
            Log "GetAccountSID: Creating object for (AD user) domain: `"$domain`" and user `"$user`""
            $objUser = New-Object System.Security.Principal.NTAccount($domain, $user)
        }
        else {
            Log "GetAccountSID: Creating object for local (non-AD) user `"$user`""
            $objUser = New-Object System.Security.Principal.NTAccount($user)
        }

        if ($objUser -ne $null) {
            Log "GetAccountSID: Translating account object to SID instance"
            $sid_obj = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
            $sid = $sid_obj.Value
            $sid = $sid.ToString()
            Log "GetAccountSID: SID retrieved for the specified user account to be used as SL1 credential is `"$sid`""
        }
    }
    catch {
        Log "GetAccountSID: Exception caught while translating account to SID - detail - $_"
    }

    # Return string representation or SID object, which caller may need to use in other APIs
    if ($return_string) {
        return $sid
    }
    else {
        return $sid_obj
    }
}


Function CreateAclMask($permissions) {
    $ENABLE = 1
    $METHOD_EXECUTE = 2
    $FULL_WRITE_REP = 4
    $PARTIAL_WRITE_REP = 8
    $WRITE_PROVIDER = 0x10
    $REMOTE_ACCESS = 0x20
    $RIGHT_SUBSCRIBE = 0x40
    $RIGHT_PUBLISH = 0x80
    $READ_CONTROL = 0x20000
    $WRITE_DAC = 0x40000
   
    $RIGHT_FLAGS = $ENABLE, $METHOD_EXECUTE, $FULL_WRITE_REP, $PARTIAL_WRITE_REP, $WRITE_PROVIDER, `
        $REMOTE_ACCESS, $READ_CONTROL, $WRITE_DAC
    $RIGHT_STRINGS = "Enable", "MethodExecute", "FullWrite", "PartialWrite", "ProviderWrite", "RemoteAccess", "ReadSecurity", "WriteSecurity"
    $permissionTable = @{}
    for ($i = 0; $i -lt $RIGHT_FLAGS.Length; $i++) {
        $permissionTable.Add($RIGHT_STRINGS[$i].ToLower(), $RIGHT_FLAGS[$i])
    }
    $accessMask = 0
    foreach ($permission in $permissions) {
        if (-not $permissionTable.ContainsKey($permission.ToLower())) {
            throw "Invalid value for a permission: `"$permission`"`nValid permissions: $($permissionTable.Keys)"
        }
        $accessMask += $permissionTable[$permission.ToLower()]
    }
    $accessMask
}

# GetSQLServerClusterInstanceNames: Finds every clustered instance of Microsoft SQL Server on the local
# computer to use for permisison settings, if this is a clustered computer
#
Function GetSQLServerClusterInstanceNames() { 
    $clus_instances = @{};
    $avail = Get-Command Get-ClusterResource -ErrorAction SilentlyContinue;
    if ($avail -ne $null) {
        $instances = Get-ClusterResource | Where-Object { $_.ResourceType -eq "SQL Server" };
        if ($instances -ne $null) { 
            foreach ($inst in $instances) {
                $param = $inst | Get-ClusterParameter -Name "InstanceName";
                $name = $param.Value.ToString();
                $param = $inst | Get-ClusterParameter -Name "VirtualServerName";
                $net_name = $param.Value.ToString();
                $owner_grp = Get-ClusterGroup -Name $inst.OwnerGroup.ToString();
                $owner_node = $owner_grp.OwnerNode.ToString(); 
                if ($owner_node.ToUpper() -eq $script:computer_name) {
                    $clus_instances[$name.ToUpper()] = $net_name;
                }
                else {
                    $clus_instances[$name.ToUpper()] = $null;
                }
            }
        }
    }
    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "GetSQLServerClusterInstanceNames: After running get-command on Get-ClusterResource, most recent error => $error_string"
    }
    $error.clear()
    return $clus_instances
}


# AddWinRMRights - give read/execute rights for WinRM to the user account specified 
# Equivalent of running winrm configsddl default
Function AddWinRMRights() {
    Log "AddWinRMRights: Enter"
    $bSuccess = $false

    try {
        # Get SID of user in object form
        Log "AddWinRMRights: Getting SID object for user account ..."
        $acct_sid = GetAccountSID $script:account $false

        # Account access needs to be added to WinRM root sddl
        $sddl = (Get-Item -Path WSMan:\Localhost\Service\RootSDDL).Value
        Log "AddWinRMRights: SDDL for root of WinRM retrieved = `"$sddl`""

        # Convert the SDDL string to a SecurityDescriptor object
        Log "AddWinRMRights: Instantiate new security descriptor object for SDDL retrieved ..."
        $sd = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $false, $false, $sddl

        # Update the DACL on the SecurityDescriptor object for this account and its permission
        Log "AddWinRMRights: Adding new DACL for this user account to the existing security descriptor"
        $sd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow,
            $acct_sid,
                                                              ($GENERIC_READ -bor $GENERIC_EXECUTE),
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None)

        # Get the SDDL string from the changed SecurityDescriptor object
        $new_sddl = $sd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)

        # Apply the new SDDL to the WinRM listener
        Log "AddWinRMRights: Setting the SDDL with the updated rights for the SL1 user"
        Set-Item -Path WSMan:\localhost\Service\RootSDDL -Value $new_sddl -Force | Out-Null
        $bSuccess = $true
    }
    catch {
        Log "AddWinRMRights: Exception caught while setting updated SDDL for SL1 user account - detail - $_"
    }

    Log "AddWinRMRights: Exit"
}


# AddUserToGroups: adds the user account specified to the security groups required for Windows Remote Management via Powershell
# and monitoring with Microsoft: Windows PowerPacks, inclusing Microsoft: SQL Server Enhanced PP.
Function AddUserToGroups($user) {
    Log "AddUserToGroups: Enter with user `"$user`""
    $bSuccess = $true
    $bPrependDomainToLocalUser = $true
    $members = @()
    $groups = @("WinRMRemoteWMIUsers__", "Remote Management Users", "Performance Monitor Users", "Distributed COM Users", "Event Log Readers")

    # First ensure user account is not in the Administrators group on the computer; if it is, there is no 
    # need to add it separately to each required user group
    if (IsAccountInAdminGroup($user) -eq $true) {
        Log "AddUserToGroups: User `"$user`" is already in the local Administrators group, so no need to add this user."
    }
    else {
        # Add-LocalGroupMember cmdlet was added in PowerShell 5.1, can be used going forward
        foreach ($group in $groups) {
            try {
                # Check to see if user is already in group
                try {
                    Log "AddUserToGroups: Checking if user `"$user`" is already in local user group `"$group`""
                    $groupObj = [ADSI]"WinNT://./$group,group"
                    if ($groupObj -ne $null) {
                        $membersObj = @($groupObj.psbase.Invoke("Members"))
                    }
                    else {
                        Log "AddUserToGroups: --- Unable to retrieve the members of this security user group, so skipping it (it may not exist on this computer)!"
                        continue
                    }
                }
                catch {
                    $bSuccess = $false
                    Log "AddUserToGroups: --- Exception caught while creating member list for this group, so skipping this group - detail - $_"
                    continue
                }

                # First try ADSpath so we have domain\user format
                Log "AddUserToGroups: --- Querying ADS path for group members"
                $members = ($membersObj | ForEach-Object { $_.GetType().InvokeMember('ADspath', 'GetProperty', $null, $_, $null).Replace('WinNT://', '').Replace("/", "\") })
                if ($members.Count -eq 0) {
                    # Get user names only in each respective group for comparison
                    $members = ($membersObj | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) })
                    $bPrependDomainToLocalUser = $false  # Do not match on usernames with domain prepended since Name property does not contain domain names
                }

                # Fix $user string based on whether our list was obtained with domain names or not
                if (($bPrependDomainToLocalUser -eq $true) -and (-not $user.Contains('\'))) {
                    $user = $script:localhost_name + '\' + $user
                }

                Log "AddUserToGroups: --- Is user `"$user`" one of these existing group members?  `"$members`""
                if ($members -Contains $user) {
                    Log "AddUserToGroups: --- User `"$user`" is already in local user group `"$group`", so not adding the account."
                }
                else {
                    Log "AddUserToGroups: --- Adding user `"$user`" to local user group `"$group`""
                    # Add local or domain user to local group
                    $output = Invoke-Command -ScriptBlock { net localgroup "$group" /add $user }
                    Log "AddUserToGroups: --- Output returned by `"net localgroup`": $output"
                }
            }
            catch {
                $bSuccess = $false
                Log "AddUserToGroups: --- Exception caught while adding account to nececessary user groups - detail - $_"
            }

        }  # Done foreach group to add to

    }

    Log "AddUserToGroups: Exit and returning $bSuccess"
    return $bSuccess
}


# CollectCurrentConfig: take inventory of current configuration settings that will be modified by this utility, save them to file, and save them for use throughout script
Function CollectCurrentConfig() {
    # Get OS and PowerShell info to save to the logging
    Log "CollectCurrentConfig: Getting PowerShell and Windows version info ..."
    try {
        $ps_ver_string = $PSVersionTable.PSVersion.ToString()
        $script:major_ps_ver = $PSVersionTable.PSVersion.Major
        Log "CollectCurrentConfig: PowerShell version - $ps_ver_string"
    }
    catch {
        # Assuming that verison 1.x of PowerShell is installed, as the lack of presence of $PSVersionTable should be
        # the only reason an exception should be thrown using that cmdlet, as it was introduced in v2.0
        Log "CollectCurrentConfig: Error occurred while fetching version of PowerShell - detail - $_"
        $script:major_ps_ver = 1
    }

    try {
        $os_ver = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName
        Log "CollectCurrentConfig: Windows information - $os_ver"
    }
    catch {
        Log "CollectCurrentConfig: Error occurred while fetching version of operating system - detail - $_"

    }

    # Fetch current authentication settings (basic auth, kerberos, AllowUnencyrpted, MaxConnections)
    # using Web Services Management provider (eg. WSMan)
    Log "CollectCurrentConfig: Getting current authentication and request/connection settings ..."

    # Basic Authentication: for this, the username and password are sent in the authentication exchange. Basic authentication can be 
    # configured to use either HTTP or HTTPS transport in a domain or workgroup.
    $basic_auth_enabled = (Get-Item WSMan:\Localhost\Service\Auth\Basic | % { $_.Value }).ToLower()
    if ($basic_auth_enabled -match "true") {
        Log "CollectCurrentConfig: Basic authentication is currently enabled - saving this value to backup."
        $script:original_basic_auth_enabled = $true
        SaveOriginal "Basic_Authentication_Enabled" "True"
    }
    else {
        Log "CollectCurrentConfig: Basic authentication is currently disabled - saving this value to backup."
        $script:original_basic_auth_enabled = $false
        SaveOriginal "Basic_Authentication_Enabled" "False"
    }

    # Kerberos Authentication: Mutual authentication between the client and server that uses encrypted keys. 
    # The client account must be a domain account in the same domain as the server. When a client uses 
    # default credentials (and is not connecting to localhost), Kerberos is the authentication method
    $kerberos_auth_enabled = (Get-Item WSMan:\Localhost\Service\Auth\Kerberos | % { $_.Value }).ToLower()
    if ($kerberos_auth_enabled -match "true") {
        Log "CollectCurrentConfig: Kerberos authentication is currently enabled - saving this value to backup."
        $script:original_kerberos_auth_enabled = $true
        SaveOriginal "Kerberos_Authentication_Enabled" "True"
    }
    else {
        Log "CollectCurrentConfig: Kerberos authentication is currently disabled - saving this value to backup."
        $script:original_kerberos_auth_enabled = $false
        SaveOriginal "Kerberos_Authentication_Enabled" "False"
    }

    # AllowUnencrypted: whether traffic between client and WinRM server will be encrypted - typically should be
    # enabled
    $allow_unencrypted = Get-Item WSMan:\Localhost\Service\AllowUnencrypted
    $allow_unencrypted_source = $allow_unencrypted.SourceOfValue
    $allow_unencrypted_traffic = ($allow_unencrypted.Value).ToLower()
    if ($allow_unencrypted_traffic -match "true") {
        Log "CollectCurrentConfig: AllowUnencrypted for WinRM traffic is currently enabled - saving this value to backup."
        $script:original_allow_unencrypted = $true
        SaveOriginal "WinRM_Allow_Unencrypted_Traffic" "True"
    }
    else {
        Log "CollectCurrentConfig: AllowUnencrypted for WinRM traffic is currently disabled - saving this value to backup."
        $script:original_allow_unencrypted = $false
        SaveOriginal "WinRM_Allow_Unencrypted_Traffic" "False"
    }
    if ($allow_unencrypted_source -and ($allow_unencrypted_source.Length -gt 0)) {
        Log "CollectCurrentConfig: Source of AllowUnencrypted for WinRM value is `"$allow_unencrypted_source`" - saving this value to backup."
        $script:original_allow_unencrypted_source = $allow_unencrypted_source
        SaveOriginal "WinRM_Allow_Unencrypted_Source" $allow_unencrypted_source
    }

    # MaxConnections: Specifies the maximum number of active requests that the service can process simultaneously - we increase this 
    # to allow for N number of Dynamic Applications from P number of collectors to collect on this computer.
    $max_winrm_requests = Get-Item WSMan:\Localhost\Service\MaxConnections | % { $_.Value }
    if ($max_winrm_requests -and ($max_winrm_requests.Length -gt 0)) {
        Log "CollectCurrentConfig: Max WinRM connections is currently set to `"$max_winrm_requests`" - saving this value to backup."
        $script:original_max_requests = $max_winrm_requests
        SaveOriginal "WinRM_Max_WinRM_Requests" $script:original_max_requests
    }

    # HTTP listener: used for communication if traffic is not to be encrypted
    $http_listener = dir WSMan:\Localhost\Listener\* | ? { $_.Keys -like "*HTTP" } | % { $_.Name }
    if ($http_listener -and ($http_listener.Length -gt 0)) {
        Log "CollectCurrentConfig: Name of HTTP listener = $http_listener"
        $script:original_http_listener = $http_listener
        $script:http_listener = $http_listener
        $script:original_http_port = Get-Item WSMan:\Localhost\Listener\$http_listener\Port | % { $_.Value }
        Log "CollectCurrentConfig: HTTP listener port is currently set to `"$script:original_http_port`" - saving this value to backup."
        SaveOriginal "HTTP_Listener_Port" $script:original_http_port
    }
    else {
        Log "CollectCurrentConfig: HTTP listener port value was *not* found on the computer.."
        $script:change_winrm_ports = $true
   	    $script:original_http_port = $DEFAULT_WINRM_HTTP_PORT
        SaveOriginal "HTTP_Listener_Port" $DEFAULT_WINRM_HTTP_PORT
    }

    # HTTPS listener: used for communication if traffic is to be encrypted
    $https_listener = dir WSMan:\Localhost\Listener\* | ? { $_.Keys -match "HTTPS" } | % { $_.Name }
    if ($https_listener -and ($https_listener.Length -gt 0)) {
        Log "CollectCurrentConfig: Name of HTTPS listener = $https_listener"
        $script:original_https_listener = $https_listener
        $script:https_listener = $https_listener
        $script:original_https_port = Get-Item WSMan:\Localhost\Listener\$https_listener\Port | % { $_.Value }
        Log "CollectCurrentConfig: HTTPS listener port is currently set to `"$script:original_https_port`" - saving this value to backup."
        SaveOriginal "HTTPS_Listener_Port" $script:original_https_port
    }
    else {
        Log "CollectCurrentConfig: HTTPS listener port value was *not* found on the computer.."
        $script:change_winrm_ports = $true
   	    $script:original_https_port = $DEFAULT_WINRM_HTTPS_PORT
        SaveOriginal "HTTPS_Listener_Port" $DEFAULT_WINRM_HTTPS_PORT
    }

    # If being asked to change the idleTimeout, make sure the information is not controlled by GPO
    $idle_data = (Get-Item WSMan:\Localhost\Shell\IdleTimeout)
    $script:current_idle_timeout = $idle_data.Value
    $idle_timeout_source = $idle_data.SourceOfValue

    # If GPO is used then we will not change anything
    if ($idle_timeout_source.Length -gt 0 -and $idle_timeout_source.ToUpper() -eq "GPO") {
        $script:winrm_set_idle = $false
        Log "CollectCurrentConfig: IdleTimeout is set by Group Policy and will not be changed by this script"
    }
    else {
        Log "CollectCurrentConfig: IdleTimeout current value: $script:current_idle_timeout - saving this value to backup"
        SaveOriginal "IdleTimeout" $script:current_idle_timeout
    }


}  # end CollectCurrentConfig


# SetAuthenticationType: Show dialogs for user to choose authentication and account settings
Function SetAuthenticationType() {
    $DIALOG_INTRO = "This program will configure Windows Remote Management on your Windows "
    $DIALOG_INTRO += " Server, permissions to use WMI, query performance counters and event logs. "
    $DIALOG_INTRO += " It will ask a series of questions to determine the preferred security settings and will "
    $DIALOG_INTRO += " display your choices at the end. Configuration changes will not be made until the "
    $DIALOG_INTRO += " end of the wizard.  Before beginning, here are your current settings: `n`n"
    $DIALOG_INTRO += "                        Basic Authentication = $script:original_basic_auth_enabled `n"
    $DIALOG_INTRO += "                        Kerberos Authentication = $script:original_kerberos_auth_enabled `n"
    $DIALOG_INTRO += "                        Allow Unencrypted WinRM Traffic = $script:original_allow_unencrypted `n"
    $DIALOG_INTRO += "                        Maximum WinRM Requests = $script:original_max_requests `n"
    $DIALOG_INTRO += "                        IdleTimeout = $script:current_idle_timeout `n"
    $DIALOG_INTRO += "                        HTTP Port = $script:original_http_port `n"
    $DIALOG_INTRO += "                        HTTPS Port = $script:original_https_port `n`n"
    $DIALOG_INTRO += "NOTE: This wizard cannot override settings applied by Group Policy (GPO). "
    $DIALOG_INTRO += "To overwrite those settings, please contact a system administrator. `n`n"
    $DIALOG_INTRO += "Click OK to Continue."

    $DIALOG_ACCT_TYPE = "Will you be using an Active Directory domain account? `n`n"
    $DIALOG_ACCT_TYPE += "        Click YES to enable Kerberos Authentication. `n"
    $DIALOG_ACCT_TYPE += "        Click NO to enable Basic Authentication. "

    $DIALOG_ENCRYPTION = "Should your WinRM traffic from SL1 be encrypted? `n`n"
    $DIALOG_ENCRYPTION += "        Click YES to use only encrypted data. `n"
    $DIALOG_ENCRYPTION += "        Click NO to allow unencrypted data."

    $DIALOG_MAX_REQUESTS = "This host allows $script:original_max_requests WinRM requests at one time. `n"
    $DIALOG_MAX_REQUESTS += "Do you want to change this value of maximum requests? `n`n"
    $DIALOG_MAX_REQUESTS += "        Click YES to edit the maximum number of requests. `n"
    $DIALOG_MAX_REQUESTS += "        Click NO to leave the maximum number of requests unchanged."

    $DIALOG_IDLE = "This host currently has WinRM IdleTimeout of $script:current_idle_timeout ms. `n"
    $DIALOG_IDLE += "Do you want to change this value for the IdleTimeout? `n`n"
    $DIALOG_IDLE += "        Click YES to edit the IdleTimeout. `n"
    $DIALOG_IDLE += "        Click NO to leave the IdleTimeout unchanged."


    if (-not $silent) {
        Log "SetAuthenticationType: Starting wizard ...."
        if ([System.Windows.Forms.MessageBox]::Show($DIALOG_INTRO, "WinRM Installation Wizard", $okCancelButtons) -eq $OkClicked) {

            # Get user account type to determine authentication type to use
            $using_ad_acct = [System.Windows.Forms.MessageBox]::Show($DIALOG_ACCT_TYPE, "Windows Account Type", $yesNoButtons)
            $using_ad_acct = $using_ad_acct.ToString()
            if ($using_ad_acct.ToLower() -eq "yes") {
                Log "SetAuthenticationType: User selected Active Directory domain account for Windows account type to be used for ScienceLogic credential."
                $script:domain_acct = $true
            }
            else {
                Log "SetAuthenticationType: User selected that a local Windows account type will be used for ScienceLogic credential."
            }

            # Future: allow user to enter the user account name in the user interface when not running this utility silently
            # As of now, must specify user on the command-line in order to proceed with an interactive config

            # Get choice of encryption of traffic
            $use_encrypted_data = [System.Windows.Forms.MessageBox]::Show($DIALOG_ENCRYPTION, "Set Encryption Policy", $yesNoButtons)
            $use_encrypted_data = $use_encrypted_data.ToString()
            if ($use_encrypted_data.ToLower() -eq 'yes') {
                $script:allow_unencrypted = $false
                Log "SetAuthenticationType: User selected to allow only `"encrypted`" WinRM traffic between SL1 and Windows."
            }
            else {
                $script:allow_unencrypted = $true
                Log "SetAuthenticationType: User selected to allow `"unencrypted`" WinRM traffic between SL1 and Windows."
            }

            # Get the number of the WinRM connections the server ought to allow simultaneously
            $show_max_requests = [System.Windows.Forms.MessageBox]::Show($DIALOG_MAX_REQUESTS, "Change Max Requests", $yesNoButtons)
            $show_max_requests = $show_max_requests.ToString()
            if ($show_max_requests.ToLower() -eq 'no') {
                Log "SetAuthenticationType: User chose *NOT* to modify max connections (eg. simulataneous requests) value."
                $script:change_max_connections = $false
            }
            else {
                Log "SetAuthenticationType: User wants to change the max WinRM connections value (eg. simulaneous requests), so display that dialog now."

                # Define the form size & placement of max connections/request dialog
                $connform = New-Object System.Windows.Forms.Form
                $connform.Width = 360
                $connform.Height = 150
                $connform.Text = "Set maximum WinRM Requests"
                $connform.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
                $connform.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
                $connform.MinimizeBox = $false

                # Ask for new maximum WInRM requests number
                $maxConnLabel = New-Object System.Windows.Forms.Label
                $maxConnLabel.Left = 30
                $maxConnLabel.Top = 40
                $maxConnLabel.AutoSize = $true
                $maxConnLabel.Text = "Set maximum WinRM Requests to: "

                # Text box for setting value
                $maxConnNumberBox = New-Object System.Windows.Forms.NumericUpDown
                $maxConnNumberBox.Left = 220
                $maxConnNumberBox.Top = 38
                $maxConnNumberBox.width = 60
                $maxConnNumberBox.Minimum = 0
                $maxConnNumberBox.Maximum = 10000

                # Define default values
                $maxConnNumberBox.Value = $script:original_max_requests

                # Define OK button
                $button = New-Object System.Windows.Forms.Button
                $button.Left = 234
                $button.Top = 82
                $button.Width = 80
                $button.Text = $OkClicked
                

                # Close the form after getting values
                $eventHandler = [System.EventHandler] { $connform.Close() }
                $button.Add_Click($eventHandler)

                # Add controls to all the above objects defined
                $connform.Controls.Add($button)
                $connform.Controls.Add($maxConnLabel)
                $connform.Controls.Add($maxConnNumberBox)
                $ret = $connform.ShowDialog()

                # Set new value 
                $script:max_winrm_requests = $maxConnNumberBox.Value
                Log "SetAuthenticationType: User wants to change the max WinRM connections value to $script:max_winrm_requests"
            }

            # Set WinRM IdleTimeout
            $show_idle_timeout = [System.Windows.Forms.MessageBox]::Show($DIALOG_IDLE, "Change IdleTimeout", $yesNoButtons)
            $show_idle_timeout = $show_idle_timeout.ToString()
            if ($show_idle_timeout.ToLower() -eq 'no') {
                Log "SetAuthenticationType: User chose *NOT* to modify IdleTimeout value."
                $script:winrm_set_idle = $false
            }
            else {
                $form = New-Object System.Windows.Forms.Form
                $form.Width = 260
                $form.Height = 100
                $form.Text = "Set WinRM IdleTimeout"
                $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
                $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
                $form.MaximizeBox = $false
                $form.MinimizeBox = $false

                $timeoutLabel = New-Object System.Windows.Forms.Label
                $timeoutLabel.Left = 10
                $timeoutLabel.Top = 15
                $timeoutLabel.Width = 120
                $timeoutLabel.Text = "IdleTimeout (seconds):"

                $seconds = $script:current_idle_timeout / 1000

                $timeoutText = New-Object System.Windows.Forms.TextBox
                $timeoutText.Left = 140
                $timeoutText.Top = 15
                $timeoutText.Width = 100
                $timeoutText.Text = $seconds

                $okButton = New-Object System.Windows.Forms.Button
                $okButton.Left = 190
                $okButton.Top = 40
                $okButton.Width = 50
                $okButton.Text = "OK"

                $eh = [System.EventHandler] {
                    $timeoutText.Text = $timeoutText.Text -replace '\D'
                    $form.Close()
                }

                $okButton.Add_Click($eh)

                $form.Controls.Add($okButton)
                $form.Controls.Add($timeoutLabel)
                $form.Controls.Add($timeoutText)
                $dlg = $form.ShowDialog()

                $newValue = $timeoutText.Text

                if ($newValue -as [int]) {
                    $newValue = $newValue -as [int]
                    
                    if ($newValue -ge 300 -and $newValue -le 14400) {
                        Log "SetAuthenticationType: User supplied value for IdleTimeout will be used: $newValue"
                        $script:winrm_idle_timeout = ($newValue * 1000)
                        $script:winrm_set_idle = $true
                    }
                    else {
                        Log "SetAuthenticationType: User supplied value for IdleTimeout of $newValue is outside acceptable range - not changing"
                        $script:winrm_set_idle = $false
                    }
                }
                else {
                    Log "SetAuthenticationType: User entered an invalid value $newValue for idleTimeout - not changing"
                    $script:winrm_set_idle = $false
                } 

            }

        }
        else {
            Log "SetAuthenticationType: The wizard was closed by the user."
        }

        # Set WinRM IdleTimeout

    }
}


# GrantUserSQLServerPermissions: sets read-only access for the specified user on SQL Server instance and databases
# installed on the local computer. The permissions granted below are considered a least-privilege set and is the easiest
# set to provide with these least-privilege settings.
Function GrantUserSQLServerPermissions() {
    # Using user_login as the account variable to grant access
    $user_login = $script:account
    # We need SQL Server network name\instance name for clustered instances to connect to
    Log "GrantUserSQLServerPermissions: Calling GetSQLServerClusterInstanceNames() to find any clustered SQL Server instances."
    $sql_cluster_instances = GetSQLServerClusterInstanceNames
    $server = $null

    try {
        # Load the SMO assembly for use
        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null;
        if ($error.count -gt 0) {
            $error_string = $error[0].ToString()
            Log "GrantUserSQLServerPermissions: After attempting to import the `"SQLPS`" PowerShell module, error set was: $error_string"
            $error.clear()
        }
        Log "`r`n"

        # First get the names of all Microsoft SQL Server Instances on this computer - use service names as the indicator, instead of 
        # the registry, since the service must be running anyway to set permissions
        $instances = @()
        $services = Get-Service -ErrorAction SilentlyContinue | where { $_.Name -match "MSSQL" -and $_.DisplayName -match "SQL Server \(" }
        if ($services -ne $null) {
            foreach ($svc in $services) {
                $svc_name = $svc.Name
                if ($svc.Status -eq "Running") {
                    if ($svc_name.ToUpper() -eq "MSSQLSERVER") {
                        $instances += "MSSQLSERVER"
                    }
                    else {
                        # Parse the service name to get the name of the SQL Server instance
                        $name = $svc_name.ToUpper()
                        $instances += $name.substring(6)
                    }
                }
                else {
                    Log "GrantUserSQLServerPermissions: [[ WARNING: the service `"$svc_name`" is *NOT* running, so not setting permissions on its SQL Server instance!! ]]`r`n"
                    continue
                }

            }
        }

        if ($instances.Count -gt 0) {
            foreach ($instance in $instances) {
                # Compare with clustered instance names found, in order to determine which string
                # to use as the server name
                Log "GrantUserSQLServerPermissions: ---------- Granting permissions for user `"$user_login`" on instance `"$instance`" ----------"
                $netwkname = $null
                if (($sql_cluster_instances.Count -gt 0) -and ($sql_cluster_instances.ContainsKey($instance))) {
                    $nn = $sql_cluster_instances[$instance];
                    if ($nn -ne $null) {
                        if ($instance -eq "MSSQLSERVER") {
                            $netwkname = $nn
                            Log "GrantUserSQLServerPermissions: Cluster network name for this default instance set to: $netwkname"
                        }
                        else {
                            $netwkname = $nn + '\' + $instance
                            Log "GrantUserSQLServerPermissions: Cluster network name for this instance set to: $netwkname"
                        }
                    } 
                }

                try {
                    # Get an SMO.Server object instance to each SQL instance by server identifier
                    if ($netwkname -eq $null) {
                        if ($instance.ToUpper() -eq "MSSQLSERVER") {
                            $server = $script:computer_name
                            Log "GrantUserSQLServerPermissions: Obtaining SMO.Server object for standalone (default) instance `"$server`""
                            $SMOServer = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $server
                        }
                        else {
                            $server = "{0}\{1}" -f $script:computer_name, $instance
                            Log "GrantUserSQLServerPermissions: Obtaining SMO.Server object for standalone instance `"$server`""
                            $SMOServer = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $server
                        }
                    }
                    else {
                        $server = $netwkname
                        Log "GrantUserSQLServerPermissions: Obtaining SMO.Server object for clustered instance $server"
                        $SMOServer = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $server
                    }

                    # Figure out the major version of SQL Server that this instance is
                    # Default to SQL Server 2014 (v12)
                    $sql_version = 12
                    $sql_version_string = $SMOServer.VersionMajor
                    if ($sql_version_string -ne $null) {
                        $sql_version = [int32]$sql_version_string
                    }
                    Log "GrantUserSQLServerPermissions: Instance `"$instance `" is SQL Server major version `"$sql_version`""

                    # Step 1: Create a SQL login with the user account, if it doesn't already exist
                    Log "GrantUserSQLServerPermissions: Creating a SqlServer.Management.Login object for user `"$user_login`""
                    $sql_login = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Login -ArgumentList $SMOServer, $user_login
                    if ($SMOServer.Logins.Contains($user_login)) {
                        Log "GrantUserSQLServerPermissions: User $user_login already exists as a login on instance `"$instance`", so not creating it."
                        $sql_login.Enable()
                    }
                    else {
                        Log "GrantUserSQLServerPermissions: Creating user `"$user_login`" on instance `"$instance`" using SMO..."
                        $sql_login.LoginType = "WindowsUser"
                        $sql_login.Create()
                        Log "GrantUserSQLServerPermissions: Enabling user `"$user_login`" on instance `"$instance`" using SMO..."
                        $sql_login.Enable()
                    }

                    # Step 2 - Grant CONNECT SQL, VIEW SERVER STATE and CONNECT ANY DATABASE (if SQL 2014 or newer) to the 
                    # user on each SQL Server instance on the computer
                    Log "GrantUserSQLServerPermissions: Setting server-level permissions ..."
                    $permission_set = New-Object -TypeName Microsoft.SqlServer.Management.SMO.ServerPermissionSet 
                    $permission_set.ViewServerState = $true
                    if ($sql_version -gt 11) {
                        # Available in SQL 2014 and newer releases
                        $permission_set.ConnectAnyDatabase = $true
                        Log "GrantUserSQLServerPermissions: Granting CONNECT SQL, CONNECT ANY DATABASE, and VIEW SERVER STATE permission to $user_login, on this instance ..."
                    }
                    else {
                        Log "GrantUserSQLServerPermissions: Granting CONNECT SQL and VIEW SERVER STATE permission to $user_login, on this instance ..."
                    }
                    $permission_set.ConnectSql = $true
                    $SMOServer.Grant($permission_set, $user_login)

                    # Step 3 - Grant VIEW DATABASE STATE to the 'master' database on each SQL Server instance on the computer
                    Log "GrantUserSQLServerPermissions: Granting VIEW DATABASE STATE permission to $user_login on the `"master`" database ..."
                    $master_db = $SMOServer.Databases["master"]
                    $permission_set = New-Object -TypeName Microsoft.SqlServer.Management.SMO.DatabasePermissionSet
                    $permission_set.ViewDatabaseState = $true
                    $master_db.Grant($permission_set, $user_login)

                    # Step 4  - Grant the DB_DATA_READER role to the user account on the 'master' database (user login will already exist on this login)
                    Log "GrantUserSQLServerPermissions: Adding `"$user_login`" to the `"db_datareader`" role on the `"master`" database on instance `"$instance`""
                    $role_master = $master_db.Roles["db_datareader"]
                    $role_master.AddMember($user_login)

                    # Step 5  - Grant the DB_DATA_READER role to the user account on the 'msdb' database (user login must be added to the database
                    # if it does not already exist, prior to adding it to the database role)
                    $msdb_db = $SMOServer.Databases["msdb"]
                    if ($msdb_db.Users.Contains($user_login)) {
                        Log "GrantUserSQLServerPermissions: User `"$user_login`" is already a login on the `"msdb`" database on instance `"$instance`""
                    }
                    else {
                        # Add user to database and enable the user
                        Log "GrantUserSQLServerPermissions: Adding user `"$user_login`" as a login on the `"msdb`" database on instance `"$instance`""
                        $usr = New-Object ('Microsoft.SqlServer.Management.Smo.User') ($msdb_db, $user_login)
                        $usr.Login = $user_login
                        $usr.Create()
                    }
                    Log "GrantUserSQLServerPermissions: Adding `"$user_login`" to the `"db_datareader`" role on the `"msdb`" database on instance `"$instance`""
                    $role_msdb = $msdb_db.Roles["db_datareader"]
                    $role_msdb.AddMember($user_login)

                    # Step 6: Grant CONNECT permissions to the user account on all databases if the SQL Server instance
                    # is SQL Server 2012 or 2008R2
                    if ($sql_version -lt 12) {
                        $all_dbs = $SMOServer.Databases
                        $permission_set = New-Object -TypeName Microsoft.SqlServer.Management.SMO.DatabasePermissionSet
                        Log "GrantUserSQLServerPermissions: Granting CONNECT permission to user `"$user_login`" for ALL databases on this pre-SQL 2014 version instance."
                        $permission_set.Connect = $true
                        foreach ($db in $all_dbs) {
                            $db_name = $db.Name
                            try {
                                # Use separate try...catch since db permission setting is more noisy
                                $db.Grant($permission_set, $user_login)
                            }
                            catch {
                                # Log exception and Inner exception for more detail on failure
                                $inner_exception = $error[0].Exception.InnerException
                                $inner_exception = $inner_exception.ToString()
                                Log "GrantUserSQLServerPermissions: Exception occurred while granting CONNECT permission to database `"$db_name`" - $_`r`n`r`n$inner_exception`r`n`r`n"
                                $error.clear()
                            }
                        }
                    }

                    Log "GrantUserSQLServerPermissions: *********** Done with instance `"$instance`" **********`r`n"

                    # Log last error for troubleshooting purposes
                    if ($error.count -gt 0) {
                        $error_string = $error[0].ToString()
                        Log "GrantUserSQLServerPermissions: After granting SQL Server permissions to instance `"$instance`", most recent error => $error_string"
                        $error.clear()
                    }
                }
                catch {
                    # Inner exception - look for message contents to get at the heart of the problem
                    Log "GrantUserSQLServerPermissions: Exception occurred while granting SQL Server permissions to instance `"$instance`"- detail - $_"
                    $inner_exception = $error[0].Exception.InnerException
                    $inner_exception = $inner_exception.ToString()
                    Log "GrantUserSQLServerPermissions: InnerException = `r`n`r`n$inner_exception`r`n`r`n"
                }
            } # end foreach instance

        }
        else {
            Log "GrantUserSQLServerPermissions: No Microsoft SQL Server instances were found to be in a running state on this computer."
        }

        if ($error.count -gt 0) {
            $error_string = $error[0].ToString()
            Log "GrantUserSQLServerPermissions: After granting SQL Server permissions, most recent error => $error_string"
            $error.clear()
        }
    }
    catch {
        Log "GrantUserSQLServerPermissions: Outer exception handler caught exception with detail - $_"
        if ($error.count -gt 0) {
            $error_string = $error[0].ToString()
            Log "GrantUserSQLServerPermissions: After catching outer exception, most recent error => $error_string"
        }
    }

    $error.clear()
    Log "GrantUserSQLServerPermissions: Exiting"
    return $true
}


# ConfigureClusterSecurity: sets read-only access for the specified user on the local Failover Cluster
Function ConfigureClusterSecurity() {
    try {
        Log "ConfigureClusterSecurity: Granting read-only access to the local Failover Cluster for user $($script:account) ..."
        $cmdlet_avail = Get-Command Grant-ClusterAccess -ErrorAction SilentlyContinue
        if ($cmdlet_avail -ne $null) {
            Grant-ClusterAccess -User $script:account -ReadOnly
        }
        else {
            Log "ConfigureClusterSecurity: This computer does not appear to be part of a Failover Cluster."
        }
        if ($error.count -gt 0) {
            $error_string = $error[0].ToString()
            Log "ConfigureClusterSecurity: After running Grant-ClusterAccess command, most recent error => $error_string"
        }
    }
    catch {
        Log "ConfigureClusterSecurity: Error occurred while granting read-only cluster access - detail - $_"
    }
    $error.clear()
    Log "ConfigureClusterSecurity: Exiting"
    return $true
}


# EnabledPSRemoting: sets the computer up to receive and run remote PowerShell commands through Windows Remote Mgmt
Function EnablePSRemoting() {
    try {
        Log "Enabling RemoteSigned execution policy for PowerShell scripts..."
        Set-ExecutionPolicy RemoteSigned

        Log "EnablePSRemoting: Executing the Enable-PSRemoting cmdlet, which will restart the relevant WinRM services"
        Enable-PSRemoting -SkipNetworkProfileCheck -Force
    }
    catch {
        Log "EnablePSRemoting: Error occurred while enabling PS remoting - detail - $_"
    }

    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "EnablePSRemoting: After running Set-ExecutionPolicy command, most recent error => $error_string"
    }
    $error.clear()

    Log "EnablePSRemoting: Exiting"
    return $true
}


# ConfigureWinRM: sets up the default WinRM configuration settings, including:
# - starts Windows Remote Management service
# - creates default listener for HTTP/HTTPS ports (we later update this setting) depending
#   on choice of encrypted/unencrypted
# - creates firewall exception for WS-Mgmt traffic (but only for the Admin user running this utility)
Function ConfigureWinRM() {
    # Delete the existing HTTPS listener if it exists, we will recreate it at the end
    $listenerExists = Invoke-Command -ScriptBlock { winrm e winrm/config/listener } | Select-String "HTTPS"
    if ($listenerExists) {
        try {
            Log "ConfigureWinRM: Deleting the existing HTTPS listener..."
            $output = Invoke-Command -ScriptBlock { winrm delete winrm/config/Listener?Address=*+Transport=HTTPS }
            Log "ConfigureWinRM: Removed the existing HTTPS listener..."
        }
        catch {
            Log "ConfigureWinRM: Could not remove existing listener"
        }
    }

    Log "ConfigureWinRM: Stopping WinRM service ...."
    $output = Invoke-Command -ScriptBlock { Stop-Service WinMgmt -Force -ErrorAction SilentlyContinue }
    Log "ConfigureWinRM: Stop-Service on WinMgmt service returned: $output"

    # Give use WinRM rights
    Log "ConfigureWinRM: Adding user account the ability to connect over WinRM ..."
    $bSuccess = AddWinRMRights

    if ($script:allow_unencrypted -eq $true) {
        Log "ConfigureWinRM: Running winrm quickconfig -force...."
        $output = Invoke-Command -ScriptBlock { winrm quickconfig -force }
    }
    else {
        Log "ConfigureWinRM: Running winrm quickconfig -transport:https -force ...."
        $output = Invoke-Command -ScriptBlock { winrm quickconfig -transport:https -force }
    }
    Log "ConfigureWinRM: winrm quickconfig returned: $output"

    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "ConfigureWinRM: After running winrm quickconfig command, most recent error => $error_string"
    }
    $error.clear()

    Log "ConfigureWinRM: Exiting."
    return $true
}



# SetHTTPPorts: ensures the HTTP or HTTPS ports the user wants to user are set for WinRM authentication and communication
Function SetHTTPPorts() {
    Log "SetHTTPPorts: Enter"

    # Search for digital certificates that can used for configuring WinRM listener later
    $first_saved = $false
    $first_print = $null
    $priority_thumbprint = $null
    try {
        Log "SetHTTPPorts: Looking for certificate thumbprints on the computer ..."
        $thumbprints = Get-ChildItem -Path Cert:\LocalMachine\My -EKU "*Server Authentication*"
        foreach ($thumbprint in $thumbprints) {
            if ($first_saved -ne $true) {
                # Save first thumbprint in case we don't find one for the WMSVC or one issued from domain CN
                $first_print = $thumbprint
                $first_saved = $true
                Log "SetHTTPPorts: Found at least one thumbprint, so saving it ..."
            }
            if ($thumbprint.FriendlyName -and ($thumbprint.FriendlyName -eq "WMSVC")) {
                # A cert issued for the WMSVC takes priority to use for WinRM config
                $priority_thumbprint = $thumbprint
                Log "SetHTTPPorts: Found WMSVC thumbprint, so saving it ..."
            }
            else {
                # Use DC-issued cert thumbprint if we don't find WMSVC one
                if ($thumbprint.Issuer -and ($thumbprint.Issuer -match "DC=")) {
                    if ($priority_thumbprint -eq $null) {
                        $priority_thumbprint = $thumbprint
                        $cert_issuer = ($thumbprint.Issuer).ToString()
                        Log "SetHTTPPorts: Saving certificate thumbprint issued by Domain Controller"
                    }
                }
            }
        } # end foreach thumbprint returned

    }
    catch {
        Log "SetHTTPPorts: Error occurred while saving certificate thumbprint - detail - $_"
    }

    if ($priority_thumbprint -ne $null) {
        $script:cert_thumbprint = ($priority_thumbprint.Thumbprint).ToString()
        Log "SetHTTPPorts: Priority certificate thumbprint saved: `"$script:cert_thumbprint`" "
    }
    else {
        if ($first_print -ne $null) {
            $script:cert_thumbprint = ($first_print.Thumbprint).ToString()
            Log "SetHTTPPorts: Certificate thumbprint saved: `"$script:cert_thumbprint`" "
        }
    }

    # Allow user to enter HTTP and HTTPS ports interactively, as well as a digital certificate thumbprint
    if (-not $silent) {
        $DIALOG_PORTS = "Your current HTTP port for Windows Remote Management is set to $script:original_http_port, "
        $DIALOG_PORTS += "and the HTTPS port for Windows Remote Management is set to $script:original_https_port. "
        $DIALOG_PORTS += "Do you want to modify these ports for WinRM traffic use?`n`n "
        $DIALOG_PORTS += "           Click YES to edit your HTTP/HTTPS ports.`n"
        $DIALOG_PORTS += "            Click NO to continue to the next page."

        # Allow user to make port changes interactively, as well as requring manually obtain cert thumbprint
        $change_ports = [System.Windows.Forms.MessageBox]::Show($DIALOG_PORTS, "Set Ports for WinRM Traffic", $yesNoButtons)
        $change_ports = $change_ports.ToString()
        if ($change_ports.ToLower() -eq "yes") {

            # Define the form size & placement
            $form = New-Object System.Windows.Forms.Form
            $form.Width = 380
            $form.Height = 150
            $form.Text = "Set HTTP/HTTPS Ports"
            $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
            $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

            # Ask for new HTTP port number
            $httpLabel = New-Object System.Windows.Forms.Label
            $httpLabel.Left = 50
            $httpLabel.Top = 16
            $httpLabel.Text = "New HTTP port:"

            # Ask for new HTTPS port number
            $httpsLabel = New-Object System.Windows.Forms.Label
            $httpsLabel.Left = 50
            $httpsLabel.Top = 56
            $httpsLabel.Text = "New HTTPS port:"

            # Text box for HTTP port number
            $httpTextBox = New-Object System.Windows.Forms.TextBox
            $httpTextBox.Left = 160
            $httpTextBox.Top = 15
            $httpTextBox.width = 100

            # Text box for HTTPS port number
            $httpsTextBox = New-Object System.Windows.Forms.TextBox
            $httpsTextBox.Left = 160
            $httpsTextBox.Top = 55
            $httpsTextBox.width = 100

            # Define default values
            if ($script:original_http_port -and ($script:original_http_port.Length -gt 0)) {
                $httpTextBox.Text = $script:original_http_port
            }
            else {
                $httpTextBox.Text = $DEFAULT_WINRM_HTTP_PORT
            }

            if ($script:original_https_port -and ($script:original_https_port.Length -gt 0)) {
                $httpsTextBox.Text = $script:original_https_port
            }
            else {
                $httpsTextBox.Text = $DEFAULT_WINRM_HTTPS_PORT
            }

            # Define OK button
            $button = New-Object System.Windows.Forms.Button
            $button.Left = 270
            $button.Top = 85
            $button.Width = 80
            $button.Text = $OkClicked

            # Close the form after getting values
            $eventHandler = [System.EventHandler] {
                $httpTextBox.Text = $httpTextBox.Text -replace '\D'
                $httpsTextBox.Text = $httpsTextBox.Text -replace '\D'
                $form.Close() 
            }

            $button.Add_Click($eventHandler)

            # Add controls to all the above objects defined
            $form.Controls.Add($button)
            $form.Controls.Add($httpLabel)
            $form.Controls.Add($httpsLabel)
            $form.Controls.Add($httpTextBox)
            $form.Controls.Add($httpsTextBox)
            $dialog_ret = $form.ShowDialog()
            Log "SetHTTPPorts: Return code from HTTP/HTTPS dialog was $dialog_ret"

            # Set new variables
            $script:http_port = $httpTextBox.Text
            $script:https_port = $httpsTextBox.Text
            Log "SetHTTPPorts: User entered (or kept in place) HTTP port: $script:http_port"
            Log "SetHTTPPorts: User entered (or kepy in place) HTTPS port: $script:https_port"

            # Ask for digital cert thumbprints
            if (($script:allow_unencrypted -eq $false) -or ($script:https_port -and ($script:https_port.Length -gt 0))) {

                # If unencrypted traffic not selected, or if HTTPS port filled in, let's prompt for a digital
                # cert thumbprint. If the HTTPS port happens to have been left empty, it will be 
                # populated with Microsoft's default during configuration.
                $DIALOG_CERT = "To setup the WinRM HTTPS listener, you will need to use a certificate thumbprint`n"
                $DIALOG_CERT += "Run the PowerShell cmdlet below on this Windows computer to get your existing certificate thumbprints:`n`n"
                $DIALOG_CERT += "           Get-ChildItem -Path Cert:\LocalMachine\My `n`n"
                $DIALOG_CERT += "Then press OK to continue."

                # Create the Label.
                $certlabel = New-Object System.Windows.Forms.Label
                $certlabel.Location = New-Object System.Drawing.Size(10, 10) 
                $certlabel.Size = New-Object System.Drawing.Size(280, 20)
                $certlabel.AutoSize = $true
                $certlabel.Text = $DIALOG_CERT
  				 
                # Create the TextBox
                $certtextBox = New-Object System.Windows.Forms.TextBox 
                $certtextBox.Location = New-Object System.Drawing.Size(10, 40) 
                $certtextBox.Size = New-Object System.Drawing.Size(575, 50)
                $certtextBox.Top = 130
                $certtextBox.AcceptsReturn = $true
                $certtextBox.AcceptsTab = $false
                $certtextBox.Multiline = $true
                $certtextBox.ScrollBars = 'Both'
                $certtextBox.Text = "Enter your certificate thumbprint here..."
  				 
                # Create the OK button.
                $okButton = New-Object System.Windows.Forms.Button
                $okButton.Location = New-Object System.Drawing.Size(510, 220)
                $okButton.Size = New-Object System.Drawing.Size(75, 25)
                $okButton.Text = $OkClicked
                $okButton.Add_Click({ $form.Tag = $certtextBox.Text; $form.Close() })
  				 
                # Create the form.
                $form = New-Object System.Windows.Forms.Form 
                $form.Text = "Set HTTPS Thumbprint"
                $form.Size = New-Object System.Drawing.Size(610, 300)
                $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
                $form.StartPosition = "CenterScreen"
                $form.AutoSizeMode = 'GrowAndShrink'
                $form.Topmost = $True
                $form.AcceptButton = $okButton
                $form.ShowInTaskbar = $true
  				 
                # Add form controls
                $form.Controls.Add($certlabel)
                $form.Controls.Add($certtextBox)
                $form.Controls.Add($okButton)
  				 
                $form.Add_Shown({ $form.Activate() })
                # Trash the text of the button that was clicked.				
                $form.ShowDialog() > $null
  				 
                # Return the text that the user entered.
                $script:cert_thumbprint = $form.Tag
                Log "SetHTTPPorts: User entered certificate thumbprint: `"$script:cert_thumbprint`""
            }  # end of asking for cert thumbprint

        }
        else {
            $script:change_winrm_ports = $false
        }  # end of asking for port numbers

    }
    else {
        # If running silently, see if port numbers changed from originals
        if ($script:change_winrm_ports -eq $false) {
            if (($script:http_port -ne $script:original_http_port) -or ($script:https_port -ne $script:original_https_port) ) {
                Log "SetHTTPPorts: HTTP or HTTPS port change detected, so setting `$script:change_winrm_ports to True"
                $script:change_winrm_ports = $true
            }
            # Or if running silently, an HTTPS listener is not setup, and we see that we found a proper thumbprint
            # then set the change ports flag
            if ($script:cert_thumbprint -ne $null) {
                Log "SetHTTPPorts: Acceptable digital cert found, so setting `$script:change_winrm_ports to True"
                $script:change_winrm_ports = $true
            }
        }
    }

    Log "SetHTTPPorts: Exit"
    return $true
}


# CreateFinalSDDL: take two strings of SDDL and place the insertion string in the Discretionary ACL portion
# of the SDDL and return the final string for use.
Function CreateFinalSDDL([String] $user_sid, [String] $insertion_string, [String] $sddl) {
    $final_sddl = ""
    $sacl = ""
    $dacl = ""
    LogDebug "CreateFinalSDDL: Enter with user SID `"$user_sid`" and SDDL string `"$sddl`""

    # Separate the SACL (System Access Control List) from DACL (Discretionary Access List), and then insert
    # our required SL1 SID ACL at the end of DACL list, putting entire SDDL back together.
    $found_sacl = $false
    $remove_existing_acl = $false

    # First ensure the SID for this user is not already in the SDDL - if it is, if it is not what we are setting, remove it, so we 
    # can reset the ACL for the user to what we need
    if ($sddl -Like "*$user_sid*") {
        if ($sddl -Like "*$insertion_string*") {
            LogDebug "CreateFinalSDDL: ** Not inserting the new ACL for the account into the existing SDDL as it already exists there."
            return $final_sddl
        }
        else {
            # User/Group SID found in SDDL already but not identical, so we need to parse it from the DACL and reinsert it
            LogDebug "CreateFinalSDDL: User/group SID found in SDDL but it is not identical, so we will replace with ACL for SL1."
            $remove_existing_acl = $true
        }
    }

    # Split the existing SDDL string into a maximum of 2 strings, preserving the S:
    foreach ($sddl_part in ($sddl -split '(S:)', 2)) {
        if ($sddl_part -eq 'S:') {
            $found_sacl = $true
        }
        if ($found_sacl) {
            # Append remaining parts to SACL string
            $sacl += $sddl_part
        }
        else {
            # Append to DACL string
            $dacl += $sddl_part
        }
    }

    LogDebug "CreateFinalSDDL: DACL string after parsing on Discretionary/System = `"$dacl`""
    LogDebug "CreateFinalSDDL: SACL string after parsing on Discretionary/System = `"$sacl`""

    # Remove section with user/group SID if found earlier - not doing so results in access denied error
    if ($remove_existing_acl) {
        $found = $dacl -match "A;;\w+;;;$user_sid"
        if ($found) {
            if (($Matches[0] -ne $null) -and ($Matches[0].Length -gt 0)) {
                # Making sure we matched on expected string and that it starts with a left paren, then 'A' for Allow
                # since this is going to be a replaced string
                $replacement = $Matches[0]
                $replacement = $replacement.TrimStart('(')
                $replacement = $replacement.TrimEnd(')')
                LogDebug "CreateFinalSDDL: Replacing existing DACL substring `"$replacement`" with updated string of `"$insertion_string`""
                $output = $dacl -replace $replacement, $insertion_string
                LogDebug "CreateFinalSDDL: Final DACL `"$output`""

                # Since we replaced a substring in the dacl, just concatenate dacl and sacl
                $final_sddl = $output + $sacl
            }
        }
        else {
            # No need to replace anything - should not get into this block
            LogDebug "CreateFinalSDDL: ACL with user SID `"$user_sid`" not found in DACL portion of existing SDDL, so no replacement being made."
        }
    }
    else {
        $final_sddl = $dacl + '(' + $insertion_string + ')' + $sacl
    }

    LogDebug "CreateFinalSDDL: Exit and returning final SDDL `"$final_sddl`""
    return $final_sddl
}

# SetSecurityRegKeyReadPermissionNonAdminAccount
Function SetSecurityRegKeyReadPermission() {
    Log "SetSecurityRegKeyReadPermission: Enter"
    $bSuccess = $true
    # If user is in the Administrators group, no need to proceed here.
    if (IsAccountInAdminGroup($script:account) -eq $true) {
        Log "SetSecurityRegKeyReadPermission: User `"$script:account`" is already in the local Administrators group, so no need to add this user."
        return $bSuccess
    }
    try {
        Log "SetSecurityRegKeyReadPermission: Creating inheritance flag ..."
        $inheritFlag = @([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
        Log "SetSecurityRegKeyReadPermission: Creating propagation flag ..."
        $propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
        $reg_path = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
        Log "SetSecurityRegKeyReadPermission: Obtaining handle to HKLM registry tree: `"$reg_path`" ..."
        $acl = Get-Acl $reg_path
        Log "SetSecurityRegKeyReadPermission: Creating read rule for account: `"$script:account`" ..."
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($script:account, "ReadPermissions, ReadKey", $inheritFlag, $propagationFlag, "Allow")
        Log "SetSecurityRegKeyReadPermission: Setting rule for Security registry Key."
        $acl.SetAccessRule($rule)
        $acl | Set-Acl -Path $reg_path
        Log "SetSecurityRegKeyReadPermission: Exit"
    }
    catch {
        Log "SetSecurityRegKeyReadPermission: Exception caught while adding account to Security register key - detail - $_"
        $bSuccess = $false
    }
    return $bSuccess
}

# SetServicePermissions
Function SetServicePermissions() {
    $bSuccess = $true
    $sddl = $null
    $final_sddl = $null
    Log "SetServicePermissions: Enter"

    # If user is in the Administrators group, no need to proceed here.
    if (IsAccountInAdminGroup($script:account) -eq $true) {
        Log "SetServicePermissions: User `"$script:account`" is already in the local Administrators group, so no need to add this user."
        return $bSuccess
    }

    # Set SDDL snippet we want to on SCMANAGER and each service
    # Grants SERVICE_QUERY_CONFIG (CC), SERVICE_QUERY_STATUS (LC), READ_CONTROL (RC),
    # and SERVICE_START (RP), SERVICE_ENUMERATE_DEPENDENTS(SW), SERVICE_INTERROGATE(LO)
    $sddl_insertion_scm = "A;;CCLCSWLORPRC;;;$script:account_sid"
    $sddl_insertion_svc = "A;;CCLCSWLORPRC;;;$script:account_sid"

    # HKLM\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder\Security holds these updates

    # (1) Get SDDL for SCMANAGER and insert permission for SL1 credential user specified
    LogDebug "SetServicePermissions: Running `"sc.exe sdshow SCMANAGER`" to get SDDL for services control manager."
    $scm_sddl = Invoke-Command -ScriptBlock { sc.exe sdshow SCMANAGER }
    if (($scm_sddl -ne $null) -and ($scm_sddl.Length -gt 0)) {
        $output = $null
        $scm_sddl = $scm_sddl.Trim()
        LogDebug "SetServicePermissions: -- SDDL for SCMANAGER returned is: `"$scm_sddl`""
        SaveOriginal "SDDL (SCMANAGER)" $scm_sddl
        $final_sddl = CreateFinalSDDL $script:account_sid $sddl_insertion_scm $scm_sddl
        if (($final_sddl -ne $null) -and ($final_sddl.Length -gt 0)) {
            # Set the SDDL in SCMANAGER
            LogDebug "SetServicePermissions: -- Calling sc.exe sdset SCMANAGER to set new SDDL to `"$final_sddl`""
            $output = Invoke-Command -ScriptBlock { sc.exe sdset SCMANAGER $final_sddl } -ErrorAction SilentlyContinue
            if (($output -ne $null) -and ($output.Length -gt 0)) {
                Log "SetServicePermissions: -- Setting permissions on SCMANAGER returned: `"$output`""
            }
            else {
                Log "SetServicePermissions: -- Nothing returned by sc.exe sdset SCMANAGER."
            }

            # We can add later another call to 'sdshow SCMANAGER' to see if updated SDDL was saved properly - the output will typically
            # set us from sdset
        }
        else {
            Log "SetServicePermissions: -- Warning - no final SDDL string was returned for setting in service permissions - this may be fine if the ACL already exists."
        }

    }
    else {
        Log "SetServicePermissions: -- Error: unable to get the existing SDDL set for SCMANAGER, so cannot provide permissions to SL1 credential user"
        $bSuccess = $false
    }

    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "SetServicePermissions: After fetching SDDL for SCMANAGER, most recent error => $error_string"
    }
    $error.clear()



    # (2) Get SDDL for every Windows service and insert permission for SL1 credential user specified
    $service_list = Get-Service
    foreach ($service in $service_list) {
        $service = $service.ToString()
        LogDebug "SetServicePermissions: -- Getting SDDL for service `"$service`""
        $scm_sddl = Invoke-Command -ScriptBlock { sc.exe sdshow $service }
        if (($scm_sddl -ne $null) -and ($scm_sddl.Length -gt 0)) {
            $output = $null
            $scm_sddl = $scm_sddl.Trim()
            LogDebug "SetServicePermissions: -- SDDL for this service returned is: `"$scm_sddl`""
            SaveOriginal "SDDL ($service)" $scm_sddl
            $final_sddl = CreateFinalSDDL $script:account_sid $sddl_insertion_svc $scm_sddl
            if (($final_sddl -ne $null) -and ($final_sddl.Length -gt 0)) {
                # Set the SDDL in SCMANAGER
                Log "SetServicePermissions:--  Calling `"sc.exe sdset $service`" to set new SDDL to `"$final_sddl`""
                $output = Invoke-Command -ScriptBlock { sc.exe sdset $service $final_sddl } -ErrorAction SilentlyContinue
                if (($output -ne $null) -and ($output.Length -gt 0)) {
                    Log "SetServicePermissions: -- Setting permissions on service `"$service`" returned: `"$output`""
                }
                else {
                    Log "SetServicePermissions: -- Nothing returned by sc.exe sdset for this service. "
                }
                # We can add later another call to 'sdshow $service' to see if updated SDDL was saved properly - the output will typically
                # set us from sdset
            }
            else {
                Log "SetServicePermissions: -- Warning - no final SDDL string was returned for setting in service permissions - this may be fine if the ACL already exists."
            }
        }
        else {
            Log "SetServicePermissions: -- Error - unable to get the existing SDDL set for service `"$service`" so cannot provide permissions to SL1 credential user"
            $bSuccess = $false
        }

        if ($error.count -gt 0) {
            $error_string = $error[0].ToString()
            Log "SetServicePermissions: After fetching SDDL for every service and updating it, most recent error => $error_string"
        }
        $error.clear()

    }  # end foreach service

    Log "SetServicePermissions: Exit"
    return $bSuccess
}


# SetRegistryPermissions
Function SetRegistryPermissions() {
    Log "SetRegistryPermissions: Enter"
    $bSuccess = $true
    $acct_sid = $null
    $new_rule = $null
    $32BIT_MS_KEY = "SOFTWARE\Wow6432Node\Microsoft"
    $64BIT_MS_KEY = "SOFTWARE\Microsoft"
    $registry_trees = @($32BIT_MS_KEY, $64BIT_MS_KEY)

    # If user is in the Administrators group, no need to proceed here.
    if (IsAccountInAdminGroup($script:account) -eq $true) {
        Log "SetRegistryPermissions: User `"$script:account`" is already in the local Administrators group, so no need to add this user."
        return $bSuccess
    }

    try {
        # Get .Net object representation of user SID
        Log "SetRegistryPermissions: Getting object translation of user SID ..."
        $acct_sid = GetAccountSID $script:account $false
        Log "SetRegistryPermissions: Creating RegistrySecurity object and creating RegistryRights variable ..."
        $reg_rights = [System.Security.AccessControl.RegistryRights]"EnumerateSubKeys, ReadKey, QueryValues, ReadPermissions"
        Log "SetRegistryPermissions: Creating inheritance flags ..."
        $iFlag = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
        $pFlag = [System.Security.AccessControl.PropagationFlags]::None
        $access = [System.Security.AccessControl.AccessControlType]::Allow
        Log "SetRegistryPermissions: Creating RegistryAccessRule object with set properties ..."
        $new_rule = New-Object system.Security.AccessControl.RegistryAccessRule($acct_sid, $reg_rights, $iFlag, $pFlag, $access)
    }
    catch {
        Log "SetRegistryPermissions: Exception caught while creating registry access rule - detail - $_"
        $bSuccess = $false
    }

    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "SetRegistryPermissions: After creating new registry access rule, most recent error => $error_string"
    }
    $error.clear()

    if ($new_rule -eq $null) {
        $bSuccess = $false
        Log "SetRegistryPermissions: Error: unable to create new access rule for user, so unable to set registry permissions!"
        return $bSuccess
    }

    # Set permissions for the SL1 user on the Microsoft registry tree - 32-bit and 64-bit
    foreach ($tree in $registry_trees) {
        $reg_handle = $null
        $reg_tree = $tree
        try {
            Log "SetRegistryPermissions: Obtaining handle to HKLM registry tree: `"$reg_tree`" ..."
            $reg_handle = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($reg_tree, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
            if ($reg_handle -ne $null) {
                # Get current ACL for this registry tree
                Log "SetRegistryPermissions: --- Getting current ACL for this registry key ..."
                $acl_regkey = $reg_handle.GetAccessControl()
                Log "SetRegistryPermissions: --- Setting new rule on existing registry key ACL ..."
                $acl_regkey.SetAccessRule($new_rule)
                Log "SetRegistryPermissions: --- Updating access control on this registry key ..."
                $reg_handle.SetAccessControl($acl_regkey)
            }
            else {
                Log "SetRegistryPermissions: Error - unable to open registry key $reg_tree"
            }

            if ($error.count -gt 0) {
                $error_string = $error[0].ToString()
                Log "SetRegistryPermissions: After setting ACL on registry key $reg_tree, most recent error => $error_string"
            }
            $error.clear()

        }
        catch {
            if ($reg_tree -ne $null) {
                Log "SetRegistryPermissions: Exception caught while setting permissions on registry tree $reg_tree - detail - $_"
            }
            else {
                Log "SetRegistryPermissions: Exception caught while setting permissions on registry tree - detail - $_"
            }
            $bSuccess = $false
        }

        if ($reg_handle -ne $null) {
            Log "SetRegistryPermissions: --- Closing handle to this registry key."
            $reg_handle.Close()
            $reg_handle = $null
        }

    }  # end foreach reg tree to process

    Log "SetRegistryPermissions: Exit"
    return $bSuccess
}


# SetWMIPermissions
Function SetWMIPermissions() {
    Log "SetWMIPermissions: Enter"
    $inherit = $true
    $localhost = "."
    $try_alternate = $false
    $permissions = @("Enable", "RemoteAccess", "MethodExecute")

    # Specify the namespace to set permissions 
    $invoke_params = @{Namespace = $script:wmi_namespace_root; Path = "__SystemSecurity=@" }

    try {
        # If user account to be configured is already in Administrators group, this step is not necessary.
        if (IsAccountInAdminGroup($script:account) -eq $true) {
            Log "SetWMIPermissions: User `"$user`" is already in the local Administrators group, so no need to add this user."
            return $true
        }

        Log "SetWMIPermissions: Calling Invoke-WmiMethod -Name GetSecurityDescriptor with parameters: "
        foreach ($invokeparam in $invoke_params.keys) {
            Log "SetWMIPermissions:     `"$($invokeparam)`" => `"$($invoke_params.$invokeparam)`""
        } 

        $output = Invoke-WmiMethod $invoke_params -Name GetSecurityDescriptor -ErrorAction SilentlyContinue
        if ($error.count -gt 0) {
            $error_string = $error[0].ToString()
            Log "SetWMIPermissions: After Invoke-WmiMethod for GetSecurityDescriptor(), most recent error => $error_string"
        }
        $error.clear()

        if (($output -eq $null)) {
            Log "SetWMIPermissions: GetSecurityDescriptor() did not return the user SID, so trying alternate method of retrieving SID."
            $try_alternate = $true
        }
        else {
            $rc = $output.ReturnValue
            Log "SetWMIPermissions: GetSecurityDescriptor() returned ret value $rc"
            if ($rc -ne 0) {
                Log "SetWMIPermissions: GetSecurityDescriptor() call failed, returning $($output.ReturnValue), so trying alternate method of retrieving SID."
                $try_alternate = $true
            }
        } 
    }
    catch {
        Log "SetWMIPermissions: Exception caught while retrieving SID for WMI namespace `"$script:wmi_namespace_root`" - detail - $_"
        $try_alternate = $true
    }

    $security_descriptor = $null
    if ($try_alternate -eq $true) {
        # In some envs, invoke-wmimethod does not behave well, so use this alternative to get the descriptor for this namespace
        Log "SetWMIPermissions: Using an alternate means to find the SID of the `"$script:wmi_namespace_root`" namespace"
        $binarySD = @($null)  
        $result = $(Get-WMIObject -Namespace "root" -Class __SystemSecurity).PsBase.InvokeMethod("GetSD", $binarySD)  
        $converter = New-Object system.management.ManagementClass Win32_SecurityDescriptorHelper 
        $sddl_output = $converter.BinarySDToSDDL($binarySD[0])
        Log "SetWMIPermissions: Alternate method found SID of this namespace as `"$($sddl_output.SDDL)`"" 
        $security_descriptor = ($converter.BinarySDToWin32SD($binarySD[0])).Descriptor
        if ($result -ne 0) {
            Log "SetWMIPermissions: Error - the attempt to convert the byte format security descriptor to a Win32 instance failed with rc = $result" 
        }
        else {
            Log "SetWMIPermissions: Converted byte-format security descriptor to Win32 instance successfully." 
        }

    }
    else {
        # We appear to have gotten the descriptor - assign it for use 
        $security_descriptor = $output.Descriptor
    }

    Log "SetWMIPermissions: Looking at user account `"$script:account`" in relation to computer `"$script:localhost_name`""
    if ($script:account.Contains('\')) {
        $domainaccount = $script:account.Split('\')
        $domain = $domainaccount[0]
        if (($domain -eq ".") -or ($domain -eq "BUILTIN")) {
            $domain = $script:localhost_name
        }
        $accountname = $domainaccount[1]
    }
    elseif ($script:account.Contains('@')) {
        $domainaccount = $script:account.Split('@')
        $domain = $domainaccount[1].Split('.')[0]
        $accountname = $domainaccount[0]
    }
    else {
        $domain = $script:localhost_name
        $accountname = $script:account
    }
 
    Log "SetWMIPermissions: Looking for account with domain `"$domain`" and user `"$accountname`" in Win32_Account"
    $win32account = $null
    $getparams = @{Class = "Win32_Account"; Filter = "Domain='$domain' and Name='$accountname'" }
    $win32account = Get-WmiObject @getparams
    if ($win32account -eq $null) {
        Log "SetWMIPermissions: Warning - Windows account specified was *not* found in a lookup in the Win32_Account WMI class, so we will use SID collected already to set in trustee object"
    }
 
    # Add permissions to WMI security for the user account  specified 
    $OBJECT_INHERIT_ACE_FLAG = 0x1
    $CONTAINER_INHERIT_ACE_FLAG = 0x2
    $accessMask = CreateAclMask($permissions)
    Log "SetWMIPermissions: Creating Win32_ACE instance ..."
    $ace = (New-Object System.Management.ManagementClass("win32_Ace")).CreateInstance()
    $ace.AccessMask = $accessMask
    if ($inherit -eq $true) {
        # Failures occur on some OS versions when object inherit flag was used, and it is not typically
        # necessary for setting inheritance of permissions on namespaces
        if ($script:set_wmi_inherit_obj -eq $true) {
            $ace.AceFlags = $OBJECT_INHERIT_ACE_FLAG + $CONTAINER_INHERIT_ACE_FLAG
        }
        else {
            $ace.AceFlags = $CONTAINER_INHERIT_ACE_FLAG
        }
    }
    else {
        $ace.AceFlags = 0
    }
               
    $trustee = (New-Object System.Management.ManagementClass("win32_Trustee")).CreateInstance()
    if ($win32account -eq $null) {
        Log "SetWMIPermissions: Using SID collector at start of script execution."
        $trustee.SidString = $script:account_sid
    }
    else {
        $trustee.SidString = $win32account.Sid
    }
    $ace.Trustee = $trustee
    $ACCESS_ALLOWED_ACE_TYPE = 0x0
    $ACCESS_DENIED_ACE_TYPE = 0x1
    $ace.AceType = $ACCESS_ALLOWED_ACE_TYPE
    $security_descriptor.DACL += $ace.psobject.immediateBaseObject
    try {
        $setparams = @{Name = "SetSecurityDescriptor"; ArgumentList = $security_descriptor.psobject.immediateBaseObject } + $invoke_params
        Log "SetWMIPermissions: Calling SetSecurityDescriptor() to commit WMI permission changes for the account."
        $output = Invoke-WmiMethod @setparams -ErrorAction SilentlyContinue
        if ($error.count -gt 0) {
            $error_string = $error[0].ToString()
            Log "SetWMIPermissions: After Invoke-WmiMethod for SetSecurityDescriptor, most recent error => $error_string"
        }
        $error.clear()

        if (($output -eq $null)) {
            Log "SetWMIPermissions: SetSecurityDescriptor() call failed, returning a NULL object."
        }
        else {
            $rc = $output.ReturnValue
            Log "SetWMIPermissions: SetSecurityDescriptor() returned ret value $rc"
            if ($rc -ne 0) {
                Log "SetWMIPermissions: SetSecurityDescriptor() call failed, returning $($output.ReturnValue), so WMI permissions were not setup properly!"
                $try_alternate = $true
            }
        }
    }
    catch {
        Log "SetWMIPermissions: Error - Exception caught while setting security descriptor for user on the WMI namespace `"$script:wmi_namespace_root`" - detail - $_"
        $try_alternate = $true
    }

    Log "SetWMIPermissions: Exit"
    return $true
}



# SaveWinRMConfiguration
Function SaveWinRMConfiguration() {
    Log "SaveWinRMConfiguration: Enter"

    if ($script:domain_acct -eq $true) {
        $authentication_type = "Kerberos (for Active Directory)"
    }
    else {
        $authentication_type = "Basic Authentication (for local account)"
    }

    if ($script:allow_unencrypted -eq $true) {
        $winrm_traffic = "Allow unencrypted WinRM traffic"
    }
    else {
        $winrm_traffic = "Restrict Unencrypted Data"
    }

    if ($script:cert_thumbprint -eq $null) {
        Log "SaveWinRMConfiguration: No certificate thumbprint was set in a prior check!"
        $certificate = "Not using a certificate thumbprint at this time."
    }
    else {
        Log "SaveWinRMConfiguration: Certificate thumbprint to be used: `"$script:cert_thumbprint`""
        $certificate = $script:cert_thumbprint
    }

    $DIALOG_CONFIRM = "Please confirm your settings:`n`n"
    $DIALOG_CONFIRM += "       Authentication Type: $authentication_type`n"
    $DIALOG_CONFIRM += "       Encryption Policy: $winrm_traffic`n"
    $DIALOG_CONFIRM += "       Maximum Connections: $script:max_winrm_requests`n"

    if ($script:winrm_set_idle) {
        $DIALOG_CONFIRM += "       IdleTimeout: $script:winrm_idle_timeout`n"
    }

    $DIALOG_CONFIRM += "       HTTP Port: $script:http_port`n"
    $DIALOG_CONFIRM += "       HTTPS Port: $script:https_port`n"
    $DIALOG_CONFIRM += "       Certificate Thumbprint: $certificate`n`n"
    $DIALOG_CONFIRM += "Click OK to update WinRM settings.`n"
    $DIALOG_CONFIRM += "Click CANCEL to quit wizard (settings will not be updated).`n"

    # Show user what the changes will be and allow confirmation
    if ($silent -eq $false) {
        $confirm = [System.Windows.Forms.MessageBox]::Show($DIALOG_CONFIRM, "Confirm Settings", $okCancelButtons)
        if ($confirm -ne "OK") {
            Log "SaveWinRMConfiguration: User did not click OK on confirmation settings dialog, so exiting without setting configuration changes."
            return $false
        }
    }

    # Log the most recent error that occurred before clearing
    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "SaveWinRMConfiguration: Last error before adding user to security groups => $error_string"
    }
    $error.clear()


    # Set authentication type based on account type chosen for using as SL1 credential
    if ($script:domain_acct -eq $true) {
        Log "SaveWinRMConfiguration: Setting Kerberos authentication value to True for use of AD user account."
        Set-Item WSMan:\Localhost\Service\Auth\Kerberos -value true -ErrorAction SilentlyContinue
    }
    else {
        Log "SaveWinRMConfiguration: Setting Basic authentication value to True for use of local user account."
        Set-Item WSMan:\Localhost\Service\Auth\Basic -value true -ErrorAction SilentlyContinue
    }

    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "SaveWinRMConfiguration: After setting authentication type, most recent error => $error_string"
    }
    $error.clear()

    # Set the IdleTimeout - should already have been disabled if controller by GPO
    if ($script:winrm_set_idle) {
        Log "SaveWinRMConfiguration: Setting IdleTimeout value to $script:winrm_idle_timeout ,.."
        Set-Item WSMan:\Localhost\Shell\IdleTimeout -value $script:winrm_idle_timeout -ErrorAction SilentlyContinue | Out-Null
    }

    # Set allow unencrypted value if not controlled by GPO
    if (($script:original_allow_unencrypted_source -ne $null) -and ($script:original_allow_unencrypted_source) -eq "GPO") {
        Log "SaveWinRMConfiguration: Not setting AllowUnencrypted value because GPO set the value on this computer."
    }
    else {
        if ($script:allow_unencrypted -eq $true) {
            Log "SaveWinRMConfiguration: Setting AllowUnencrypted value to True ..."
            Set-Item WSMan:\Localhost\Service\AllowUnencrypted -value true -ErrorAction SilentlyContinue | Out-Null
        }
        else {
            Log "SaveWinRMConfiguration: Setting AllowUnencrypted value to False ..."
            Set-Item WSMan:\Localhost\Service\AllowUnencrypted -value false -ErrorAction SilentlyContinue | Out-Null
        }
    }

    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "SaveWinRMConfiguration: After setting AllowUnencrypted value, most recent error => $error_string"
    }
    $error.clear()

    # Set maximum WinRM requests this computer should handle simultaneously
    if ($script:change_max_connections -eq $true) {
        Log "SaveWinRMConfiguration: Setting MaxConnections (simulataneous WMI requests) to $script:max_winrm_requests ..."
        Set-Item WSMan:\Localhost\Service\MaxConnections -value $script:max_winrm_requests | Out-Null
    }

    Function SetItemIfNotGPO($policy, $value) {
        $policy_object = Get-Item $policy
        if ($policy_object.SourceOfValue -eq "GPO") {
            Log "The config setting $($policy_object.Name) cannot be changed because is controlled by policies. The policy would need to be set to `"Not Configured`" in order to change the config setting."
        }
        else {
            Set-Item $policy -value $value | Out-Null
        }
    }

    # Set maximum concurrent operations per user minimum value, if not higher already
    $max_concurrent_operations_per_user = Get-Item WSMan:\Localhost\Service\MaxConcurrentOperationsPerUser | % { $_.Value }
    if ($max_concurrent_operations_per_user -and ($max_concurrent_operations_per_user.Length -gt 0)) {
        Log "CollectCurrentConfig: MaxConcurrentOperationsPerUser is currently set to `"$max_concurrent_operations_per_user`""
        if ($max_concurrent_operations_per_user -lt $DESIRED_MAX_CONCURRENT_OPS_PERUSER) {
            SaveOriginal "WinRM_MaxConcurrentOperationsPerUser" $max_concurrent_operations_per_user
            SetItemIfNotGPO "WSMan:\Localhost\Service\MaxConcurrentOperationsPerUser" $DESIRED_MAX_CONCURRENT_OPS_PERUSER
        }
    }

    # Set maximum concurrent users minimum value, if not higher already
    $max_concurrent_users = Get-Item WSMan:\Localhost\Shell\MaxConcurrentUsers | % { $_.Value }
    if ($max_concurrent_users -and ($max_concurrent_users.Length -gt 0)) {
        Log "CollectCurrentConfig: MaxConcurrentUsers is currently set to `"$max_concurrent_users`""
        if ($max_concurrent_users -lt $DESIRED_MAX_CONCURRENT_USERS) {
            SaveOriginal "WinRM_MaxConcurrentUsers" $max_concurrent_users
            SetItemIfNotGPO "WSMan:\Localhost\Shell\MaxConcurrentUsers" $DESIRED_MAX_CONCURRENT_USERS
        }
    }

    # Set maximum shells per user minimum value, if not higher already
    $max_shells_per_user = Get-Item WSMan:\Localhost\Shell\MaxShellsPerUser | % { $_.Value }
    if ($max_shells_per_user -and ($max_shells_per_user.Length -gt 0)) {
        Log "CollectCurrentConfig: MaxShellsPerUser is currently set to `"$max_shells_per_user`""
        if ($max_shells_per_user -lt $DESIRED_MAX_SHELLS_PERUSER) {
            SaveOriginal "WinRM_MaxShellsPerUser" $max_shells_per_user
            SetItemIfNotGPO "WSMan:\Localhost\Shell\MaxShellsPerUser" $DESIRED_MAX_SHELLS_PERUSER
        }
    }


    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "SaveWinRMConfiguration: After setting MaxConnections value, most recent error => $error_string"
    }
    $error.clear()

    Function GetCNFromSubject([String] $subject) {
        $common_name = $null
        $subject_split = $subject -split ","
        foreach ($i in $subject_split) {
            $i = $i.Trim()
            if ($i.StartsWith("CN=")) {
                $common_name = $i.Substring(3)
                return $common_name
            }
        }
    }

    # Set HTTP and HTTPs ports, and listener(s), if necessary
    if ($script:change_winrm_ports -eq $true) {
        Log "SaveWinRMConfiguration: Configuring http/https WinRM ports and listeners ...."
        try {
            # Get certificate thumbprint to create new port
            # For hostname use in CN, we need to find the proper string in case the cert we are using does not have a Subject populated properly
            # Possible $cert_subjects sample values:
            # CN=TL12R2-SQ-01.MSTL12R2.com
            # CN=TL12R2-SQ-01.MSTL12R2.com, OU=LocalServer, O="Windows 2012, R2", L=Reston, S=Virginia, C=US
            # E=50centostest1@mail.com, CN=TL12R2-SQ-01.MSTL12R2.com, OU=LocalServer, O=`"Windows 2012, R2`", L=Reston, S=Virginia, C=US
            $chosen_thumbprint_cert = ((Get-ChildItem -Path Cert:\LocalMachine\My -EKU "*Server Authentication*") | ? { $_.Thumbprint -match $script:cert_thumbprint })
            $hostname = $null
            if ($chosen_thumbprint_cert -and ($chosen_thumbprint_cert.Length -gt 0)) {
                $subject = $chosen_thumbprint_cert.Subject
                Log "SaveWinRMConfiguration: Returned certificate Subject `"$subject`" from Thumbprint `"$script:cert_thumbprint`""
                $cert_common_name = GetCNFromSubject($subject)
                Log "SaveWinRMConfiguration: CN from certificate subject: `"$cert_common_name`""
                if ($cert_common_name -ne $null -and ($cert_common_name.Length -gt 0)) {
                    if ($cert_common_name -like "*$script:localhost_name*") {
                        $hostname = $cert_common_name
                        Log "SaveWinRMConfiguration: Hostname identified: `"$hostname`""
                    }
                } 
                if ($hostname -eq $null) {
                    Log "SaveWinRMConfiguration: Warning - unable to identify full hostname identifier through Subject properties of existing certificates, so using NetBIOS name!"
                    $hostname = $script:localhost_name
                }
            }
            else {
                Log "SaveWinRMConfiguration: Warning - unable to identify hostname through WMI and certificate paths - using known hostname!"
                $hostname = $script:localhost_name
            }

            # Check to see if a HTTP listener exists and set to proper port if it does - otherwise create a new listener
            if ($script:allow_unencrypted -eq $true) {
                if ($script:http_listener -ne $null) {
       	            # Update the HTTP port
                    Log "SaveWinRMConfiguration: Updating the HTTP port in listener `"$script:http_listener`" to value `"$script:http_port`""
                    Set-Item WSMan:\Localhost\Listener\$script:http_listener\Port -Force $script:http_port | Out-Null
                }
                else {
                    # If there is no HTTP port, create a new one with the HTTP port info collected earlier
                    if ($script:cert_thumbprint -and ($script:cert_thumbprint.Length -gt 0)) {
                        Log "SaveWinRMConfiguration: No HTTP listener exists, so creating a new one for HTTP port $script:http_port and Hostname = $hostname"
                        New-WSManInstance winrm/config/Listener -SelectorSet @{Address = "*"; Transport = "HTTP" } -ValueSet @{Hostname = "$hostname"; CertificateThumbprint = "$script:cert_thumbprint"; Port = "$script:http_port" }
                    }
                    else {
                        Log "SaveWinRMConfiguration: Warning - no HTTP listener exists, but no cert thumbprint was saved, so not configuring a new listener!"
                    }
                }
            }
            else {
                Log "SaveWinRMConfiguration: Not setting up HTTP port and listener, as user chose not to allow unecrypted traffic ..."
            }

        }
        catch {
            $DETAIL_ERROR = "Error configuring WinRM HTTP port and listener. Detail: $_`n`n"
            $DETAIL_ERROR += "Please contact a system administrator to troubleshoot the error."
            Log "SaveWinRMConfiguration: Error - an exception was caught while setting HTTP port and creating a WinRM listener. Detail: $_"
            if (-not $silent) {
                $closure = [System.Windows.Forms.MessageBox]::Show($DETAIL_ERROR, "Error", $script:okButton)
            }
        }

        # NOTE: using separate try...catch for each port type, as setting the HTTPS port might succeed while setting the HTTP port, which 
        # may have been set by GPO, may fail. This situation is acceptable, so we need to try both port settings without exit
        try {
            # Check to see if a HTTPS listener exists
            if ($script:https_listener -ne $null) {
                # Update the HTTPS port
                Log "SaveWinRMConfiguration: Updating the HTTPS port in listener `"$script:https_listener`" to value `"$script:https_port`""
                Set-Item WSMan:\Localhost\Listener\$script:https_listener\Port -Force $script:https_port | Out-Null
            }
            else {
                # If there is no HTTPS port, create a new one with the HTTPS port info collected earlier
                if ($script:cert_thumbprint -and ($script:cert_thumbprint.Length -gt 0)) {
                    Log "SaveWinRMConfiguration: No HTTPS listener exists, so creating a new one for HTTPS port $script:https_port, with certificate thumbprint, for Hostname = $hostname"
                    New-WSManInstance winrm/config/Listener -SelectorSet @{Address = "*"; Transport = "HTTPS" } -ValueSet @{Hostname = "$hostname"; CertificateThumbprint = "$script:cert_thumbprint"; Port = "$script:https_port" }
                }
                else {
                    Log "SaveWinRMConfiguration: Warning - No digital certificate was found on this computer with Server Authentication, so encrypted traffic over Windows Remote Management will not be accepted!"
                }
            }
        }
        catch {
            $DETAIL_ERROR = "Error configuring WinRM HTTPS port and listener. Detail: $_`n`n"
            $DETAIL_ERROR += "Please contact a system administrator to troubleshoot the error."
            Log "SaveWinRMConfiguration: Error - an exception was caught while setting HTTPS ports and creating a WinRM listener, so exiting. Detail: $_"
            Log "SaveWinRMConfiguration: Warning - encrypted traffic over Windows Remote Management will not be accepted to this server!"
            if (-not $silent) {
                $closure = [System.Windows.Forms.MessageBox]::Show($DETAIL_ERROR, "Error", $script:okButton)
                if ($closure -eq $OkClicked) {
                    Log "SaveWinRMConfiguration: User clicked OK on error dialog, exiting."
                }
                exit
            }
        }

    }
    else {
        Log "SaveWinRMConfiguration: Not changing ports (and thus creating any listeners) as no changes to the HTTP/HTTPS ports were detected or chosen by user."
    }

    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "SaveWinRMConfiguration: After setting http/https ports and listener, most recent error => $error_string"
    }
    $error.clear()

    # Show confirmation dialog after settings are completed .... this has not had anything added to it since the script's inception.
    # We should add other config actions taken as an updated here.
    if (-not $silent) {
        Log "SaveWinRMConfiguration: Retrieving final settings of WinRM properties to show to user in confirmation dialog."
        $saved_http_listener = dir WSMan:\Localhost\Listener\* | ? { $_.Keys -like "*HTTP" } | % { $_.Name }
        $saved_https_listener = dir WSMan:\Localhost\Listener\* | ? { $_.Keys -match "HTTPS" } | % { $_.Name }
        $saved_basic_auth = Get-Item WSMan:\Localhost\Service\Auth\Basic | % { $_.Value }
        $saved_kerberos_auth = Get-Item WSMan:\Localhost\Service\Auth\Kerberos | % { $_.Value }
        $saved_allow_unencrypted = Get-Item WSMan:\Localhost\Service\AllowUnencrypted | % { $_.Value }
        $saved_max_connections = Get-Item WSMan:\Localhost\Service\MaxConnections | % { $_.Value }
        $saved_http_port = Get-Item WSMan:\Localhost\Listener\$saved_http_listener\Port | % { $_.Value }
        if ($saved_https_listener) {
            $saved_https_port = Get-Item WSMan:\Localhost\Listener\$saved_https_listener\Port | % { $_.Value }
        }
        else {
            $saved_https_port = "Not Set"
        }

        $DIALOG_CONFIRM = "Your Windows Remote Management settings have been updated. To view "
        $DIALOG_CONFIRM += " them when necessary, you can run the following commands in a PowerShell "
        $DIALOG_CONFIRM += " console: "
        $DIALOG_CONFIRM += " winrm get winrm/config/service "
        $DIALOG_CONFIRM += " winrm e winrm/config/listener`n`n"
        $DIALOG_CONFIRM += " Your updated WinRM settings are detailed below:`n`n"
        $DIALOG_CONFIRM += "                        Basic Authentication = $saved_basic_auth `n"
        $DIALOG_CONFIRM += "                        Kerberos Authentication = $saved_kerberos_auth `n"
        $DIALOG_CONFIRM += "                        Allow Unencrypted WinRM Traffic = $saved_allow_unencrypted `n"
        $DIALOG_CONFIRM += "                        Maximum WinRM Requests = $saved_max_connections `n"

        if ($script:winrm_set_idle) {
            $DIALOG_CONFIRM += "                        WinRM IdleTimeout = $script:winrm_idle_timeout `n"
        }

        $DIALOG_CONFIRM += "                        HTTP Port = $saved_http_port `n"
        $DIALOG_CONFIRM += "                        HTTPS Port = $saved_https_port `n"
        $DIALOG_CONFIRM += "                        Certificate Thumbprint = $script:cert_thumbprint `n`n"
        $DIALOG_CONFIRM += "The WinRM service will be restarted after this dialog is closed."

        $result = [System.Windows.Forms.MessageBox]::Show($DIALOG_CONFIRM, "Complete", $okCancelButtons)

    }  # end not silent and showing confirmation


    Log "SaveWinRMConfiguration: Exit"
    return $true
}


# FinishCleanup
Function FinishCleanup() {
    Log "FinishCleanup: Enter"

    try {
        # Restart WinRM service
        Log "FinishCleanup: Restarting the Windows Remote Management service ..."
        $output = Invoke-Command -ScriptBlock { Restart-Service WinRM -Force -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue
        if ( ($output -ne $null) -and ($output.Length -gt 0)) {
            Log "FinishCleanup: Restart-Service WinRM returned: $output"
        }
    }
    catch {
        Log "FinishCleanup: Exception caught while attempting to restart the WinRM service. Detail: $_"
    }

    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "FinishCleanup: After running Set-ExecutionPolicy command, most recent error => $error_string"
    }
    $error.clear()

    try {
        # Restart WMI service
        Log "FinishCleanup: Restarting the Windows Management Instrumentation (WMI) service ..."
        $output = Invoke-Command -ScriptBlock { Get-Service WinMgmt | ForEach-Object { Restart-Service WinMgmt -Force -PassThru -ErrorAction SilentlyContinue; $_.DependentServices | Where-Object { $_.StartType -eq 'Automatic' -and $_.State -ne 'Running' } | Start-Service -PassThru -ErrorAction SilentlyContinue } | Select Name, DisplayName, Status | fl } -ErrorAction SilentlyContinue
        if ( ($output -ne $null) -and ($output.Length -gt 0)) {
            Log "FinishCleanup: Restart-Service WinMgmt returned: $output"
        }
    }
    catch {
        Log "FinishCleanup: Exception caught while attempting to restart the WinMgmt service. Detail: $_"
    }

    if ($error.count -gt 0) {
        $error_string = $error[0].ToString()
        Log "FinishCleanup: After running Set-ExecutionPolicy command, most recent error => $error_string"
    }
    $error.clear()

    Log "FinishCleanup: Exit"
}



# #############################################################################
#
# Notes: Useful commands to perform these steps manully
#
# ENABLE BASIC AUTHENTICATION
# winrm set winrm/config/service/auth @{Basic="true"}
#
# ALLOW UNENCRYPTED DATA
# winrm set winrm/config/service @{AllowUnencrypted="true"}
#
# CHANGE HTTP PORT
# winrm create winrm/config/listener?Address=*+Transport=HTTP @{Port="8888"}
#
# CHANGE HTTPS PORT
# winrm create winrm/config/listener?Address=*+Transport=HTTPS @{Port="8888"}
#
# GET HTTP/HTTPS LISTENERS
# winrm e winrm/config/listener
#
# GET CERTIFICATE THUMBPRINT
# Get-ChildItem -Path Cert:\LocalMachine\My -EKU "*Server Authentication*"
#
# #############################################################################


# Main script execution - read in command-line arguments

# Construct file path to save original settings found on computer
$script:original_settings_path = ""
$script:original_settings_file = "silo_winrm_original_settings.log"

# Setup logging to a file location on the Windows computer
$logfile_name = "silo_winrm_config.log"   # Default logfile name if no override from command-line
$temp_path = (Get-ChildItem Env:TEMP).Value
if ($temp_path -eq $null) {
    $temp_path = (Get-ChildItem Env:TMP).Value
}
if ($temp_path -eq $null) {
    $temp_path = "."
}
$temp_path = $temp_path.TrimEnd("\")
if ($stdout) {
    Write-Host "`n`nMain: Temp path = `"$temp_path`""
}
if ($temp_path.Length -gt 0) {
    $script:original_settings_path = join-path $temp_path $script:original_settings_file
}
# Use user path and filename if specified on command-line for logging
$script:log_filepath = $log_path
if (($script:log_filepath -eq $null) -or ($script:log_filepath.Length -eq 0)) {
    $script:log_filepath = join-path $temp_path $logfile_name
    if ($stdout) {
        Write-Host "Main: Log output will be written to: `"$script:log_filepath`"`n"
    }
}
else {
    if ($stdout) {
        Write-Host "Main: User entered a log path of: `"$script:log_filepath`" `n"
    }
}

Log ""
Log "Main: Starting execution of winrm_configuration_wizard.ps1"
Log "Main: Original configuration settings will be saved to file: `"$script:original_settings_path"


# Script variables - values are passed in or later set through dialog entry
$script:major_ps_ver = 1
$script:max_winrm_requests = $max_requests
$script:set_wmi_inherit_obj = $false
$script:change_max_connections = $true
$script:allow_unencrypted = $unencrypted
$script:target_computer = $server
$script:account = $null       
$script:account_user = $null
$script:account_domain = $null
$script:domain_acct = $false  # helper for identifying local versus Active Directory domain account
$script:account_sid = $null
$script:http_port = $http_port
$script:http_listener = $null
$script:https_port = $https_port
$script:https_listener = $null
$script:cert_thumbprint = $null
$script:change_winrm_ports = $false
$script:is_user_an_admin = $false
$script:localhost_name = ""
$script:winrm_idle_timeout = ($idle_timeout * 1000)
$script:winrm_set_idle = $true

if ($silent -and !$set_timeout) {
    # If in silent mode, only enable setting the timeout if the set_timeout switch was specified
    $script:winrm_set_idle = $false
}

# User/silo_user flag is not required, but some aspects of the configuration cannot be performed, so those
# will be skipped when an account is not specified (even if run interactively)
if ($user) {
    $script:account = $user.Trim()
    if ($user -match "\\") {
        Log "Main: Domain user account specified for configuration: `"$script:account`""
        $script:domain_acct = $true
        $domain_account = $script:account.Split('\')
        $script:account_domain = $domain_account[0]
        $script:account_user = $domain_account[1]
    }
    else {
        Log "Main: Local user account specified for configuration: `"$script:account`""
        $script:account_domain = $null
        $script:account_user = $script:account
    }

    # Get the user account SID for setting security for this user
    # Future: allow AD group names to be specified instead of just users - ensure group SID can be used where user account settings are
    $script:account_sid = GetAccountSID $script:account $true
    if ($script:account_sid -eq $null) {
        Log "Main: Warning - unable to find SID for the specified user, so some security cannot be set!"
        Write-Host "Error - unable to retrieve the security ID for user `"$script:account`", so the script cannot continue!"
        exit
    }
    else {
        Log "Main: User SID retrieved is `"$script:account_sid`""
    }
}
else {
    # Only allow the script to be run without user specification under certain set of conditions
    if ($silent -and $winrm_only) {
        # Interactive execution does not require a user account
        Log "Main: Important  - `"User`" was not specified on the command-line, but `$winrm_only flag set, so that is allowed."
    }
    else {
        # Error
        Log "Main: Important  - `"User`" was not specified on the command-line, so exiting with an error as this is required!"
        Write-Host "Error - a user account for configuration must be specified unless setting up Windows Remote Management only!!"
        exit
    }
}


# Determine what functions to perform, based on command-line args
$do_enablepsremoting = $false
$do_winrm_config = $false
$do_cluster_setup = $false
$do_sql_config = $false
$do_get_auth_traffic = $false
$do_get_certs_and_ports = $false
$do_set_svc_security = $false
$do_reg_security = $false
$do_wmi_config = $false
$do_user_group_addition = $false

if ($services_only -ne $false) {
    # Do just service permissions
    $do_set_svc_security = $true
}
elseif ($winrm_only -ne $false) {
    # Do basic winrm config
    $do_winrm_config = $true
}
elseif ($cluster_only -ne $false) {
    # Do cluster security config
    $do_cluster_setup = $true
}
elseif ($sql_only -ne $false) {
    # Set permissions in SQL Server
    # instances
    $do_sql_config = $true
}
elseif ($wmi_only -ne $false) {
    # Do WMI config only - if we find setting object inherit flag fails
    # during normal WMI config, user can run with wmi_only set
    # to propagate WMI settings to container objects only
    $do_wmi_config = $true
}
elseif ($skip_services -ne $false) { 
    # Do everything other than services 
    $do_winrm_config = $true
    $do_cluster_setup = $true
    $do_get_auth_traffic = $true
    $do_get_certs_and_ports = $true
    $do_user_group_addition = $true
    if ($skip_wmi -eq $false) {
        $do_wmi_config = $true
    }
}
elseif ($skip_wmi -ne $false) { 
    # Do everything but WMI config
    $do_winrm_config = $true
    $do_cluster_setup = $true
    $do_get_auth_traffic = $true
    $do_get_certs_and_ports = $true
    $do_reg_security = $true
    $do_user_group_addition = $true
    if ($skip_services -eq $false) {
        $do_set_svc_security = $true
    }
}
else {
    # Do everything - winrm config will only open up 
    # listener for encrypted traffic unless unencrypted
    # is explicitly passed on command-line
    $do_winrm_config = $true
    $do_cluster_setup = $true
    $do_get_auth_traffic = $true
    $do_get_certs_and_ports = $true
    $do_set_svc_security = $true
    $do_reg_security = $true
    $do_wmi_config = $true
    $do_user_group_addition = $true
}

# Load Windows Forms for UI, if not running silently
if ($silent -eq $false) {
    Log "Main: User is running the utility interactively - loading System.Windows.Forms for dialogs."
    try {
        $forms_assembly = [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    }
    catch {
        Log "Main: Exception caught while loading Windows.Forms .Net class - detail - $_"
    }
}

# Original settings found on the computer stored in these script variables
$script:original_basic_auth_enabled = $false        # variable for saving original Basic authentication value on the computer
$script:original_kerberos_auth_enabled = $false  # variable for saving original Kerberos authentication value on the computer
$script:original_allow_unencrypted = $false  # variable for saving original AllowUnecrypted WinRM traffic value on the computer
$script:original_allow_unencrypted_source = $null # variable for setting use of unencrypted data - if GPO we do not set this value in commit
$script:original_http_port = ""   # variable for saving original HTTP listener port found
$script:original_https_port = ""  # variable for saving original HTTPS listener port found
$script:original_http_listener = $null # variable for name of original http listener, if found 
$script:original_https_listener = $null # variable for name of original https listener, if found
$script:original_max_requests = 500 # Number of maximum WinRM requests allowed at one time to the server
$script:wmi_namespace_root = "root"  # top of WMI namespace tree necessary to have read/execute permissions on for monitoring
$script:computer_name = $Env:ComputerName.ToUpper()  # Hostname, in all caps


# Other script constants
$script:error_summary = $null
$yesNoButtons = 4
$okCancelButtons = 1
$script:okButton = 0
$OkClicked = "OK"
$DEFAULT_WINRM_HTTP_PORT = "5985"
$DEFAULT_WINRM_HTTPS_PORT = "5986"
$DESIRED_MAX_CONCURRENT_OPS_PERUSER = 200
$DESIRED_MAX_CONCURRENT_USERS = 40
$DESIRED_MAX_SHELLS_PERUSER = 50

# Some permission bitmasks
$GENERIC_READ = 0x80000000
$GENERIC_WRITE = 0x40000000
$GENERIC_EXECUTE = 0x20000000
$GENERIC_ALL = 0x10000000

# String constants
$NOT_ADMIN = "You do not have Administrator rights for successful use of this utility. Please run this script as an Administrator."

# Retrieve current WinRM and other configuration values and save them to file
try {
    $ret_code = $false

    # Ensure user is running this utility as an Administrator
    $IsAdmin = IsRunByAdmin
    if ($IsAdmin -eq $false) {
        if ($silent -eq $false) {
            [System.Windows.Forms.MessageBox]::Show($NOT_ADMIN, "Error", $script:okButton)
        }
        Log "Main: Error - This script is not being run with Administrator privileges, so exiting."
        exit
    }

    # Get computer name
    $script:localhost_name = (Get-WmiObject Win32_ComputerSystem).Name
    Log "Main: Hostname is `"$script:localhost_name`""

    # Retrieve current configuration settings to save
    Log "Main: Retrieving current security settings to save for reversion, if necessary"
    $ret_code = CollectCurrentConfig

    # Ensure PowerShell version desired, from command-line or by default, is installed and exit if it is not
    Log "Main: Checking Windows PowerShell version present against version $ps_version (ps_version command-line argument or default value of 1)"
    $script:major_ps_ver = $script:major_ps_ver / 1   # Ensure this is an integer before using in comparison - PS ensures this after division
    if ($script:major_ps_ver -ge $ps_version) {
        Log "Main: Windows PowerShell is version $script:major_ps_ver, and only $ps_version is requested as the minimum for configuration, so continuing."
    }
    else {
        Log "Main: Error - Windows PowerShell is version $script:major_ps_ver, less than the required version of $ps_version, so exiting!"
        Write-Host "Error - Windows PowerShell is version $script:major_ps_ver, less than the required version of $ps_version, so exiting!"
        exit
    }

    # Set permissions for reading Windows cluster info on the local server
    if ($do_cluster_setup) {
        if ($script:account -ne $null) {
            Log "Main: Calling ConfigureClusterSecurity() to ensure SL1 credential can read cluster information..."
            $ret_code = ConfigureClusterSecurity
        }
        else {
            Log "Main: Warning - no user account has been set, so unable to grant cluster read-only permissions!"
        }
    }

    # Set permissions inside Microsoft SQL Server instances installed on this local computer. For now, this is a global
    # update. The ability to specify a specific instance or database is not available yet.
    if ($do_sql_config) {
        if ($script:account -ne $null) {
            Log "Main: Calling GrantUserSQLServerPermissions() to allow account to read Microsoft SQL Server instance/database information ..."
            $ret_code = GrantUserSQLServerPermissions
        }
        else {
            Log "Main: Warning - no user account has been set, so unable to grant read permissons to SQL Server instances/databases!"
        }
    }

    # Enable PS remoting capability on the computer
    if ($do_enablepsremoting -or $do_winrm_config) {
        Log "Main: Calling EnablePSRemoting() to ensure computer has the ability to receive remote PowerShell commands."
        $ret_code = EnablePSRemoting
    }

    # Quick config winrm settings
    if ($do_winrm_config) {
        Log "Main: Configuring WinRM with default settings ..."
        $ret_code = ConfigureWinRM
    }

    # Set authentication choice and number of max requests device can accept
    if ($do_get_auth_traffic) {
        Log "Main: Get the account type for SL1 user, encryption choice, and max connections (requests) properties"
        $ret_code = SetAuthenticationType
    }

    # Find digital certificate and set port info for WinRM traffic based on user choice
    if ($do_get_certs_and_ports) {
        Log "Main: Get digital cert thumbprint and set HTTP/HTTPS port choices"
        $ret_code = SetHTTPPorts
    }

    # Set WMI permission for the user account specified
    if ($do_wmi_config) {
        if ($script:account -ne $null) {
            Log "Main: Setting WMI permissions ..."
            $ret_code = SetWMIPermissions
        }
        else {
            Log "Main: Warning - no user account has been set, so unable to set WMI permissions."
        }
    }

    # Add user to required security groups for SL1 monitoring
    if ($do_user_group_addition) {
        if ($script:account -ne $null) {
            Log "Main: Adding user account to local groups required for SL1 monitoring"
            $ret_code = AddUserToGroups($script:account)
            if ($ret_code -eq $false) {
                Log "Main: At least one failure occurred adding the user to the required security groups!!"
            }
        }
        else {
            Log "Main: ** Not adding user account to necessary security groups as no user account was specified **"
        }
    }

    # Set permissions on services if user specified to and included an account
    if ($do_set_svc_security) {
        if ($script:account_sid -ne $null) {
            Log "Main: Setting permission on Windows services ..."
            $ret_code = SetServicePermissions
        }
    }

    # Set permissions on Microsoft registry key for the SL1 credential user
    if ($do_reg_security) {
        if ($script:account_sid -ne $null) {
            Log "Main: Setting permissions on the 32-bit/64-bit Microsoft registry subkey tree ..."
            $ret_code = SetRegistryPermissions
        }
    }

    # Set permissions on EventLog registry key for the SL1 credential user group for non admin accounts
    if ($do_reg_security) {
        if ($script:account -ne $null) {
            Log "Main: Setting permissions on the EventLog registry subkey tree ..."
            $ret_code = SetSecurityRegKeyReadPermission
        }
    }

    # Complete WinRM settings
    if ($do_winrm_config) {
        Log "Main: Committing/saving WinRM configuration choices ..."
        $ret_code = SaveWinRMConfiguration
    }

    # Finish up 
    if ($do_sql_config -ne $true) {
        Log "Main: Finishing and cleaning up ..."
        FinishCleanup
    }

    # Write error and warning summary to end of std output
    # and log file
    if ($script:error_summary -ne $null) {
        Log "****************************************************************************`n`n"
        Log "List of errors and warnings encountered during execution: `n"
        Log "$($script:error_summary)`n`n"
        Log "****************************************************************************`n`n"
    }

    Log "Main: Configuration has completed. Exiting ....`r`n`r`n`r`n`r`n`r`n`r`n`r`n"

}
catch {
    Log "Main: Exception caught while executing - detail - $_ `r`n`r`n`r`n`r`n`r`n`r`n`r`n"
}