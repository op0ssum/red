# Using the OSQL Command Line Tool to Perform SQL Server Operations
Applies To: Express Software Manager version 7.x and above

## Summary
If you do not have a version of Microsoft SQL Server that includes an interactive management
application such as SQL Enterprise Manager or SQL Studio, you can still perform maintenance tasks
such as backup and restore, on your Express database using OSQL, the command line SQL tool. This
technical note describes how to perform such tasks using OSQL.

## Using OSQL with the Express Database
### Basic OSQL syntax
OSQL is a command line tool that allows you to issue commands to Microsoft SQL Server. To run
OSQL, simply bring up a DOS box and type OSQL followed by any required switches. You can view
the complete OSQL command syntax with:

```
OSQL -?
```

This technical note describes only those switches required to perform the operations included in the
note. Note: OSQL switches are case-sensitive. Switches:

* `-S <sql-server-name>` - the name of the SQL Server, including instance, if applicable. You may
use "." (without quotes) if you are running OSQL on the same machine as SQL Server.
* `-d <database-name>' - the name of the database on which the operation is to be performed. For
example `-d ExpressDB`.
* `-U <user-name>` - the SQL Server user account under which to run the specified command.
* `-P <password>` - the password associated with the specified user account.
* `-E` - use NT authentication to interact with SQL Server
* `-Q "<SQL-command>"` - the command to issue to SQL Server.
* `-i <file-of-SQL-commands>` - a file containing one or more commands to issue to SQL Server.

OSQL can also operate interactively. If you specify only the server, database, user name, and
password, you will be presented with a prompt allowing you to enter and execute commands one at a
time. The command exit exists interactive mode.

The examples below using the following sample values for the switch parameters described above:

* Database: `ExpressDB`
* SQL Server: `.\ESM` - that is, the ESM instance of SQL Server on the current machine
* User: `sa` - the SQL Server administrative account
* Password: `mysapwd` - the password associated with the sa account

**Important notes**

1. The operations described in this technical note require SQL Server administrative privileges.
This means you must either use the SQL Server sa account, another administrative-capable
account, or be logged into Windows under an account that has SQL Server administrative
rights.

2. SQL commands are issued in the context of the machine running SQL Server. If you use
OSQL on one machine to issue commands to SQL Server on a different machine, any file/path
information specified must be in the context of the SQL Server machine, not your local
machine.

## Backing up your Express Database
Backups of your Express Database should be done on a regular basis. To create a backup using
OSQL, use the following command:

```
OSQL -S <sql-server-name> -U <user-name> -P <password> _
-Q "BACKUP DATABASE <database-name> to disk = '<path>\<database-name>.bak' WITH
INIT"
```

For example, using the sample parameters above and creating the backup file in the `\sqlbackups`
folder on your `C:` drive, the command would be:

```
OSQL -S .\ESM -U sa -P mysapwd -Q "BACKUP DATABASE ExpressDB to disk =
'c:\sqlbackups\ExpressDB.bak'"
```

**Important note**

You can write the backup to a local folder or network share, however in either case, the account
under which SQL Server is running must have write access to the folder in which the backup file is
written.

## Restoring an Express Database
If you need to restore your Express Database from a backup, you can use the following OSQL
command:

```
OSQL -S <sql-server-name> -U <user-name> -P <password> _
-Q"RESTORE DATABASE <database-name> FROM DISK = '<backup-file-path>\<databasename>.bak'
WITH MOVE '<database-name>' TO '<new-data-file-path>\<database-name>.mdf',
MOVE '<database-name>_Log' TO '<new-data-file-path>\<database-name>_Log.ldf'"
```

Notice that when restoring a database, you specify where the backup file exists as well as where SQL
Server will actually create the database files (`.mdf`, `.ldf`) when restoring. For example, using the
sample parameters above, restoring a database backup found in the `\sqlbackups` folder on your `C:``
drive, and creating the new database files in C:\Program Files\Microsoft SQL
Server\MSSQL.1\MSSQL\Data` (the data folder for a typical instance of SQL Server 2005):

```
OSQL -S .\ESM -U sa -P mysapwd -Q "RESTORE DATABASE ExpressDB FROM DISK =
'c:\sqlbackups\ExpressDB.bak' WITH MOVE 'ExpressDB' TO 'C:\Program Files\Microsoft
SQL Server\MSSQL.1\MSSQL\Data\ExpressDB.mdf', MOVE 'ExpressDB_Log' TO
'C:\Program Files\Microsoft SQL Server\MSSQL.1\MSSQL\Data\ExpressDB_Log.ldf'"
```

**Important notes**

1. You can specify that the backup file come from a network share, however, the account under
which SQL Server is running, must have access to the share.

2. The account under which SQL Server is running must also have write access to wherever the
database files (`.mdf`, `.ldf`) are created.

3. If you are moving a database from one machine to another (or from one SQL Server instance
to another), you will need to recreate the Express account used by Express Software Manager
to access the data. (Even if the target SQL Server already has an Express account, you may
need to "bind" it to the account information restored from the backup.) Included with the
database and database tools components of your Express Software Manager installation is a
batch file, InitializeExpressUser.bat which facilitates the creation (if necessary) and binding
of the Express account. From a DOS prompt, you can run `InitializeExpressUser.bat` without
parameters to view its syntax.
