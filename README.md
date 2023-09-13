# winprivX

# WinPrivX: Windows Privilege Escalation and Information Gathering Tool

WinPrivX is a tool used to perform privilege escalation and system information gathering operations on the Windows operating system. By using the commands listed below, you can gather more information about the system and potentially gain access to the required privileges:

- **systeminfo:** Obtain detailed information about the system.
- **ver:** View the operating system version.
- **hostname:** Retrieve the host name.
- **whoami:** Get the current username and group information.
- **net user** and **net localgroup administrators:** Retrieve user and administrator group information.
- **wmic useraccount:** List user accounts.
- **ipconfig /all**, **arp -a**, **netstat -ano**, and **route print:** Gather network information.
- **tasklist /v** or **tasklist:** List running processes and applications.
- **findstr /si password *.txt**, **findstr /si password *.ini**, and **findstr /si password *.xml:** Search for files containing passwords.
- **sc query windefend:** Obtain information about the Windows Defender service.
- **cmdkey /list:** List stored credentials.
- **icacls "C:"**, **icacls "C:" /T**, and **icacls C:\path\to\directory /T /C | findstr /i "(OI)(CI)(M)": Check file and folder permissions.
- **wmic qfe list:** View installed updates.

WinPrivX should be used for the purpose of system analysis and identifying potential security vulnerabilities. Please use it on legal and authorized systems. Adhere to relevant legal regulations and rules.
