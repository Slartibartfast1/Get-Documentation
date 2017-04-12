# Get-Documentation

Created by Mark Durham

v1 - 12/04/2017

PowerShell module that will create a .txt file for each server within a specified OU (and child OUs) containing configuration details of that server.

Including:
- Make and model
- CPU
- RAM
- Domain
- OU
- AD Groups
- Storage
- Installed Applications

Prerequisites:
- Windows Management Instrumentation (WMI-In) firewall rule enabled
- File and Printer Sharing (Echo Request - ICMPv4-In) firewall rule enabled
- WinRM configured

AD Attributes used:
- OperatingSystem
- MemberOf
- Description
- CanonicalName
- DistinguishedName
