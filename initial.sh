sudo echo "kali    ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
echo "[+] made kali password-free sudoer"
sudo echo "CustomLog /var/log/apache2/access.log combined" >> /etc/apache2/apache2.conf
sudo service apache2 restart
echo "[+] enabled apache logging - read logs with:\nsudo tail -f /var/log/apache2/access.log"
sudo apt install samba
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.old
cat <<EOF >>/etc/samba/smb.conf
[visualstudio]
path = /home/kali/data
browseable = yes
read only = no
EOF
echo "[+] smbd and nmbd setup set - enter \"kali\" in next prompt:"
sudo smbpasswd -a kali
sudo systemctl start smbd
sudo systemctl start nmbd
echo "[+] smbd and nmbd started"
mkdir /home/kali/data
chmod -R 777 /home/kali/data
echo "[+] /home/kali/data created for visualstudio projects"
sudo chown -R kali:kali /var/www/html
echo "[+] normalized /var/www/html ownership"
sudo chown -R kali:kali /opt
echo "[+] normalized /opt ownership"
echo "[+] installing sublimetext.."
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
sudo apt-get install apt-transport-https
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
sudo apt-get update
sudo apt-get install sublime-text
echo "[+] installing oletools.."
sudo -H pip install -U oletools
echo "[+] installing mono.."
sudo apt-get install mono-complete
sudo msfdb start
echo "[+] msfdb started"
echo "[+] filling /opt/ folders.."
cd /opt/
git clone https://github.com/fox-it/BloodHound.py
git clone https://github.com/mdsecactivebreach/Chameleon
git clone https://github.com/cobbr/Covenant
git clone https://github.com/tyranid/DotNetToJScript
git clone https://github.com/Keramas/DS_Walk
git clone https://github.com/BC-SECURITY/Empire
git clone https://github.com/outflanknl/EvilClippy
git clone https://github.com/rvrsh3ll/FindFrontableDomains
git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
git clone https://github.com/danielbohannon/Invoke-Obfuscation
git clone https://github.com/411Hall/JAWS
git clone https://github.com/leoloobeek/LAPSToolkit
git clone https://github.com/ajinabraham/Node.Js-Security-Course
git clone https://github.com/carlospolop/PEASS-ng
git clone https://github.com/PowerShellMafia/PowerSploit/tree/master
git clone https://github.com/NetSPI/PowerUpSQL
git clone https://github.com/Kevin-Robertson/Powermad
git clone https://github.com/itm4n/PrintSpoofer
git clone https://github.com/0x09AL/RdpThief
git clone https://github.com/GhostPack/Rubeus
git clone https://github.com/rvrsh3ll/Rubeus-Rundll32
git clone https://github.com/Mr-Un1k0d3r/SCShell
git clone https://github.com/0xthirteen/SharpRDP
git clone https://github.com/mdsecactivebreach/SharpShooter
git clone https://github.com/GhostPack/SharpUp
git clone https://github.com/vletoux/SpoolerScanner
git clone https://github.com/leechristensen/SpoolSample
git clone https://github.com/latortuga71/TortugaToolKit
git clone https://github.com/iagox86/dnscat2
git clone https://github.com/jpillora/chisel
git clone https://github.com/calebstewart/bypass-clm
git clone https://github.com/CiscoCXSecurity/creddump7
git clone https://github.com/nidem/kerberoast
git clone https://github.com/hashcat/kwprocessor
git clone https://github.com/cwolff411/powerob
git clone https://github.com/DominicBreuker/pspy
git clone https://github.com/gentilkiwi/mimikatz
git clone https://github.com/int0x33/nc.exe
git clone https://github.com/trustedsec/social-engineer-toolkit
git clone https://github.com/eloypgz/ticket_converter
git clone https://github.com/Zer1t0/ticket_converter
git clone https://github.com/trinitronx/vncpasswd.py
cp /var/www/html/chisel /opt/chisel/
chmod +x /opt/chisel
echo "[+] copied /var/www/html/chisel to /opt/chisel/chisel"
