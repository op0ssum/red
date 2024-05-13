if [ "$(id -u)" -ne "0" ] ; then
    echo "[+] run this script with sudo - and i mean sudo, not root. aborting"
    exit 1
fi
cuser=$SUDO_USER
sudo echo "$cuser    ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
echo "[+] made current user $cuser password-free sudoer"
sudo echo "CustomLog /var/log/apache2/access.log combined" >> /etc/apache2/apache2.conf
sudo service apache2 restart
echo "[+] enabled apache logging - read logs with:\nsudo tail -f /var/log/apache2/access.log"
echo "[+] installing sublimetext.."
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
sudo apt-get -y update
echo "[+] installing essentials.."
sudo apt-get -y install apt-transport-https awscli ca-certificates checksec dirmngr ghidra git gnupg jq krb5-user pipx samba sublime-text seclists  
echo "[+] setting up samba.." 
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.old
cat <<EOF >>/etc/samba/smb.conf
[visualstudio]
path = /home/$cuser/data
browseable = yes
read only = no
EOF
echo "[+] smbd and nmbd setup set - enter \"$cuser\" in next prompt:"
sudo smbpasswd -a $cuser
sudo systemctl start smbd
sudo systemctl start nmbd
echo "[+] smbd and nmbd started"
echo "[+] installing NetExec.."
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
echo "[+] installing ansible-core.."
pipx install ansible-core
echo "[+] installing certipy-ad.."
pipx install certipy-ad
echo "[+] installing oletools.."
sudo -H pip install -U oletools
echo "[+] installing mono.."
sudo gpg --homedir /tmp --no-default-keyring --keyring /usr/share/keyrings/mono-official-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
echo "deb [signed-by=/usr/share/keyrings/mono-official-archive-keyring.gpg] https://download.mono-project.com/repo/debian stable-buster main" | sudo tee /etc/apt/sources.list.d/mono-official-stable.list
sudo apt -y update
sudo apt-get -y install mono-devel
sudo msfdb start
echo "[+] msfdb started"
echo "[+] filling /opt .."
for i in $(cat ./optlist.txt);do 
j=`echo $i | rev | cut -d"/" -f1 | rev`
git clone $i /opt/$j
done
mkdir /home/$cuser/data
chmod -R 777 /home/$cuser/data
echo "[+] /home/$cuser/data created for visualstudio projects"
sudo chown -R $cuser:$cuser /var/www/html
echo "[+] normalized /var/www/html ownership"
sudo chown -R $cuser:$cuser /opt
echo "[+] normalized /opt ownership"
echo "[+] copying html to /var/www/html .."
cp -r html /var/www/
cp /var/www/html/chisel /opt/chisel/
chmod +x /opt/chisel/chisel
echo "[+] copied /var/www/html/chisel to /opt/chisel/chisel"
echo "[+] downloading revsocks linux and windows binaries to /opt/revsocks.."
mkdir /opt/revsocks
wget https://github.com/kost/revsocks/releases/download/v2.8/revsocks_windows_amd64.exe
wget https://github.com/kost/revsocks/releases/download/v2.8/revsocks_windows_386.exe
wget https://github.com/kost/revsocks/releases/download/v2.8/revsocks_linux_amd64
wget https://github.com/kost/revsocks/releases/download/v2.8/revsocks_linux_386
chmod +x /opt/revsocks/revsocks_linux_amd64
chmod +x /opt/revsocks/revsocks_linux_386
cp /opt/revsocks/revsocks_windows_amd64.exe /var/www/html/
cp /opt/revsocks/revsocks_windows_386.exe /var/www/html/
cp /opt/revsocks/revsocks_linux_amd64 /var/www/html/
cp /opt/revsocks/revsocks_linux_386 /var/www/html/
echo "[+] copied revsocks binaries to /var/www/html/"
echo "[+] git clone CrossC2 branch cs4.1 to /opt/CrossC2..."
git clone -b cs4.1 https://github.com/gloxec/CrossC2 /opt/CrossC2
echo "[+] downloading CrossC2 binaries to /opt/CrossC2/src"
wget https://github.com/gloxec/CrossC2/releases/download/v3.3/CrossC2-GithubBot-2023-11-20.cna -P /opt/CrossC2/src
wget https://github.com/gloxec/CrossC2/releases/download/v3.3/CrossC2Kit-GithubBot-2023-11-20.zip -P /opt/CrossC2/src
wget https://github.com/gloxec/CrossC2/releases/download/v3.3/genCrossC2.Linux -P /opt/CrossC2/src
wget https://github.com/gloxec/CrossC2/releases/download/v3.3/genCrossC2.MacOS -P /opt/CrossC2/src
unzip /opt/CrossC2/src/CrossC2Kit-GithubBot-2023-11-20.zip -d /opt/CrossC2/src/
echo "[+] prepping CrossC2.cna"
sed -i 's+/xxx/xx/xx/+/opt/CrossC2/src+g' /opt/CrossC2/src/CrossC2.cna
sed -i 's+genCrossC2.MacOS+genCrossC2.Linux+g' /opt/CrossC2/src/CrossC2.cna
echo "[+] check: head -n 5 /opt/CrossC2/src/CrossC2.cna -> must see /opt/CrossC2/src and genCrossC2.Linux"
head -n 5 /opt/CrossC2/src/CrossC2.cna
echo "[+] copying contents of /opt/CrossC2/src/ to /opt/cs/cobaltstrike/"
mkdir -p /opt/cs/cobaltstrike
cp -r /opt/CrossC2/src/ /opt/cs/cobaltstrike/
echo "[+] CrossC2 prep done - rmb to add cna script on cs: /opt/cs/cobaltstrike/CrossC2.cna"
echo "[+] building ligolo-ng"
cd /opt/ligolo-ng
go build -o agent cmd/agent/main.go
go build -o proxy cmd/proxy/main.go
GOOS=windows go build -o agent.exe cmd/agent/main.go
GOOS=windows go build -o proxy.exe cmd/proxy/main.go
cp /opt/ligolo-ng/agent /var/www/html/
cp /opt/ligolo-ng/agent.exe /var/www/html/
echo "[+] built ligolo-ng, copied agent binaries to /var/www/html/"
echo "[+] downloading kwp release"
wget https://github.com/hashcat/kwprocessor/releases/download/v1.00/kwprocessor-1.00.7z -P /opt/kwprocessor
