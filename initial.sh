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
sudo apt install samba
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
echo "[+] installing sublimetext.."
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
sudo apt-get -y update
sudo apt-get -y install apt-transport-https
sudo apt-get -y install sublime-text
echo "[+] installing NetExec.."
apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
echo "[+] installing krb5-user.."
sudo apt-get -y install krb5-user
echo "[+] installing oletools.."
sudo -H pip install -U oletools
echo "[+] installing awscli.."
sudo apt-get -y install awscli
echo "[+] installing mono.."
sudo apt -y install dirmngr ca-certificates gnupg
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
