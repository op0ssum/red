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
cat ./optlist.txt | bash
cp /var/www/html/chisel /opt/chisel/
chmod +x /opt/chisel
echo "[+] copied /var/www/html/chisel to /opt/chisel/chisel"
