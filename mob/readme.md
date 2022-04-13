kali objection setup [apktool sauce](https://github.com/iBotPeaches/Apktool/issues/2149) [sauce2](https://ibotpeaches.github.io/Apktool/install/)
```
sudo apt-get update
sudo apt-get install python3-pip

wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.6.1.jar
mv apktool_2.6.1.jar apktool.jar
chmod +x apktool apktool.jar
sudo mv apktool apktool.jar /usr/local/bin

sudo apt-get install apksigner zipalign aapt adb

sudo pip3 install objection
sudo objection patchapk -s target.apk -a arm64-v8a
```

windows objection setup
```
# open admin powershell/cmd prompt
pip install objection
pip install frida-tools
```

frida objection setup [sauce](https://gowthamr1.medium.com/android-ssl-pinning-bypass-using-objection-and-frida-scripts-f8199571e7d8)
```
# start the patched apk no android phone

# powershell window
frida-trace -U -i open Gadget

# another window
objection explore
```

objection disable
```
android sslpinning disable
android root disable
```
