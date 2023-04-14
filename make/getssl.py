import subprocess

filenames = subprocess.check_output(['ls','/home/kali/Desktop/scans/'])
filenames = filenames.decode()
filenames = filenames.split('\n')

nmapresults = []
for i in filenames:
	if "nmap-tcpscans" in i:
		nmapresults.append(i)

#print(nmapresults)

bigres = []

def getssl(filename):
	ipaddr = filename.split("_")[1].split(".txt")[0]
	#res = []
	with open(filename,'r') as f:
		line = f.readline()
		while line != "":
			if "open" in line:
				if "ssl" in line:
					port = line.split("/tcp")[0]
					bigres.append(ipaddr+":"+port)
			line = f.readline()
	f.close()
	#print(res)
	pass

for filename in nmapresults:
	getssl(filename)

#print(bigres)
#bigres_str = "\n".join(bigres)
#print(bigres_str)

with open("ssl.txt","w") as f:
	for i in bigres:
		f.write(i)
		f.write("\n")
f.close()

print("[+] done. written to ssl.txt")
print("[+] use with: \nfor i in $(cat ssl.txt);do sslscan $i | tee sslscan_$i.txt;done")
