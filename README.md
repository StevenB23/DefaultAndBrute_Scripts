# DefaultAndBrute_Scripts
Brute force and use default credential lists to audit various networking protocols like Telnet/SSH/SMB/HTTP

**telnet-brute.nmap.py**
* Takes in a csv file with ip addresses of known Telnet servers. The column of IPs must be named "IPv4".
* The purpose is to audit credentials in a large environment with 300+ discovered Telnet servers.
* There was an issue supplying a list to nmap directly for these scans so this script runs nmap against each IP address which makes things slower but gets the job done and doesn't miss as much.
* Supply the CSV file, credentials file with a list in "usernames/passwords" format, and the output csv file(contains a new column "Brute_Results")
* Timeout and long server response times are taken into consideration and if the nmap nse scripts take too long will timeout and move on after 10 minutes. See script for other options used or modify as needed.
* in case the script or machine stops abruptly a log is saved to /root/pentests/telnet

> ./telnet-brute.nmap.py telnet-machines.csv creds.txt telnet-brute-results.csv

**telnet-passonly-brute.py**
* Takes the csv file with column named "IPv4" containing a list of telnet server IPs to perform password only checks.
* Uses nmap switches to only check the password from a list of supplied passwords. Good for auditing a large number of telnet servers returning the "Prompt encountered" error when otherwise running a username/password nmap brute-force script. Mostly printers.

> ./telnet-passonly-brute.py telnet-machines.csv passwords.txt telnet-brute-results.csv
