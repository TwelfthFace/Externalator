## Externalator

Script to automate and log vulnerabilties found during an external infrastructure assessment.

### Capabilities

FTP, SSH, TLS checking, logging common vulnerabilties, such as; Outdated TLS (and other exploits), anonymous FTP enabled, checks if explicit FTP is supported, password authentication supported (SSH), weak KEX algos supported (SSH), missing security headers on web applications / deprecated header usage... so far.

### How To Use
Place completed Nmap xml files inside of the script directory `<companyname>/xml`.
Then run,
```

#install the requirements
pip install -r requirements.txt
python3 externalator.py <work_dir>

#give exec perms to the externalator.py (alternatively run with `python3 externaltor.py`)
chmod +x externalator.py

#run externalator to create the directory skeleton
./externalator <work_dir_name>
"<work_dir_name> doesn't exist. create (Y/n): "

cd <work_dir_name>

#create the scope file (list of IPs, each ip to a new line)
#example below
echo -e "127.0.0.1\n127.0.0.2\n127.0.0.3\n"

#run the nmap command in the `nmap_cmd` file
#syn scan - all ports - default scripts (IMPORTANT) - version discovery (IMPORTANT) - treat all hosts as up regardless of ping response - list of hosts - output results in file in XML (IMPORTANT)
nmap -sS -p- -sC -sV -Pn -iL <work_dir>/host_list -oX <work_dir>/xml/scan01_TCP.xml

#run externalator and wait :)
./externalator.py <work_dir_name>

```

## For The Future
I plan to expand the script's capabilities to cover a wider range of services.
