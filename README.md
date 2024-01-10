## Externalator

Script to automate and log vulnerabilties found during an external infrastructure assessment.

### Capabilities

FTP, SSH, TLS checking, logging common vulnerabilties, such as; Outdated TLS (and other exploits), anonymous FTP enabled, checks if explicit FTP is supported, password authentication supported (SSH), weak KEX algos supported (SSH), missing security headers on web applications / deprecated header usage... so far.

### How To Use
Place completed Nmap xml files inside of the script directory `<companyname>/xmls`.
Then run,
`pip install -r requirements.txt
python3 externalator.py <companyname>`

## For The Future
I plan to expand the script's capabilities to cover a wider range of services.
