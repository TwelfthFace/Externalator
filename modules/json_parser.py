import json
import os

main_dir = os.path.dirname(os.path.abspath(__file__)) + '/../'

vuln_to_sp = {"SSLv2": "SSL/TLS - Version 2 and 3 Protocol Detection",
                 "SSLv3": "SSL/TLS - Version 2 and 3 Protocol Detection",
                 "TLS1": "SSL/TLS - Version 1.0 Protocol Detection",
                 "TLS1_1": "SSL/TLS - TLS Version 1.1 Protocol Detection",
                 "cert_chain_of_trust": "SSL/TLS - Self-Signed Certificate",
                 "secure_client_renego": "Client-Initiated Secure Renegotiation (DoS Threat)",
                 "cert_expirationStatus": "SSL/TLS -  Certificate Expiry",
                 "BREACH": "HTTPS Compression Attack (BREACH)",
                 "POODLE_SSL": "SSL/TLS - SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
                 "POODLE_TLS": "SSL/TLS - SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
                 "fallback_SCSV": "TLS Fallback SCSV",
                 "FREAK": "SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)",
                 "LOGJAM": "SSL/TLS -  Diffie-Hellman Modulus <= 1024 Bits (Logjam)",
                 "DROWN": "SSL/TLS - Decrypting RSA with Obsolete and Weakened eNcryption (DROWN)",
                 "BEAST": "SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)",
                 "BEAST_CBC_TLS1": "SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)",
                 "LUCKY13": "SSL/TLS Lucky13",
                 "RC4": "SSL/TLS - RC4 Cipher Suites Supported (Bar Mitzvah)"
                 }

def normalise_vuln_to_sp(vuln_id):
    if vuln_id in vuln_to_sp:
        return vuln_to_sp[vuln_id]
    return vuln_id

def load_vuln_desc_from_sp(vuln_id):
    vuln_files = [os.path.join(main_dir + 'vulns/', name) for name in os.listdir(main_dir + 'vulns/')]
    total_count = 1
    
    for file in vuln_files:
        try:
            with open(file, 'r') as f:
                data = json.load(f)

                if vuln_id in vuln_to_sp:
                    vuln_id = vuln_to_sp[vuln_id]

                for page in data:
                    for entry in page:
                        for vuln in entry['data']:
                            if vuln_id in vuln['name']:
                                return vuln['description']
            return "NULL"
        except Exception as e:
            print(e)

    print(total_count)
