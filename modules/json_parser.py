import json
import os

main_dir = os.path.dirname(os.path.abspath(__file__)) + '/../'

testssl_to_sp = {"SSLv2": "SSL/TLS - Version 2 and 3 Protocol Detection",
                 "SSLv3": "SSL/TLS - Version 2 and 3 Protocol Detection",
                 "TLS1": "SSL/TLS - Version 1.0 Protocol Detection",
                 "TLS1_1": "SSL/TLS - TLS Version 1.1 Protocol Detection",
                 "cert_chain_of_trust": "SSL/TLS - Self-Signed Certificate",
                 "secure_client_renego": "Client-Initiated Secure Renegotiation (DoS Threat)",
                 "BREACH": "HTTPS Compression Attack (BREACH)",
                 "POODLE_SSL": "SSL/TLS - SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
                 "POODLE_TLS": "SSL/TLS - SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)",
                 "fallback_SCSV": "TLS Fallback SCSV",
                 "FREAK": "SSL/TLS EXPORT_RSA <= 512-bit Cipher Suites Supported (FREAK)",
                 "LOGJAM": "SSL/TLS -  Diffie-Hellman Modulus <= 1024 Bits (Logjam)",
                 "DROWN": "SSL/TLS - Decrypting RSA with Obsolete and Weakened eNcryption (DROWN)",
                 "BEAST": "SSL/TLS Protocol Initialization Vector Implementation Information Disclosure Vulnerability (BEAST)",
                 "LUCKY13": "SSL/TLS Lucky13",
                 "RC4": "SSL/TLS - RC4 Cipher Suites Supported (Bar Mitzvah)"
                 }

def normalise_testssl_vuln_to_sp(vuln_id):
    if vuln_id in testssl_to_sp:
        return testssl_to_sp[vuln_id]
    return vuln_id

def load_vuln_desc_from_sp(vuln_id):
    vuln_files = [os.path.join(main_dir + 'vulns/', name) for name in os.listdir(main_dir + 'vulns/')]
    total_count = 1
    
    for file in vuln_files:
        try:
            f = open(file)

            data = json.load(f)
            
            if vuln_id in testssl_to_sp:
                vuln_id = testssl_to_sp[vuln_id]
                print(vuln_id)

            for page in data:
                for entry in page:
                    for vuln in entry['data']:
                        if vuln_id in vuln['name']:
                            return vuln['description']
            return "NULL"

            f.close()
        except Exception as e:
            print(e)

    print(total_count)
