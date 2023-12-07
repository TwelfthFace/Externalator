import json
import os

main_dir = os.path.dirname(os.path.abspath(__file__)) + '/../'

def load_vuln_desc_from_sp(vuln_id):
    
    vuln_files = [os.path.join(main_dir + 'vulns/', name) for name in os.listdir(main_dir + 'vulns/')]
    total_count = 1
    
    for file in vuln_files:
        try:
            f = open(file)

            data = json.load(f)
            
            for page in data:
                for entry in page:
                    for vuln in entry['data']:
                        if vuln_id in vuln['name']:
                            return vuln['description']
            f.close()
        except Exception as e:
            print(e)

    print(total_count)
