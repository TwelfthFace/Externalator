import json
import os

def load_vulns_from_files(main_dir):
    vuln_files = [os.path.join(main_dir + '/vulns/', name) for name in os.listdir(main_dir + '/vulns/')]
    total_count = 1
    
    for file in vuln_files:
        try:
            f = open(file)

            data = json.load(f)

            for count, vuln in enumerate(data['data']):
                print(vuln)
            total_count += count
            f.close()
        except Exception as e:
            print(e)

    print(total_count)
