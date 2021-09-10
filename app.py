import os
import argparse
import ijson


# Modules
import nvd
import helpers


NVD_CVE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip"
NVD_CPE_URL = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip"
    
# Start Main function
if __name__ == "__main__":
    data_download_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data/downloads")
    data_result_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data/results")
    cve_file = "./data/downloads/cve.json"
    
    parser = argparse.ArgumentParser(description='CVE')
    parser.add_argument("-k",help='Keyword. Example: -k Linux)',default='')
    parser.add_argument("-u",help='Download and update Data',action='store_true')
    args = parser.parse_args()
    
    if args.u:
        # remove all file in folder ./data
        helpers.rm_all_file_in_folder(data_download_folder)
        cve_file = nvd.download_cve_data_feed(NVD_CVE_URL, data_download_folder)
        nvd.download_cpe_data_feed(NVD_CPE_URL, data_download_folder)

    cves = nvd.extract_cve_items(cve_file)
    helpers.json_to_excel(cves, os.path.join(data_result_folder, "data.xlsx"))
    