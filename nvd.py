import helpers

nvd_cve_path = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip"

def download_cve_data_feed(save_folder: str):
    file_name_cve_zip = "cve.zip"
    file_name_cve_json = "cve.json"
    
    cve_dl = helpers.download(nvd_cve_path, save_folder, file_name=file_name_cve_zip)
    
    if(cve_dl):
        helpers.unzip(cve_dl, save_folder, file_name_cve_json)
    
    return True