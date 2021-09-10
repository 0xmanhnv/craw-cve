import ijson
import helpers

def download_cve_data_feed(url: str, save_folder: str):
    file_name_cve_zip = "cve.zip"
    file_name_cve_json = "cve.json"
    
    cve_dl = helpers.download(url, save_folder, file_name=file_name_cve_zip)
    
    if(cve_dl):
        return helpers.unzip(cve_dl, save_folder, file_name_cve_json)
    
    return None

def download_cpe_data_feed(url: str, save_folder: str):
    file_name_cpe_match_zip = "cpe_match.zip"
    file_name_cpe_match_json = "cpe_match.json"
    
    cpe_dl = helpers.download(url, save_folder, file_name=file_name_cpe_match_zip)
    
    if(cpe_dl):
        return helpers.unzip(cpe_dl, save_folder, file_name_cpe_match_json)
    
    return None

def cve_items_to_info(item):
    data = dict()
    cve = item.get("cve")
    
    data["CVE ID"] = cve.get("CVE_data_meta").get("ID")
    data["Desciption"] = cve.get("description").get("description_data")[0].get("value")
    data["Last modified date"] = item.get("lastModifiedDate")
    data["Pushlish date"] = item.get("publishedDate")
    return data

def extract_cve_items(path_file: str):
    cves_info = list()
    with open(path_file, 'r') as f:
        cve_items = ijson.items(f, 'CVE_Items.item')
        for item in cve_items:
            cves_info.append(cve_items_to_info(item))
            
    return cves_info
            
    
