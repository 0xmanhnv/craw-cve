import zipfile
import urllib.request

#Download file .zip from NIST and extract
def update():
    print('Downloading...')
    url='https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip'
    urllib.request.urlretrieve(url, "data.zip")
    with zipfile.ZipFile('data.zip', 'r') as zip_ref:
        zip_ref.extractall()
    print('Done!')