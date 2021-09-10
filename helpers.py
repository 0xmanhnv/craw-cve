import os
import requests
import sys

from zipfile import ZipFile

def download(url: str, save_path: str = "data", file_name: str = "data.zip"):
    path_file = os.path.join(save_path, file_name)
    dl = 0
    
    try:
        with open(path_file, "wb") as f:
            res = requests.get(url, stream=True)
            total_length = int(res.headers.get('content-length', 0))
            
            if total_length is None: # no content length header
                f.write(res.content)
                return True
            
            for data in res.iter_content(chunk_size=4096):
                dl += len(data)
                f.write(data)
                done = int(50 * dl / total_length)
                sys.stdout.write("\rDownloading [%s>%s]" % ('=' * done, ' ' * (50-done)) )    
                sys.stdout.flush()

            f.close()

        return path_file
    except:
        return None
    
def unzip(zip_file: str, save_folder: str = "./data", new_file: str = "data.json"):
    new_file = os.path.join(save_folder, new_file)
    old_file = ""
    print("\nUnzip " + zip_file + " to " +  new_file)
    
    try:
        with ZipFile(zip_file, 'r') as zip_ref:
            for zipinfo in zip_ref.infolist():
                old_file = os.path.join(save_folder, zipinfo.filename)

            zip_ref.extractall(save_folder)

        os.rename(old_file, new_file)
        print(old_file)
        os.remove(zip_file)
    except:
        return None