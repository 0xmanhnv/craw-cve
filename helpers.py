import os
import shutil
import json
import requests
import sys
from zipfile import ZipFile
import pandas as pd

import bcolor

def process_bar(total_length, dl_process):
    done = int(50 * dl_process / total_length)
    
    
    process = "\r{0}Downloading...{1} [{2}{3}>{4}{5}] {6}%".format(
        bcolor.Bcolor.OKGREEN,
        bcolor.Bcolor.ENDC,
        bcolor.Bcolor.CRED2,
        '=' * done,
        ' ' * (50-done),
        bcolor.Bcolor.ENDC,
        done * 2
    )
    sys.stdout.write(process)    
    sys.stdout.flush()
    

def download(url: str, save_path: str = "data", file_name: str = "data.zip"):
    path_file = os.path.join(save_path, file_name)
    dl_process = 0
    
    try:
        with open(path_file, "wb") as f:
            res = requests.get(url, stream=True, timeout=5)
            total_length = int(res.headers.get('content-length', 0))
            
            if total_length is None: # no content length header
                f.write(res.content)
                return True
            
            for data in res.iter_content(chunk_size=4096):
                f.write(data)
                
                dl_process += len(data)
                process_bar(total_length, dl_process)

            f.close()

        return path_file
    
    except requests.HTTPError as e:
        print("\nChecking internet connection failed, status code {0}.".format(
                e.response.status_code
            )
        )
        return None
    except requests.ConnectionError:
        print("\nNo internet connection available.")
        return None
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

        # remove file zip
        if os.path.exists(zip_file):
            print("Rm file " + zip_file)
            os.remove(zip_file)
        
        return new_file
    except:
        return None
    
def rm_all_file_in_folder(folder: str):
    # check and create folder if not exists
    if(not os.path.isdir(folder)):
        os.mkdir( folder )
        return False
    
    # rm all file in folder
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)

        try:
            if os.path.isfile(file_path) or os.path.islink(file_path) and file_path != ".gitignore":
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
            
            return True
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))
            return False
        
def load_file_json(path_file=''):
    try:
        with open(path_file, 'r') as f:
            content = json.load(f)
        return content
    except:
        return None
    
def write_file_json(var_dict: dict, path_file: str =' '):
    if var_dict:
        try:
            with open(path_file, 'w') as outfile:
                json.dump(var_dict, outfile, indent=4, ensure_ascii=False)

            return True
        except:
            return False

    return False

def json_to_excel(data, save_file):
    try:
        df = pd.json_normalize(data)
        df.to_excel(save_file)
        
        return True
    except:
        return False