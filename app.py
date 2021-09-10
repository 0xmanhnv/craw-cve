import os
import argparse

# Modules
import nvd
import helpers



# Start Main function
if __name__ == "__main__":
    data_download_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data/downloads")
    
    # remove all file in folder ./data
    helpers.rm_all_file_in_folder(data_download_folder)
    
    nvd.download_cve_data_feed(data_download_folder)
    nvd.download_cpe_data_feed(data_download_folder)