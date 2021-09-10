import os

# Modules
import nvd



# Start Main function
if __name__ == "__main__":
    data_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    
    nvd.download_cve_data_feed(data_folder)