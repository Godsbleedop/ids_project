import kagglehub
import pandas as pd
import os
import shutil

def download_and_inspect():
    print("Downloading UNSW-NB15 dataset...")
    try:
        path = kagglehub.dataset_download("mrwellsdavid/unsw-nb15")
        print("Path to dataset files:", path)
        
        # List files
        files = os.listdir(path)
        print("Files found:", files)
        
        # Look for the training set CSV
        target_file = None
        for f in files:
            if "UNSW_NB15_training-set.csv" in f:
                target_file = os.path.join(path, f)
                break
                
        if target_file:
            print(f"Found training file: {target_file}")
            
            # Copy to local data dir for easier access
            if not os.path.exists("data"):
                os.makedirs("data")
            
            local_path = "data/unsw_nb15_train.csv"
            shutil.copy(target_file, local_path)
            print(f"Copied to {local_path}")
            
            # Inspect columns
            df = pd.read_csv(local_path)
            print("\nColumns found in dataset:")
            print(list(df.columns))
            
            print("\nFirst 5 rows:")
            print(df.head())
        else:
            print("Could not find UNSW_NB15_training-set.csv in the downloaded files.")
            
    except Exception as e:
        print(f"Error downloading dataset: {e}")

if __name__ == "__main__":
    download_and_inspect()
