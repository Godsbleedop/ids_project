# Dataset Setup Instructions

Since we cannot download the dataset automatically, please follow these steps to download the **UNSW-NB15** dataset manually. This is a modern, widely accepted dataset for Intrusion Detection research.

## Step 1: Download the Dataset
You can download the training set CSV from **Kaggle** or **Figshare**.

**Option A: Kaggle (Recommended)**
1.  Go to: [UNSW-NB15 on Kaggle](https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15)
2.  Download the file named `UNSW_NB15_training-set.csv`.

**Option B: Figshare (Direct)**
1.  Go to: [UNSW-NB15 on Figshare](https://figshare.com/articles/dataset/UNSW_NB15_training-set_csv/54850502)
2.  Download the file.

## Step 2: Place the File
1.  Rename the downloaded file to `unsw_dataset.csv`.
2.  Move it into the `data` folder of your project.

**Path:** `/home/aaron/ids_project/data/unsw_dataset.csv`

## Step 3: Train the Model
Once the file is in place, run the training script:

```bash
python3 train_model.py
```

This will train the IDS model using the real UNSW-NB15 data.
