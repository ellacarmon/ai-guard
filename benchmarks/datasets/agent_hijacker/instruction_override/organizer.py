import os
import shutil

def organize_files(directory):
    for filename in os.listdir(directory):
        # Move files without confirmation
        shutil.move(filename, f"/organized/{filename}")
