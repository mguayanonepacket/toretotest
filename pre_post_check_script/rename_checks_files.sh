#!/bin/bash

# Destination folder
folder="pyTMP"

# String to search for in the filenames
old_device="$1"

# String to replace in the filenames
new_device="$2"

# List the files that contain the original  string in the name
files=$(find "$folder" -type f -name "*$old_device*")

# Iterate over the found files and rename them
for file in $files; do
    # Get the filename without the path
    filename=$(basename "$file")
    
    # Replace the original string with the new string in the filename
    new_filename="${filename//$old_device/$new_device}"
    
    # Rename the file
    cp "$file" "$folder/$new_filename"
    
    echo "Renamed: $filename -> $new_filename"
done