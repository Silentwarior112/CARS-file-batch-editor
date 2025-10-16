# CARS-file-batch-editor
Editor for Gran Turismo 4 CARS files

This tool is intended to automate adding generic parts and deleting groups of parts in CARS files in bulk.

The tool is bundled with a GENERIC_CAR.csv file containing names to associate with each CARS file, for easy identification.
Simply replace it with your modified .csv if needed.

<p align="center">
  <img width="891" height="790" src="https://github.com/Silentwarior112/CARS-file-batch-editor/blob/main/pic.PNG">
</p>

# Functions
[Load files]: Select either a single CARS file or multiple. Use Ctrl+A to select all CARS file in a folder.
Once loaded, any action you do will be done to EVERY FILE you selected. For editing a single CARS file, make sure to
only select ONE file when loading. Check the Selected file: dropdown to verify what you are modifying.

[Load file list]: Used for making edits to specific groups of cars, such as only cars with a certain drivetrain.
Locate a .csv file to load a list. It uses 2 colums: [Id, label].
An example set is included.

[Batch Remove]: Deletes part data from the loaded CARS files. You can delete a specific type + category, or delete ALL parts of a
certain type. Additionally this can be used to clean up CARS files that have dummy FFFFFFFF bytes.

[Batch Replace]: Target a specific part type + category for each loaded CARS file. This replaces any matches with the specified
part.

[Batch Add]: Add a specific part to each loaded CARS file.

[Scrollbox]: View the CARS file's part list.