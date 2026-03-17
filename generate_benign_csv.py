import csv
from pathlib import Path

base_output = Path(r"C:\benign")

csv_file = base_output / "benign_file_list.csv"

rows = []

for source_folder in base_output.iterdir():

    if not source_folder.is_dir():
        continue

    source_name = source_folder.name

    for type_folder in source_folder.iterdir():

        if not type_folder.is_dir():
            continue

        file_type = type_folder.name

        for file in type_folder.iterdir():

            if file.is_file():

                rows.append([
                    source_name,
                    file_type,
                    file.name,
                    str(file)
                ])


with open(csv_file, "w", newline="", encoding="utf-8") as f:

    writer = csv.writer(f)

    writer.writerow(["source_folder", "file_type", "file_name", "full_path"])

    writer.writerows(rows)


print(f"CSV created: {csv_file}")
print(f"Total files listed: {len(rows)}")