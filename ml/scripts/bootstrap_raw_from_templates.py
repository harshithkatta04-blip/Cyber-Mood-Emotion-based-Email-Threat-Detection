import shutil
from pathlib import Path


def main():
    template_dir = Path("ml/data/templates")
    raw_dir = Path("ml/data/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)

    copies = 0
    for template in template_dir.glob("*_template.csv"):
        target_name = template.name.replace("_template", "")
        target_path = raw_dir / target_name
        if target_path.exists():
            continue
        shutil.copyfile(template, target_path)
        copies += 1
        print(f"Created: {target_path}")

    if copies == 0:
        print("No new files created. Raw files already exist.")
    else:
        print(f"Created {copies} raw dataset skeleton file(s).")


if __name__ == "__main__":
    main()
