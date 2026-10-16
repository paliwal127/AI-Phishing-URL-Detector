import argparse
import csv
import os
from pathlib import Path

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django

django.setup()

from scanner.models import Feedback


def export_approved_feedback(output_path):
    reviewed = Feedback.objects.filter(
        review_status=Feedback.ReviewStatus.APPROVED,
    ).exclude(suggested_label="").select_related("scan")
    label_map = {"safe": "legitimate", "suspicious": "phishing", "phishing": "phishing"}
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as output_file:
        writer = csv.writer(output_file)
        writer.writerow(["url", "label"])
        writer.writerows(
            (entry.scan.url, label_map[entry.suggested_label])
            for entry in reviewed
            if entry.suggested_label in label_map
        )
    return output_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export only admin-approved, labeled feedback rows.")
    parser.add_argument("output", help="Destination CSV for reviewed URLs")
    args = parser.parse_args()
    print(export_approved_feedback(args.output))