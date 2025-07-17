import json
import csv
import re
from rich import print as rprint
from rich.table import Table
from rich.console import Console
from rich import box

# Columns shown in table output (terminal only)
column_order = [
    'risk_score',
    'score_trace',
    'file_identifier',
    'responsible_file_identifier',
    'origin_url',
]

def is_styled_rich(val):
    """Check if a string already includes rich formatting."""
    return isinstance(val, str) and re.search(r"\[[a-zA-Z_]+\]", val)

def truncate(val, width=50):
    val = str(val)
    return val if len(val) <= width else val[:width - 3] + "..."

def output_table(data, config=None):
    if not data:
        print("No data to display.")
        return

    data = sorted(data, key=lambda x: x.get("risk_score", 0), reverse=True)

    thresholds = config.get("color_thresholds", {}) if config else {}
    red = thresholds.get("red", 10)
    yellow = thresholds.get("yellow", 5)

    table = Table(
        title="ExecCheck Results",
        show_lines=True,
        header_style="bold magenta",
        box=box.SQUARE,
        row_styles=None,
        title_style="bold"
    )

    for col in column_order:
        table.add_column(col, overflow="fold")

    for row in data:
        risk = row.get("risk_score", 0)
        if isinstance(risk, str) and risk.isdigit():
            risk = int(risk)

        if risk >= red:
            color = "red"
        elif risk >= yellow:
            color = "yellow"
        else:
            color = "white"

        values = []
        for col in column_order:
            val = row.get(col, "")
            if val is None or val == "":
                values.append("None")  # plain text, no color
                continue

            if isinstance(val, list):
                val = ", ".join(map(str, val))

            val = truncate(val)

            if "[" in str(val) and "]" in str(val):
                values.append(val)  # already styled
            else:
                values.append(f"[{color}]{val}[/{color}]")

        table.add_row(*values)

    console = Console()
    console.print(table)


def output_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def output_ndjson(data, path):
    with open(path, "w", encoding="utf-8") as f:
        for row in data:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")

def output_csv(data, path):
    if not data:
        print("No data to write.")
        return

    all_keys = set().union(*[row.keys() for row in data])
    ordered_keys = [col for col in column_order if col in all_keys] + [k for k in all_keys if k not in column_order]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ordered_keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(data)
