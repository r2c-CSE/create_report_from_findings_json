# Semgrep Findings Processing Tool: create a HTML, CSV and XLS report from findings.JSON 

This Python script processes Semgrep SAST findings from JSON format, producing a detailed report in CSV, JSON, and HTML formats. It allows for efficient analysis and visualization of SAST findings, emphasizing the severity of vulnerabilities and providing actionable insights.

## Features

- **Load and Process JSON**: Takes a JSON file containing Semgrep findings and processes it.
- **Data Analysis**: Extracts, filters, and transforms findings data for analysis.
- **Report Generation**: Outputs processed data into CSV, JSON, and a detailed HTML report, which includes clickable URLs for quick access to findings.
- **Severity Mapping**: Maps Semgrep severity levels (ERROR, WARNING, INFO) to HIGH, MEDIUM, LOW for standardized reporting.
- **Command-line Interface**: Facilitates easy usage through command-line arguments for input files and repository names.

## Installation

Before running the script, ensure you have Python installed on your system (Python 3.6 or newer is recommended). This script requires the following Python packages:

- pandas
- requests
- fpdf
- pdfkit

To install these dependencies, run:

```bash
pip install pandas requests fpdf pdfkit
```

```bash
pip install -r requirements.txt
```

## Usage

1. Prepare a JSON file with Semgrep findings. The script expects a specific JSON structure, as typically outputted by Semgrep.
2. Use the command-line interface to specify the JSON file path and the repository name. Syntax:

```bash
python create_findings_from_findings_json.py <path_to_findings.json> <repo_name>
```

Example:

```bash
python create_findings_from_findings_json.py findings.json my_repo
```

This command will process `findings.json` for the repository `my_repo` and generate reports in the current directory.

## Output

The script generates three types of files:

- A CSV file (`<repo_name>_semgrep.csv`): Contains a flat table of findings.
- A JSON file (`<repo_name>_semgrep.json`): Contains findings in a structured JSON format.
- An HTML report (`<repo_name>_semgrep_result.html`): Presents findings in a web-viewable format, including a summary table and detailed findings with clickable links for quick access.

## Contributing

Contributions to improve the script or extend its functionality are welcome. Please open an issue or pull request on the project's GitHub repository.
