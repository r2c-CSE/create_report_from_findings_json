import json
import pandas as pd
import getopt
import requests
import sys
import json
import re
import os
import pandas as pd
from pandas import json_normalize
from datetime import datetime
import logging
import json
from fpdf import FPDF
import html
import pdfkit
import argparse

# Create the parser
parser = argparse.ArgumentParser(description='Process some JSON files.')

# Add arguments
parser.add_argument('json_path', type=str, help='The file path to the findings.json JSON file')
parser.add_argument('repo_name', type=str, help='Repo Name')

# Parse the arguments
args = parser.parse_args()

def load_json(file_path):
    """Load JSON data from a file."""
    with open(file_path, 'r') as file:
        return json.load(file)

def extract_fingerprints(data):
    """Extract objects keyed by their fingerprints."""
    return {item["extra"]["fingerprint"]: item for item in data}

def compare_fingerprints(left_objects, right_objects):
    """Identify unique and common fingerprints across two sets of objects."""
    left_keys = set(left_objects.keys())
    right_keys = set(right_objects.keys())
    only_in_left = left_keys - right_keys
    only_in_right = right_keys - left_keys
    in_both = left_keys & right_keys
    return only_in_left, only_in_right, in_both

def create_dataframes(findings_data):
    """Create, flatten, and filter Pandas DataFrames for objects unique to each file and common to both, with 'extra.severity' as the first column."""
    desired_columns = [
        'extra.severity', 
        'check_id', 
        'path', 
        'start.line',
        'end.line',
        'extra.lines', 
        'extra.message', 
        # 'extra.metadata.confidence', 
        # 'extra.metadata.cwe', 
        # 'extra.metadata.impact', 
        # 'extra.metadata.owasp', 
        # 'extra.metadata.product', 
        'extra.metadata.shortlink'
    ]
    
    # Flatten and filter the data
    df_findings_data = flatten_and_select_columns(findings_data, desired_columns)
    
    return df_findings_data

def flatten_and_select_columns(data, columns):
    """Flatten JSON data and reorder specific columns with 'extra.severity' as the first column."""
    df = pd.json_normalize(data)
    # Ensure all desired columns are present, even if they are empty, and reorder them
    for column in columns:
        if column not in df.columns:
            df[column] = pd.NA
    return df[columns]

def escape_df(df):
    """Escape all string columns in the DataFrame to prevent HTML and JS rendering."""
    str_columns = df.select_dtypes(include=['object', 'string']).columns
    for col in str_columns:
        if (col != 'extra.metadata.shortlink'):
            df[col] = df[col].apply(html.escape)
    return df

def replace_severity(df):
    """Map severity values from ERROR, WARNING, INFO to HIGH, MEDIUM, LOW."""
    severity_map = {
        'ERROR': 'HIGH',
        'WARNING': 'MEDIUM',
        'INFO': 'LOW'
    }
    df['extra.severity'] = df['extra.severity'].replace(severity_map)
    return df

def make_clickable(check_id, url):
    """Return the check_id as a clickable link."""
    return f'<a href="{url}">{check_id}</a>'

def apply_clickable_urls(df):
    """Apply clickable URLs to the check_id column based on extra.metadata.shortlink."""
    df['check_id'] = df.apply(lambda row: make_clickable(row['check_id'], row['extra.metadata.shortlink']), axis=1)
    return df

# Function to format the path with line numbers
def format_path_with_lines(row):
    return f"{row['path']}:L{row['start.line']}-{row['end.line']}"


def save_output(df, prefix):
    """Save DataFrame to CSV and JSON files."""
    df.to_csv(f'{prefix}.csv', index=False)
    df.to_json(f'{prefix}.json', orient='records')


def save_html(df_findings: pd.DataFrame):
    # get the Overview table HTML from the dataframe
    # overview_table_html = df_overview.to_html(table_id="table")
    # get the Findings table HTML from the dataframe

    # Escape string data in DataFrames
    df_findings = escape_df(df_findings)

    # Apply clickable URLs to the check_id column for each DataFrame
    df_findings = apply_clickable_urls(df_findings)

    # Apply the function to each row
    df_findings['path'] = df_findings.apply(format_path_with_lines, axis=1)


    # drop extra.metadata.shortlink, start.line and end.line column
    columns_to_drop = ['extra.metadata.shortlink', 'start.line', 'end.line']
    df_findings = df_findings.drop(columns_to_drop, axis=1)

    # rename columns
    columns_to_rename = {
        'extra.lines': 'vulnerable code snippet',
        'extra.message': 'message',
        'extra.severity': 'severity'
    }

    df_findings.rename(columns= columns_to_rename, inplace=True)

    findings_table_html = df_findings.to_html(index=False, table_id="tableHigh", render_links=True, escape=False, classes='my_table')

    # Get the current date and time
    now = datetime.now()

    # Format the date and time
    formatted_now = now.strftime("%Y-%m-%d %H:%M")

    # Print the formatted date and time
    print("Current date and time:", formatted_now)

    html = f"""
    <html>
    <head>
    <title> Semgrep SAST Findings Report </title>
    <style>
    .my_table {{
        width: 100%;
        table-layout: fixed; /* Use fixed table layout to honor cell width */
        border-collapse: collapse;
    }}
    .my_table th, .my_table td {{
        border: 1px solid black;
        text-align: left;
        padding: 8px;
        # max-width: 50ch; /* Set max width of cells to 50 characters */
        overflow-wrap: break-word; /* Ensure text wraps inside the cell */
    }}
    .my_table th {{
        background-color: #f2f2f2;
    }}
    /* Example of setting specific column widths */
    .my_table td:nth-of-type(1) {{ /* Targeting first column */
        width: 10% !important;
    }}
    .my_table td:nth-of-type(2) {{ /* Targeting second column */
        width: 20% !important;
    }}
    .my_table td:nth-of-type(3) {{ /* Targeting third column */
        width: 10% !important;
    }}
    .my_table td:nth-of-type(4) {{ /* Targeting fourth column */
        width: 30% !important;
    }}
    .my_table td:nth-of-type(5) {{ /* Targeting fifth column */
        width: 30% !important;
    }}
    </style>
    <style>
        #myImage {{
            display: block;
            margin-left: auto;
            margin-right: auto;
            width: 75%; /* or any desired width */
            height: auto; /* to maintain the aspect ratio */
        }}
    </style>
    <style>
        .centered-table {{
            margin-left: auto;
            margin-right: auto;
        }}
    </style>
    <style>
        table {{
            border-collapse: collapse;
            width: 50%;
        }}
        th, td {{
            border: 1px solid black;
            text-align: left;
            padding: 8px;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
    </style>

    </head>
    <header>
        <link href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css" rel="stylesheet">
    </header>
    <body>
    <div style="height: 75px;"></div> <!-- Creates 75px of vertical space -->
    <div class="container">
    <img src="https://i.ibb.co/8xyV6WJ/Semgrep-logo.png" alt="logo" id="myImage">
    </div>
    <div class="container">
    <h1> <p style="text-align: center;" id="sast"> Semgrep SAST Findings Report </p> </h1>
    <h2> <p style="text-align: center;" id="reporttime"> Report Generated at {formatted_now} </p> </h2>
    </div>
    <div style="height: 40px;"></div> <!-- Creates 50px of vertical space -->
    <div class="topnav">
    <h2> <p style="text-align: center;" id="sast-summary"> SAST Scan Summary </p> </h2>

    <table border="1" class="centered-table"> <!-- Added border for visibility -->
        <!-- Table Header -->
        <tr>
            <th>Vulnerability Severity</th>
            <th>Vulnerability Count</th>
        </tr>

        <!-- Table Rows and Data Cells -->
        <tr>
            <td><a href="#sast-pro"> Findings- PRO Only (Missed findings by OSS) </a> </td>
            <td> {len(df_findings)} </td>
        </tr>
    </table>

    </div>

    <div style="page-break-after: always;"></div>

    <div class="heading">
    <h2> <p id="sast-pro"> Semgrep SAST Findings </p> </h2>
    </div>
    <div class="container">
        {findings_table_html}
    </div>

    <div style="page-break-after: always;"></div>

    </body>
    </html>
    """

    # return the html
    return html

# Main script logic
if __name__ == "__main__":

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Take Semgrep findings input JSON files and output CSV, JSON, and HTML.')
    parser.add_argument('json_path', type=str, help='The file path to the findings.json file')
    parser.add_argument('repo_name', type=str, help='Repo Name')
    args = parser.parse_args()

    # Load JSON data from the provided file paths
    findings_data = load_json(args.json_path)
    findings_data = findings_data['results']

    df_findings_data = create_dataframes(findings_data)

    # Map severity values for each DataFrame
    df_findings_data = replace_severity(df_findings_data)

    filename= f"{args.repo_name}_semgrep"

    # Save the filtered DataFrames to CSV, JSON, and HTML
    save_output(df_findings_data, filename)

    html= save_html( df_findings_data)

    html_filename = f"{args.repo_name}_semgrep_result.html"

    # write the HTML content to an HTML file
    open(html_filename, "w").write(html)

    print("Filtered DataFrames with summary have been saved to CSV, JSON files, and an HTML file with tables.")
