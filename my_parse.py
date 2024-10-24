import fetch
import pandas as pd
import argparse
import pdb
from fetch import fetch_urls


def main(csv_file, link_file):
    dataframe = pd.read_csv(csv_file)
    all_projects = dataframe['fix_version'].unique()

    with open(link_file, 'w') as f:
        for project in all_projects:
            if 'linux' in project:
                continue
            url = fetch_urls(project)
            if url == None:
                continue
            f.write(f"{url}\n")
         



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a csv and save state")

    # Add argument to accept a file path
    parser.add_argument('--input_file', type=str, help='Path to the input csv file')
    parser.add_argument('--output_file', type=str, help='Path to the output link file')

    # Parse the command-line arguments
    args = parser.parse_args()
    main(args.input_file, args.output_file)
