#!/usr/bin/env python3
from textwrap import indent
from tetpyclient import RestClient
from json import loads, dumps
from tqdm import tqdm
from requests import Response
from urllib3 import disable_warnings
import pandas as pd
import json
import time
import argparse
from datetime import datetime

disable_warnings()

log_file = "csw-inventory.log"

DEBUG_ENABLED = False  # Change to False to disable logging. Change to True to enable logging

def timestamped_print(message):
    """Prints a message with a timestamp and logs it to the log file if debugging is enabled."""
    if DEBUG_ENABLED:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_message = f"{timestamp} - {message}"
        with open(log_file, "a") as log:
            log.write(log_message + "\n")

def pagination(api_uri_path, method, **kwargs):
    all_results = []
    try:
        response = method(api_uri_path, **kwargs)
        if response.status_code != 200:
            timestamped_print(f"Error accessing {api_uri_path}: {response.status_code} - {response.text}")
            return []

        # Initialize the tqdm progress bar with disable=True
        pbar = tqdm(unit="", desc=api_uri_path, disable=True)
        pbar.update()
        results = response.json()

        if isinstance(results, list):
            pbar.close()
            return results  # Return on list result
        elif isinstance(results, dict):
            if results.get('results'):
                all_results += results['results']
                timestamped_print(f"Progress: Retrieved {len(all_results)} results from {api_uri_path}.")
                pbar.update()
                while results.get("offset") and "post" in str(method.__func__):
                    next_page = results["offset"]
                    req_payload = loads(kwargs["json_body"])
                    req_payload["offset"] = next_page
                    kwargs["json_body"] = dumps(req_payload)
                    response = method(api_uri_path, **kwargs)
                    pbar.update()
                    results = response.json()
                    if results.get('results'):
                        all_results += results['results']
                        timestamped_print(f"Progress: Retrieved {len(all_results)} results from {api_uri_path}.")
            pbar.close()
            return all_results
        else:
            pbar.close()
            return []
    except Exception as e:
        timestamped_print(f"An error occurred in pagination: {e}")
        return []  # Return an empty list on error

def hit_api(uri_path, method, **kwargs):
    try:
        response = pagination(uri_path, method, **kwargs)

        if isinstance(response, Response):
            response = loads(response.text)

        if isinstance(response, list):
            return response
        elif isinstance(response, dict):
            return response.get("results", response)  # Return results or the entire response
        else:
            return response
    except Exception as e:
        timestamped_print(f"An error occurred while hitting the API: {e}")
        return []  # Return an empty list on error

def read_and_process_csv(filename):
    # Read the CSV file
    df = pd.read_csv(filename)
    timestamped_print(f"Loaded CSV file: {filename}")

    # Define the netmask to CIDR mapping
    netmask_to_cidr = {
        '255.255.255.255': '/32',
        '255.255.255.254': '/31',
        '255.255.255.252': '/30',
        '255.255.255.248': '/29',
        '255.255.255.240': '/28',
        '255.255.255.224': '/27',
        '255.255.255.192': '/26',
        '255.255.255.128': '/25',
        '255.255.255.0': '/24',
        '255.255.254.0': '/23',
        '255.255.252.0': '/22',
        '255.255.248.0': '/21',
        '255.255.240.0': '/20',
        '255.255.224.0': '/19',
        '255.255.192.0': '/18',
        '255.255.128.0': '/17',
        '255.255.0.0': '/16',
        '255.254.0.0': '/15',
        '255.252.0.0': '/14',
        '255.248.0.0': '/13',
        '255.240.0.0': '/12',
        '255.224.0.0': '/11',
        '255.192.0.0': '/10',
        '255.128.0.0': '/9',
        '255.0.0.0': '/8',
        '254.0.0.0': '/7',
        '252.0.0.0': '/6',
        '248.0.0.0': '/5',
        '240.0.0.0': '/4',
        '224.0.0.0': '/3',
        '192.0.0.0': '/2',
        '128.0.0.0': '/1',
        '0.0.0.0': '/0'
    }

    # Process each row to create the mappings field
    def process_row(row):
        ip = row['ip']
        netmask = row.get('netmask', '')

        # Check if IP contains a CIDR
        if '/' in ip:
            ip, cidr = ip.split('/')
            cidr = f'/{cidr}'
        else:
            cidr = None
        
        # If the netmask is empty or null, use CIDR value or default to /32
        if pd.isna(netmask) or netmask == '':
            netmask_cidr = cidr if cidr else '/32'
        else:
            netmask_cidr = netmask_to_cidr.get(netmask, '')

        # Create the mappings field
        mappings = f"{ip}{netmask_cidr}"
        return mappings

    # Apply the processing to create the mappings column
    df['mappings'] = df.apply(process_row, axis=1)

    # Select only the required columns
    df = df[['filter_name', 'mappings']]

    # Save the modified dataframe to a new CSV file
    output_filename = "processed_inventory_result.csv"
    df.to_csv(output_filename, index=False)
    timestamped_print(f"Processed data saved to {output_filename}")

    # Convert the dataframe to JSON format
    convert_to_json(df)

def convert_to_json(df):
    """Convert DataFrame to JSON format."""
    grouped = df.groupby('filter_name')['mappings'].apply(list).reset_index()

    json_data = []
    for _, row in grouped.iterrows():
        json_entry = {
            "name": row['filter_name'],
            "type": "DynamicObject",
            "objectType": "IP",
            "items": [{"mapping": mapping} for mapping in row['mappings']]
        }
        json_data.append(json_entry)

    output_json_filename = "csw_inventory_processing_dynamic_objects_mapping.json"
    with open(output_json_filename, 'w') as json_file:
        json.dump(json_data, json_file, indent=2)
    timestamped_print(f"Processed JSON data saved to {output_json_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()  # create parser
    parser.add_argument("cluster")
    parser.add_argument("filter_name")
    parser.add_argument("scope_name")
    args = parser.parse_args()  # parse the arguments

    api_endpoint = f"https://{args.cluster}"
    api_credentials = f"api-csw.json"

    try:
        rc = RestClient(api_endpoint, credentials_file=api_credentials, verify=False)
    except Exception as e:
        timestamped_print(f"Error initializing REST client: {e}")
        exit(1)

    # Main loop to run the script every 30 seconds
    while True:
        start_time = time.time()  # Track the start time of the iteration
        timestamped_print("Starting a new iteration...")  # Message at the start of the iteration

        try:
            filters = hit_api("/filters/inventories", rc.get)

            # Initialize the results list
            results = []

            for filter in filters:
                if filter["name"].startswith(args.filter_name):
                    timestamped_print(filter["query"])

                    req_payload = {
                        "filter": filter["query"],
                        "scopeName": args.scope_name
                    }

                    # Append inventory search result to the results list
                    result = hit_api("/inventory/search", rc.post, json_body=dumps(req_payload), pagination=True)

                    # Add filter_name to each result
                    for entry in result:
                        entry['filter_name'] = filter["name"]

                    results.extend(result)  # Append the result to the list

                    timestamped_print(dumps(result, indent=2))

            # Save the accumulated results to a CSV file
            if results:
                df = pd.DataFrame(results)
                filename = "inventory_result.csv"
                timestamped_print(f"Saving files to {filename}")
                df.sort_values(by=['filter_name']).to_csv(filename, index=False)
            else:
                timestamped_print("No results to save.")

            # Process the saved inventory_result.csv
            read_and_process_csv('inventory_result.csv')

        except Exception as global_error:
            timestamped_print(f"An error occurred in the main loop: {global_error}")

        end_time = time.time()  # Track the end time of the iteration
        iteration_time = end_time - start_time  # Calculate the time taken for the iteration
        timestamped_print(f"Iteration completed in {iteration_time:.2f} seconds.")

        # Wait for 30 seconds before the next execution
        timestamped_print("Waiting for 30 seconds before the next execution...")
        time.sleep(30)  # Adjusted to 30
