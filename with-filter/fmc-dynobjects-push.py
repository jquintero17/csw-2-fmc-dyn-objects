#!/usr/bin/python3

import argparse
import json
import requests
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import threading
import logging

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set up logging to file
logging.basicConfig(filename='fmc-dyn-objects-sync.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variable to hold the current header/token
current_header = {}

debug_mode = False  # Change to False to disable logging. Change to True to enable logging

def timestamped_print(message):
    """Logs a message with a timestamp only if debug mode is enabled."""
    if debug_mode:  # Only log if debug mode is enabled
        log_message = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}"
        logging.info(log_message)  # Log to file


def save_json_to_file(filename, data):
    """Save JSON data to a file."""
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)
    timestamped_print(f"Saved data to {filename}")

def file_input():
    """Reads csw_inventory_processing_dynamic_objects_mapping.json and returns its contents."""
    with open('csw_inventory_processing_dynamic_objects_mapping.json', 'r') as file:
        data = json.load(file)
    timestamped_print(f"file_input: Loaded data from csw_inventory_processing_dynamic_objects_mapping.json: {data}")
    return data

def compare_dynamic_objects(current_data, previous_data):
    """Compare the current data with previous data and return the differences."""
    current_names = {obj['name'] for obj in current_data}
    previous_names = {obj['name'] for obj in previous_data}

    added = current_names - previous_names
    removed = previous_names - current_names
    timestamped_print(f"compare_dynamic_objects: Added: {added}, Removed: {removed}")
    return added, removed

def get_token(fmcIP, path, username, password):
    try:
        r = requests.post(f"https://{fmcIP}{path}", auth=(username, password), verify=False)
        r.raise_for_status()
        access_token = r.headers.get('X-auth-access-token')
        refresh_token = r.headers.get('X-auth-refresh-token')
        timestamped_print(f"get_token: Obtained tokens - Access Token: {access_token}, Refresh Token: {refresh_token}")
    except requests.exceptions.HTTPError as errh:
        timestamped_print(f"HTTP error occurred: {errh}")  # Log error
        raise SystemExit(errh)
    except requests.exceptions.RequestException as err:
        timestamped_print(f"Request error occurred: {err}")  # Log error
        raise SystemExit(err)

    required_headers = ('X-auth-access-token', 'X-auth-refresh-token', 'DOMAIN_UUID')
    result = {key: r.headers.get(key) for key in required_headers}
    
    return result

def refresh_token(fmcIP, path, username, password):
    global current_header
    while True:
        try:
            current_header = get_token(fmcIP, path, username, password)
            timestamped_print("Token refreshed successfully.")
        except Exception as e:
            timestamped_print(f"Error refreshing token: {e}")
        finally:
            time.sleep(1200)  # 20 minutes

def hit_api(uri_path, method, **kwargs):
    """Makes an API call and logs the relevant details including tokens."""
    # Print the access and refresh tokens
    access_token = kwargs['headers'].get('X-auth-access-token')
    refresh_token = kwargs['headers'].get('X-auth-refresh-token')
    
    timestamped_print(f"Requesting {uri_path} with headers: {kwargs['headers']}")
    timestamped_print(f"Using Access Token: {access_token} and Refresh Token: {refresh_token}")
    
    response = method(uri_path, **kwargs)
    response.raise_for_status()
    try:
        data = response.json()
    except json.JSONDecodeError:
        raise ValueError("Response content is not valid JSON")
    timestamped_print(f"hit_api: Received response from {uri_path}: {data}")
    return data
    

def fetch_all_mappings(fmcIP, current_header, object_id):
    """Fetch all mappings for a specified dynamic object ID considering pagination."""
    all_mappings = []
    offset = 0
    limit = 25  # Default limit for API pagination

    try:
        while True:
            path = f"/api/fmc_config/v1/domain/{current_header['DOMAIN_UUID']}/object/dynamicobjects/{object_id}/mappings?offset={offset}&limit={limit}"
            timestamped_print(f"Fetching mappings from URL: {path}")
            response = hit_api(f"https://{fmcIP}{path}", requests.get, headers=current_header, verify=False)

            if isinstance(response, dict) and 'items' in response:
                items = response['items']
                all_mappings.extend(items)
                paging = response.get('paging', {})
                if len(items) < limit or offset + limit >= paging.get('count', 0):
                    break
                offset += limit
            else:
                timestamped_print("No mappings found or unexpected response format.")
                break
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            timestamped_print(f"Dynamic object ID {object_id} was not found. Skipping.")
            return []  # Return an empty list if the object ID is not found
        else:
            timestamped_print(f"HTTP error occurred: {e}")
            return []  # Continue execution

    return all_mappings

def normalize_ip(ip):
    if '/' not in ip:
        return f"{ip}/32"
    return ip

def compare_and_sync(file_data, filtered_objects, fmcIP, current_header, added_names, removed_names):
    """Compares file data with filtered_objects and makes necessary API calls."""
    file_names = {obj['name'] for obj in file_data}
    api_names = {obj['name'] for obj in filtered_objects}

    positive_diff_names = file_names - api_names
    negative_diff_names = api_names - file_names

    timestamped_print(f"compare_and_sync: Positive diff names: {positive_diff_names}, Negative diff names: {negative_diff_names}")

    # Handle removals
    if negative_diff_names:
        ids_to_remove = [obj['id'] for obj in filtered_objects if obj['name'] in negative_diff_names]
        if ids_to_remove:
            ids_filter = ','.join(ids_to_remove)
            path = f"/api/fmc_config/v1/domain/{current_header['DOMAIN_UUID']}/object/dynamicobjects?filter=ids%3A{ids_filter}&bulk=true"
            
            try:
                response = requests.delete(f"https://{fmcIP}{path}", headers=current_header, verify=False)
                response.raise_for_status()  # Raises an error for responses with status codes 4xx/5xx
                timestamped_print(f"compare_and_sync: Sent remove request for IDs: {ids_to_remove}")
            except requests.exceptions.HTTPError as errh:
                timestamped_print(f"HTTP error occurred during removal: {errh}")
            except requests.exceptions.RequestException as err:
                timestamped_print(f"Request error occurred during removal: {err}")

    # Handle additions
    if positive_diff_names:
        path = f"/api/fmc_config/v1/domain/{current_header['DOMAIN_UUID']}/object/dynamicobjects?bulk=true"
        add_payload = []  # Initialize payload as a list for adding objects

        for new_name in positive_diff_names:
            file_obj = next((obj for obj in file_data if obj['name'] == new_name), None)
            if file_obj:
                timestamped_print(f"Adding new dynamic object: {new_name}")
                add_payload.append({
                    "name": file_obj['name'],       
                    "type": "DynamicObject",         
                    "objectType": "IP",              
                    # Add any additional required fields here if needed
                })

        timestamped_print(f"Adding dynamic objects with payload: {json.dumps(add_payload, indent=4)}")  # Pretty print JSON

        # Attempt to add new objects
        if add_payload:  # Check if there are any objects to add
            try:
                response = requests.post(f"https://{fmcIP}{path}", headers=current_header, json=add_payload, verify=False)
                response.raise_for_status()
                timestamped_print(f"compare_and_sync: Successfully added objects: {add_payload}")
            except requests.exceptions.HTTPError as errh:
                timestamped_print(f"HTTP error occurred during add: {errh}")
                if response:
                    timestamped_print(f"Response status code: {response.status_code}")  # Log the code
                    timestamped_print(f"Response content: {response.content.decode()}")  # Log the content of the error response
            except requests.exceptions.RequestException as err:
                timestamped_print(f"Request error occurred during add: {err}")

    # Prepare path for addition/updating dynamic object mappings before the loop
    path = f"/api/fmc_config/v1/domain/{current_header['DOMAIN_UUID']}/object/dynamicobjectmappings"

    # Handle additions/updates
    add_payload = {
        "add": [],
        "remove": []
    }

    for obj in filtered_objects:
        # Fetch all mappings for the dynamic object
        mappings = fetch_all_mappings(fmcIP, current_header, obj['id'])
        api_mappings = {normalize_ip(item['mapping']) for item in mappings}  # Normalize API mappings

        # Find the corresponding file object
        file_obj = next((file_obj for file_obj in file_data if file_obj['name'] == obj['name']), None)

        if file_obj:
            file_mappings = {normalize_ip(item['mapping']) for item in file_obj.get('items', [])}  # Normalize file mappings

            # Determine mapping differences
            positive_diff_mappings = file_mappings - api_mappings
            negative_diff_mappings = api_mappings - file_mappings

            timestamped_print(f"API mappings: {api_mappings}, File mappings: {file_mappings}")
            timestamped_print(f"Positive diff mappings for {obj['name']}: {positive_diff_mappings}")
            timestamped_print(f"Negative diff mappings for {obj['name']}: {negative_diff_mappings}")

            # Prepare the payloads for changes
            if positive_diff_mappings:
                timestamped_print(f"Adding positive diff mappings to add_payload for {obj['name']}.")
                add_payload["add"].append({
                    "mappings": list(positive_diff_mappings),
                    "dynamicObject": {"name": obj['name'], "type": "DynamicObject"}
                })
            if negative_diff_mappings:
                timestamped_print(f"Adding negative diff mappings to remove_payload for {obj['name']}.")
                add_payload["remove"].append({
                    "mappings": list(negative_diff_mappings),
                    "dynamicObject": {"name": obj['name'], "type": "DynamicObject"}
                })
    
    if add_payload["add"] or add_payload["remove"]:
        # Save the update payload to a JSON file
        save_json_to_file('fmc_dynamic_objects_mappings_pushed.json', add_payload)
        try:
            response = requests.post(f"https://{fmcIP}{path}", headers=current_header, json=add_payload, verify=False)
            response.raise_for_status()
            response_data = response.json()
            timestamped_print(f"compare_and_sync: Sent add/update request with payload: {add_payload}, Response: {response_data}")
        except requests.exceptions.HTTPError as errh:
            timestamped_print(f"HTTP error occurred during add/update: {errh}") 
        except requests.exceptions.RequestException as err:
            timestamped_print(f"Request error occurred during add/update: {err}")
        except json.JSONDecodeError:
            timestamped_print("Error decoding response JSON")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("username", type=str, help="API username")
    parser.add_argument("password", type=str, help="Password of API user")
    parser.add_argument("ip_address", type=str, help="IP of FMC")
    parser.add_argument("prefix_filter", type=str, help="Substring filter for dynamic object names")
    args = parser.parse_args()

    username = args.username
    password = args.password
    fmcIP = args.ip_address
    prefix_filter = args.prefix_filter
    path = "/api/fmc_platform/v1/auth/generatetoken"

    # Get the initial token
    current_header = get_token(fmcIP, path, username, password)

    # Start the token refresh thread
    token_thread = threading.Thread(target=refresh_token, args=(fmcIP, path, username, password), daemon=True)
    token_thread.start()

    # Initialize previous file data
    previous_file_data = []

    while True:
        timestamped_print("Starting new iteration...")  # New iteration message
        start_time = time.time()  # Start timing the iteration
        
        try:
            path = f"/api/fmc_config/v1/domain/{current_header['DOMAIN_UUID']}/object/dynamicobjects"
            response = hit_api(f"https://{fmcIP}{path}", requests.get, headers=current_header, verify=False)

            if isinstance(response, dict) and 'items' in response:
                dynamic_objects = response['items']
            else:
                raise ValueError("Unexpected response format")

            # Filter objects based on prefix_filter
            filtered_objects = [obj for obj in dynamic_objects if obj.get('name', '').startswith(prefix_filter)]
            timestamped_print(f"Main: Filtered objects: {filtered_objects}")

            # Read file and compare
            file_data = file_input()

            # Compare current with previous and get added and removed names
            added_names, removed_names = compare_dynamic_objects(file_data, previous_file_data)

            # Pass added and removed names to compare_and_sync
            compare_and_sync(file_data, filtered_objects, fmcIP, current_header, added_names, removed_names)

            # Update previous_file_data for the next iteration
            previous_file_data = file_data

            end_time = time.time()  # End timing the iteration
            elapsed_time = end_time - start_time  # Calculate elapsed time
            timestamped_print(f"Iteration completed in {elapsed_time:.2f} seconds.")

            # Wait for 30 seconds before the next execution
            time.sleep(30)
        except requests.exceptions.HTTPError as errh:
            timestamped_print(f"HTTP error occurred: {errh}")  # Log error
        except requests.exceptions.RequestException as err:
            timestamped_print(f"Request error occurred: {err}")  # Log error
        except Exception as e:
            timestamped_print(f"An unexpected error occurred: {e}")  # Log any unexpected errors