#!/usr/bin/python3
<<<<<<< HEAD
=======

>>>>>>> 7168aa9 (First commit to add files and scripts)
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
<<<<<<< HEAD
current_header = {}
=======
current_header = ***REMOVED******REMOVED***
>>>>>>> 7168aa9 (First commit to add files and scripts)

debug_mode = False  # Change to False to disable logging. Change to True to enable logging

def timestamped_print(message):
    """Logs a message with a timestamp only if debug mode is enabled."""
    if debug_mode:  # Only log if debug mode is enabled
<<<<<<< HEAD
        log_message = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}"
=======
        log_message = f"***REMOVED***datetime.now().strftime('%Y-%m-%d %H:%M:%S')***REMOVED*** - ***REMOVED***message***REMOVED***"
>>>>>>> 7168aa9 (First commit to add files and scripts)
        logging.info(log_message)  # Log to file


def save_json_to_file(filename, data):
    """Save JSON data to a file."""
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)
<<<<<<< HEAD
    timestamped_print(f"Saved data to {filename}")
=======
    timestamped_print(f"Saved data to ***REMOVED***filename***REMOVED***")
>>>>>>> 7168aa9 (First commit to add files and scripts)

def file_input():
    """Reads csw_inventory_processing_dynamic_objects_mapping.json and returns its contents."""
    with open('csw_inventory_processing_dynamic_objects_mapping.json', 'r') as file:
        data = json.load(file)
<<<<<<< HEAD
    timestamped_print(f"file_input: Loaded data from csw_inventory_processing_dynamic_objects_mapping.json: {data}")
=======
    timestamped_print(f"file_input: Loaded data from csw_inventory_processing_dynamic_objects_mapping.json: ***REMOVED***data***REMOVED***")
>>>>>>> 7168aa9 (First commit to add files and scripts)
    return data

def compare_dynamic_objects(current_data, previous_data):
    """Compare the current data with previous data and return the differences."""
<<<<<<< HEAD
    current_names = {obj['name'] for obj in current_data}
    previous_names = {obj['name'] for obj in previous_data}

    added = current_names - previous_names
    removed = previous_names - current_names
    timestamped_print(f"compare_dynamic_objects: Added: {added}, Removed: {removed}")
=======
    current_names = ***REMOVED***obj['name'] for obj in current_data***REMOVED***
    previous_names = ***REMOVED***obj['name'] for obj in previous_data***REMOVED***

    added = current_names - previous_names
    removed = previous_names - current_names
    timestamped_print(f"compare_dynamic_objects: Added: ***REMOVED***added***REMOVED***, Removed: ***REMOVED***removed***REMOVED***")
>>>>>>> 7168aa9 (First commit to add files and scripts)
    return added, removed

def get_token(fmcIP, path, username, password):
    try:
<<<<<<< HEAD
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
=======
        r = requests.post(f"https://***REMOVED***fmcIP***REMOVED******REMOVED***path***REMOVED***", auth=(username, password), verify=False)
        r.raise_for_status()
        access_token = r.headers.get('X-auth-access-token')
        refresh_token = r.headers.get('X-auth-refresh-token')
        timestamped_print(f"get_token: Obtained tokens - Access Token: ***REMOVED***access_token***REMOVED***, Refresh Token: ***REMOVED***refresh_token***REMOVED***")
    except requests.exceptions.HTTPError as errh:
        timestamped_print(f"HTTP error occurred: ***REMOVED***errh***REMOVED***")  # Log error
        raise SystemExit(errh)
    except requests.exceptions.RequestException as err:
        timestamped_print(f"Request error occurred: ***REMOVED***err***REMOVED***")  # Log error
        raise SystemExit(err)

    required_headers = ('X-auth-access-token', 'X-auth-refresh-token', 'DOMAIN_UUID')
    result = ***REMOVED***key: r.headers.get(key) for key in required_headers***REMOVED***
>>>>>>> 7168aa9 (First commit to add files and scripts)
    
    return result

def refresh_token(fmcIP, path, username, password):
    global current_header
    while True:
        try:
            current_header = get_token(fmcIP, path, username, password)
            timestamped_print("Token refreshed successfully.")
        except Exception as e:
<<<<<<< HEAD
            timestamped_print(f"Error refreshing token: {e}")
=======
            timestamped_print(f"Error refreshing token: ***REMOVED***e***REMOVED***")
>>>>>>> 7168aa9 (First commit to add files and scripts)
        finally:
            time.sleep(1200)  # 20 minutes

def hit_api(uri_path, method, **kwargs):
    """Makes an API call and logs the relevant details including tokens."""
    # Print the access and refresh tokens
    access_token = kwargs['headers'].get('X-auth-access-token')
    refresh_token = kwargs['headers'].get('X-auth-refresh-token')
    
<<<<<<< HEAD
    timestamped_print(f"Requesting {uri_path} with headers: {kwargs['headers']}")
    timestamped_print(f"Using Access Token: {access_token} and Refresh Token: {refresh_token}")
=======
    timestamped_print(f"Requesting ***REMOVED***uri_path***REMOVED*** with headers: ***REMOVED***kwargs['headers']***REMOVED***")
    timestamped_print(f"Using Access Token: ***REMOVED***access_token***REMOVED*** and Refresh Token: ***REMOVED***refresh_token***REMOVED***")
>>>>>>> 7168aa9 (First commit to add files and scripts)
    
    response = method(uri_path, **kwargs)
    response.raise_for_status()
    try:
        data = response.json()
    except json.JSONDecodeError:
        raise ValueError("Response content is not valid JSON")
<<<<<<< HEAD
    timestamped_print(f"hit_api: Received response from {uri_path}: {data}")
=======
    timestamped_print(f"hit_api: Received response from ***REMOVED***uri_path***REMOVED***: ***REMOVED***data***REMOVED***")
>>>>>>> 7168aa9 (First commit to add files and scripts)
    return data
    

def fetch_all_mappings(fmcIP, current_header, object_id):
    """Fetch all mappings for a specified dynamic object ID considering pagination."""
    all_mappings = []
    offset = 0
    limit = 25  # Default limit for API pagination

    try:
        while True:
<<<<<<< HEAD
            path = f"/api/fmc_config/v1/domain/{current_header['DOMAIN_UUID']}/object/dynamicobjects/{object_id}/mappings?offset={offset}&limit={limit}"
            timestamped_print(f"Fetching mappings from URL: {path}")
            response = hit_api(f"https://{fmcIP}{path}", requests.get, headers=current_header, verify=False)
=======
            path = f"/api/fmc_config/v1/domain/***REMOVED***current_header['DOMAIN_UUID']***REMOVED***/object/dynamicobjects/***REMOVED***object_id***REMOVED***/mappings?offset=***REMOVED***offset***REMOVED***&limit=***REMOVED***limit***REMOVED***"
            timestamped_print(f"Fetching mappings from URL: ***REMOVED***path***REMOVED***")
            response = hit_api(f"https://***REMOVED***fmcIP***REMOVED******REMOVED***path***REMOVED***", requests.get, headers=current_header, verify=False)
>>>>>>> 7168aa9 (First commit to add files and scripts)

            if isinstance(response, dict) and 'items' in response:
                items = response['items']
                all_mappings.extend(items)
<<<<<<< HEAD
                paging = response.get('paging', {})
=======
                paging = response.get('paging', ***REMOVED******REMOVED***)
>>>>>>> 7168aa9 (First commit to add files and scripts)
                if len(items) < limit or offset + limit >= paging.get('count', 0):
                    break
                offset += limit
            else:
                timestamped_print("No mappings found or unexpected response format.")
                break
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
<<<<<<< HEAD
            timestamped_print(f"Dynamic object ID {object_id} was not found. Skipping.")
            return []  # Return an empty list if the object ID is not found
        else:
            timestamped_print(f"HTTP error occurred: {e}")
=======
            timestamped_print(f"Dynamic object ID ***REMOVED***object_id***REMOVED*** was not found. Skipping.")
            return []  # Return an empty list if the object ID is not found
        else:
            timestamped_print(f"HTTP error occurred: ***REMOVED***e***REMOVED***")
>>>>>>> 7168aa9 (First commit to add files and scripts)
            return []  # Continue execution

    return all_mappings

def normalize_ip(ip):
    if '/' not in ip:
<<<<<<< HEAD
        return f"{ip}/32"
=======
        return f"***REMOVED***ip***REMOVED***/32"
>>>>>>> 7168aa9 (First commit to add files and scripts)
    return ip

def compare_and_sync(file_data, filtered_objects, fmcIP, current_header, added_names, removed_names):
    """Compares file data with filtered_objects and makes necessary API calls."""
<<<<<<< HEAD
    file_names = {obj['name'] for obj in file_data}
    api_names = {obj['name'] for obj in filtered_objects}
=======
    file_names = ***REMOVED***obj['name'] for obj in file_data***REMOVED***
    api_names = ***REMOVED***obj['name'] for obj in filtered_objects***REMOVED***
>>>>>>> 7168aa9 (First commit to add files and scripts)

    positive_diff_names = file_names - api_names
    negative_diff_names = api_names - file_names

<<<<<<< HEAD
    timestamped_print(f"compare_and_sync: Positive diff names: {positive_diff_names}, Negative diff names: {negative_diff_names}")
=======
    timestamped_print(f"compare_and_sync: Positive diff names: ***REMOVED***positive_diff_names***REMOVED***, Negative diff names: ***REMOVED***negative_diff_names***REMOVED***")
>>>>>>> 7168aa9 (First commit to add files and scripts)

    # Handle removals
    if negative_diff_names:
        ids_to_remove = [obj['id'] for obj in filtered_objects if obj['name'] in negative_diff_names]
        if ids_to_remove:
            ids_filter = ','.join(ids_to_remove)
<<<<<<< HEAD
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
=======
            path = f"/api/fmc_config/v1/domain/***REMOVED***current_header['DOMAIN_UUID']***REMOVED***/object/dynamicobjects?filter=ids%3A***REMOVED***ids_filter***REMOVED***&bulk=true"
            
            try:
                response = requests.delete(f"https://***REMOVED***fmcIP***REMOVED******REMOVED***path***REMOVED***", headers=current_header, verify=False)
                response.raise_for_status()  # Raises an error for responses with status codes 4xx/5xx
                timestamped_print(f"compare_and_sync: Sent remove request for IDs: ***REMOVED***ids_to_remove***REMOVED***")
            except requests.exceptions.HTTPError as errh:
                timestamped_print(f"HTTP error occurred during removal: ***REMOVED***errh***REMOVED***")
            except requests.exceptions.RequestException as err:
                timestamped_print(f"Request error occurred during removal: ***REMOVED***err***REMOVED***")

    # Handle additions
    if positive_diff_names:
        path = f"/api/fmc_config/v1/domain/***REMOVED***current_header['DOMAIN_UUID']***REMOVED***/object/dynamicobjects?bulk=true"
>>>>>>> 7168aa9 (First commit to add files and scripts)
        add_payload = []  # Initialize payload as a list for adding objects

        for new_name in positive_diff_names:
            file_obj = next((obj for obj in file_data if obj['name'] == new_name), None)
            if file_obj:
<<<<<<< HEAD
                timestamped_print(f"Adding new dynamic object: {new_name}")
                add_payload.append({
=======
                timestamped_print(f"Adding new dynamic object: ***REMOVED***new_name***REMOVED***")
                add_payload.append(***REMOVED***
>>>>>>> 7168aa9 (First commit to add files and scripts)
                    "name": file_obj['name'],       
                    "type": "DynamicObject",         
                    "objectType": "IP",              
                    # Add any additional required fields here if needed
<<<<<<< HEAD
                })

        timestamped_print(f"Adding dynamic objects with payload: {json.dumps(add_payload, indent=4)}")  # Pretty print JSON
=======
                ***REMOVED***)

        timestamped_print(f"Adding dynamic objects with payload: ***REMOVED***json.dumps(add_payload, indent=4)***REMOVED***")  # Pretty print JSON
>>>>>>> 7168aa9 (First commit to add files and scripts)

        # Attempt to add new objects
        if add_payload:  # Check if there are any objects to add
            try:
<<<<<<< HEAD
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
=======
                response = requests.post(f"https://***REMOVED***fmcIP***REMOVED******REMOVED***path***REMOVED***", headers=current_header, json=add_payload, verify=False)
                response.raise_for_status()
                timestamped_print(f"compare_and_sync: Successfully added objects: ***REMOVED***add_payload***REMOVED***")
            except requests.exceptions.HTTPError as errh:
                timestamped_print(f"HTTP error occurred during add: ***REMOVED***errh***REMOVED***")
                if response:
                    timestamped_print(f"Response status code: ***REMOVED***response.status_code***REMOVED***")  # Log the code
                    timestamped_print(f"Response content: ***REMOVED***response.content.decode()***REMOVED***")  # Log the content of the error response
            except requests.exceptions.RequestException as err:
                timestamped_print(f"Request error occurred during add: ***REMOVED***err***REMOVED***")

    # Prepare path for addition/updating dynamic object mappings before the loop
    path = f"/api/fmc_config/v1/domain/***REMOVED***current_header['DOMAIN_UUID']***REMOVED***/object/dynamicobjectmappings"

    # Handle additions/updates
    add_payload = ***REMOVED***
        "add": [],
        "remove": []
    ***REMOVED***
>>>>>>> 7168aa9 (First commit to add files and scripts)

    for obj in filtered_objects:
        # Fetch all mappings for the dynamic object
        mappings = fetch_all_mappings(fmcIP, current_header, obj['id'])
<<<<<<< HEAD
        api_mappings = {normalize_ip(item['mapping']) for item in mappings}  # Normalize API mappings
=======
        api_mappings = ***REMOVED***normalize_ip(item['mapping']) for item in mappings***REMOVED***  # Normalize API mappings
>>>>>>> 7168aa9 (First commit to add files and scripts)

        # Find the corresponding file object
        file_obj = next((file_obj for file_obj in file_data if file_obj['name'] == obj['name']), None)

        if file_obj:
<<<<<<< HEAD
            file_mappings = {normalize_ip(item['mapping']) for item in file_obj.get('items', [])}  # Normalize file mappings
=======
            file_mappings = ***REMOVED***normalize_ip(item['mapping']) for item in file_obj.get('items', [])***REMOVED***  # Normalize file mappings
>>>>>>> 7168aa9 (First commit to add files and scripts)

            # Determine mapping differences
            positive_diff_mappings = file_mappings - api_mappings
            negative_diff_mappings = api_mappings - file_mappings

<<<<<<< HEAD
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
=======
            timestamped_print(f"API mappings: ***REMOVED***api_mappings***REMOVED***, File mappings: ***REMOVED***file_mappings***REMOVED***")
            timestamped_print(f"Positive diff mappings for ***REMOVED***obj['name']***REMOVED***: ***REMOVED***positive_diff_mappings***REMOVED***")
            timestamped_print(f"Negative diff mappings for ***REMOVED***obj['name']***REMOVED***: ***REMOVED***negative_diff_mappings***REMOVED***")

            # Prepare the payloads for changes
            if positive_diff_mappings:
                timestamped_print(f"Adding positive diff mappings to add_payload for ***REMOVED***obj['name']***REMOVED***.")
                add_payload["add"].append(***REMOVED***
                    "mappings": list(positive_diff_mappings),
                    "dynamicObject": ***REMOVED***"name": obj['name'], "type": "DynamicObject"***REMOVED***
                ***REMOVED***)
            if negative_diff_mappings:
                timestamped_print(f"Adding negative diff mappings to remove_payload for ***REMOVED***obj['name']***REMOVED***.")
                add_payload["remove"].append(***REMOVED***
                    "mappings": list(negative_diff_mappings),
                    "dynamicObject": ***REMOVED***"name": obj['name'], "type": "DynamicObject"***REMOVED***
                ***REMOVED***)
>>>>>>> 7168aa9 (First commit to add files and scripts)
    
    if add_payload["add"] or add_payload["remove"]:
        # Save the update payload to a JSON file
        save_json_to_file('fmc_dynamic_objects_mappings_pushed.json', add_payload)
        try:
<<<<<<< HEAD
            response = requests.post(f"https://{fmcIP}{path}", headers=current_header, json=add_payload, verify=False)
            response.raise_for_status()
            response_data = response.json()
            timestamped_print(f"compare_and_sync: Sent add/update request with payload: {add_payload}, Response: {response_data}")
        except requests.exceptions.HTTPError as errh:
            timestamped_print(f"HTTP error occurred during add/update: {errh}") 
        except requests.exceptions.RequestException as err:
            timestamped_print(f"Request error occurred during add/update: {err}")
=======
            response = requests.post(f"https://***REMOVED***fmcIP***REMOVED******REMOVED***path***REMOVED***", headers=current_header, json=add_payload, verify=False)
            response.raise_for_status()
            response_data = response.json()
            timestamped_print(f"compare_and_sync: Sent add/update request with payload: ***REMOVED***add_payload***REMOVED***, Response: ***REMOVED***response_data***REMOVED***")
        except requests.exceptions.HTTPError as errh:
            timestamped_print(f"HTTP error occurred during add/update: ***REMOVED***errh***REMOVED***") 
        except requests.exceptions.RequestException as err:
            timestamped_print(f"Request error occurred during add/update: ***REMOVED***err***REMOVED***")
>>>>>>> 7168aa9 (First commit to add files and scripts)
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
<<<<<<< HEAD
            path = f"/api/fmc_config/v1/domain/{current_header['DOMAIN_UUID']}/object/dynamicobjects"
            response = hit_api(f"https://{fmcIP}{path}", requests.get, headers=current_header, verify=False)
=======
            path = f"/api/fmc_config/v1/domain/***REMOVED***current_header['DOMAIN_UUID']***REMOVED***/object/dynamicobjects"
            response = hit_api(f"https://***REMOVED***fmcIP***REMOVED******REMOVED***path***REMOVED***", requests.get, headers=current_header, verify=False)
>>>>>>> 7168aa9 (First commit to add files and scripts)

            if isinstance(response, dict) and 'items' in response:
                dynamic_objects = response['items']
            else:
                raise ValueError("Unexpected response format")

            # Filter objects based on prefix_filter
            filtered_objects = [obj for obj in dynamic_objects if obj.get('name', '').startswith(prefix_filter)]
<<<<<<< HEAD
            timestamped_print(f"Main: Filtered objects: {filtered_objects}")
=======
            timestamped_print(f"Main: Filtered objects: ***REMOVED***filtered_objects***REMOVED***")
>>>>>>> 7168aa9 (First commit to add files and scripts)

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
<<<<<<< HEAD
            timestamped_print(f"Iteration completed in {elapsed_time:.2f} seconds.")
=======
            timestamped_print(f"Iteration completed in ***REMOVED***elapsed_time:.2f***REMOVED*** seconds.")
>>>>>>> 7168aa9 (First commit to add files and scripts)

            # Wait for 30 seconds before the next execution
            time.sleep(30)
        except requests.exceptions.HTTPError as errh:
<<<<<<< HEAD
            timestamped_print(f"HTTP error occurred: {errh}")  # Log error
        except requests.exceptions.RequestException as err:
            timestamped_print(f"Request error occurred: {err}")  # Log error
        except Exception as e:
            timestamped_print(f"An unexpected error occurred: {e}")  # Log any unexpected errors
=======
            timestamped_print(f"HTTP error occurred: ***REMOVED***errh***REMOVED***")  # Log error
        except requests.exceptions.RequestException as err:
            timestamped_print(f"Request error occurred: ***REMOVED***err***REMOVED***")  # Log error
        except Exception as e:
            timestamped_print(f"An unexpected error occurred: ***REMOVED***e***REMOVED***")  # Log any unexpected errors
>>>>>>> 7168aa9 (First commit to add files and scripts)
