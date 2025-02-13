# csw-2-fmc-dyn-objects
This repo contains scripts to easily pull and process Secure Workload inventory filters objects to be pushed to FMC as Dynamic Objetcs for easy intent-based policy creation.

This project consists of two main Python scripts designed for processing inventory data from CSW and interacting with FMC dynamic objects. The scripts are:

* csw-inventory-processing.py
* fmc-dynobjects-push.py


## Dependencies
Before running these scripts, ensure you have the following dependencies installed:

Python 3.x
* requests
* pandas
* argparse
* tqdm
* tetpyclient

Additionally, you may need other dependencies for logging or JSON operations, which are built-in or installed with the above packages.


# Usage

## With-Filter
First run script csw-inventory-processing.py to generate the neccesary files (e.g csw_inventory_processing_dynamic_objects_mapping.json) for consumption by script fmc-dynobjects-push.py

Within the folder "with-filter" the script only searches for inventory filter objetcs with a pre-define prefix as input, and not all existing inventory filters in Secure Workload.

![Alt Text](https://github.com/jquintero17/csw-2-fmc-dyn-objects/blob/main/usage_example.gif)


### csw-inventory-processing.py
This script is used to fetch data from CSW (Cisco Secure Workload) filters and process the inventory information. By default it assumes the API key credentials file is within the same directory with name "api-csw.json".
```
./csw-inventory-processing.py <cluster> <filter_name> <scope_name>
```

Arguments:
* cluster: The cluster address of the CSW API. This is the URL of the SaaS Secure Workload Tenant or On-Prem Secure Workload Tenant
* filter_name: The filter name prefix to search for inventory filters. Only inventory filters with the prefix specificied will be pulled.
* scope_name: The Root Scope. This is the tenant name for SaaS clusters. For on-prem, this might be "Default", "Root" or the tenant name in use.

This is an example of the script being executed in background with a SaaS tenant named "csw-sbg" and using prefix inventory filter of "csw-fmc"
```
python3 csw-inventory-pulling.py csw-sbg.tetrationcloud.com csw-fmc csw-sbg &
```



### fmc-dynobjects-push.py
This script handles the synchronization of dynamic objects between the processed CSW (Cisco Secure Workload) inventory data and FMC (Firewall Management Center)

```
./fmc-dynobjects-push.py <username> <password> <ip_address> <prefix_filter>
```

Arguments:
* username: API username for accessing the FMC.
* password: Password for the API user.
* ip_address: IP address of the FMC.
* prefix_filter: A filter prefix to select specific dynamic object names.

This is an example of the script being executed in background with prefix csw-fmc
```
python3 fmc-dynobjects-push.py  csw-fmc-api SuperSecretPassword 192.168.1.1 csw-fmc &
```
## Without-Filter
First run script csw-all-inventory-processing.py to generate the neccesary files (e.g csw_inventory_processing_dynamic_objects_mapping.json) for consumption by script fmc-dynobjects-all-objects.py

The main difference with this version is that there is no prefix filter specify, which means the csw-all-inventory-processing.py will fetch all inventory filters from Secure Workload to be pushed to FMC. A note to consider is that the prefix "csw-fmc" is hardcoded with this code to differentiate objects coming from Secure Workload.
Note: Inventory Filters with Non-IP values are ignored.

```
./csw-all-inventory-processing.py <cluster> <scope_name>
```

```
./fmc-dynobjects-all-objects.py <username> <password> <ip_address>
```

## Files Generated

### By csw-inventory-processing.py:
* inventory_result.csv: Contains the raw data from the inventory search.
* processed_inventory_result.csv: The processed CSV output showing mappings.
* csw_inventory_processing_dynamic_objects_mapping.json: A JSON file representation of dynamic objects ready for synchronization.
* csw_inventory.log: log file capturing operations and actions taken by the script.

### By fmc-dynobjects-push.py:
* fmc_dynamic_objects_mappings_pushed.json: Shows JSON data with dynamic object mappings after modifications like additions or removals.
* fmc-dyn-objects-sync.log: A log file capturing the operations and actions taken by the script.
* filtered_dynamic_objects.json: file capturing the dynamic objects fetched from FMC.

## Logging
Both scripts offer debug logging capabilities, which can be enabled or disabled by adjusting the DEBUG_ENABLED and debug_mode flags respectively in each script.

## Important Notes
Ensure that your API credentials and connection settings for both CSW and FMC are correctly configured in their respective contexts.
Review and understand the implications of the data transformations as these scripts modify network data at an enterprise level.
These scripts are designed for continuous monitoring and periodic synchronization. Ensure your runtime environment can support potentially long-running processes.


## License
This project is licensed under the Apache License 2.0. Please refer to the file LICENSE in same directory of this README file.
