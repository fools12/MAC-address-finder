from orionsdk import SwisClient
import re
import paramiko
import requests
import urllib3
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

mac_address_info = None

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to convert MAC address to XX:XX:XX:XX:XX:XX format
def convert_mac_address(mac_address):
    mac_address = re.sub(r'[^a-fA-F0-9]', '', mac_address)
    if len(mac_address) != 12:
        return "Invalid MAC address length"
    return ':'.join([mac_address[i:i+2] for i in range(0, 12, 2)])

# Function to get input from the user and convert MAC address
def get_user_mac():
    user_mac_input = input("Enter MAC address: ")
    return convert_mac_address(user_mac_input)

# Function to connect to SolarWinds and store the list
def connect_to_solarwinds(hostname, username, password, vendors, exclude_strings):
    switches = []
    swis = SwisClient(hostname, username, password)
    query = """
    SELECT N.SysName AS SwitchName, N.IPAddress AS IPAddress, N.Vendor AS VendorType
    FROM Orion.Nodes N
    WHERE N.Vendor IN @vendors
    """
    for i, exclude_string in enumerate(exclude_strings):
        query += "AND NOT (N.SysName LIKE '%' + @exclude_string{} + '%')".format(i)
    query += "ORDER BY N.Vendor, N.SysName"
    parameters = {'vendors': vendors}
    for i, exclude_string in enumerate(exclude_strings):
        parameters['exclude_string{}'.format(i)] = exclude_string
    results = swis.query(query, **parameters)
    for row in results['results']:
        switches.append({
            'SwitchName': row['SwitchName'],
            'IPAddress': row['IPAddress'],
            'VendorType': row['VendorType']
        })
    return switches

def parse_aruba_output(output, formatted_mac, switch_name, switch_ip):
    if "No MAC entries found." in output:
        return None
    if formatted_mac.lower() in output.lower():
        lines = output.splitlines()
        for line in lines:
            if formatted_mac.lower() in line.lower():
                columns = line.split()
                try:
                    port = columns[-1]
                    if "po" in port.lower() or "lag" in port.lower():
                        continue
                    info = f"MAC Address {formatted_mac} found on {switch_name} (IP: {switch_ip}) at port {port}."
                    return info
                except IndexError:
                    print(f"MAC Address {formatted_mac} information could not be fully parsed on {switch_name}.")
                    return None
        else:
            print(f"MAC address {formatted_mac} found in output but could not be parsed on {switch_name}.")
            return None
    return None

def parse_cisco_output(output, formatted_mac, switch_name, switch_ip):
    if "Total Mac Addresses for this criterion" in output:
        lines = output.splitlines()
        for line in lines:
            mac_pattern = re.compile(r'([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})')
            mac_match = mac_pattern.search(line)
            if mac_match:
                mac_address = mac_match.group().replace('.', '').lower()
                if formatted_mac.replace(':', '').lower() == mac_address:
                    parts = line.split()
                    if len(parts) > 3:
                        port = parts[-1]
                        if "po" in port.lower() or "lag" in port.lower():
                            continue
                        info = f"MAC Address {formatted_mac} found on {switch_name} (IP: {switch_ip}) at port {port}."
                        return info
    return None

# Function to convert other MAC formats to xx:xx format
def convert_to_xx_xx(mac):
    mac = mac.replace("-", "").replace(".", "").upper()
    formatted_mac = ':'.join(mac[i:i+2] for i in range(0, len(mac), 2))
    return formatted_mac

def get_mac_info_thread(switch, formatted_mac):
    global mac_address_info  # Declare the global variable
    if mac_address_info:  # Check if MAC address is already found
        return
    switch_name = switch['SwitchName']
    switch_ip = switch['IPAddress']
    vendor_type = switch['VendorType']
    print(f"Checking {switch_name}...")
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(hostname=switch_ip, username='Jabba', password='thehut321!', timeout=10)
        if vendor_type == "Aruba Networks Inc":
            command = f"sh mac-address-table address {formatted_mac}"
        elif vendor_type == "Cisco":
            command = f"sh mac address-table address {formatted_mac}"
        else:
            print(f"Unsupported vendor type: {vendor_type}")
            ssh_client.close()  # Close the SSH connection
            return

        _, stdout, _ = ssh_client.exec_command(command)
        output = stdout.read().decode('utf-8')

        if vendor_type == "Aruba Networks Inc":
            info = parse_aruba_output(output, formatted_mac, switch_name, switch_ip)
            if info:
                mac_address_info = info
                print_mac_address_found_info(info)  # Print nicely formatted MAC address found message
        elif vendor_type == "Cisco":
            info = parse_cisco_output(output, formatted_mac, switch_name, switch_ip)
            if info:
                mac_address_info = info
                print_mac_address_found_info(info)  # Print nicely formatted MAC address found message

    except Exception as e:
        print(f"Failed to connect to {switch_name} ({switch_ip}): {str(e)}")
    
    finally:
        ssh_client.close()  # Close the SSH connection regardless of success or failure

def print_mac_address_found_info(info):
    print()
    print()
    print("--------------------------------------------------------------")
    print("|                  WIRED MAC ADDRESS FOUND                   |")
    print("--------------------------------------------------------------")
    print(info)
    print("--------------------------------------------------------------")
    print()
    print()

def get_mac_info(switches, formatted_mac):
    num_threads = 5
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        for switch in switches:
            executor.submit(get_mac_info_thread, switch, formatted_mac)





def check_airwave_for_wireless_devices(mac_address):
    base_url = 'https://airwave01.valdosta.edu'
    login_url = base_url + '/LOGIN'
    username = 'readonly'
    password = 'Readonly1!'

    # Define the target URL for fetching client search data
    client_search_url = base_url + '/client_search.xml?query=' + mac_address

    # Create a session object to persist cookies across requests
    session = requests.Session()

    # Send a POST request to the login page to authenticate
    login_data = {
        'credential_0': username,
        'credential_1': password,
        'destination': '/client_search.xml'
    }

    response = session.post(login_url, data=login_data, verify=False)

    # Check if login was successful
    if response.status_code == 200:
        # Send a GET request to fetch client search data
        client_search_response = session.get(client_search_url, verify=False)

        # Check if client search data was successfully retrieved
        if client_search_response.status_code == 200:
            # Parse the XML response
            root = ET.fromstring(client_search_response.text)

            # Extract the desired details for each client
            for record in root.findall('.//record'):
                username = record.find('username').text if record.find('username') is not None else None
                ssid = record.find('ssid').text if record.find('ssid') is not None else None
                vlan = record.find('vlan').text if record.find('vlan') is not None else None
                role = record.find('role').text if record.find('role') is not None else None
                last_ap_id = record.find('last_ap_id').attrib.get('ascii_value') if record.find('last_ap_id') is not None else None
                disconnect_time = record.find('disconnect_time').text if record.find('disconnect_time') is not None else None
                duration_seconds = int(record.find('duration').text) if record.find('duration') is not None else None
                radio_mode = record.find('radio_mode').attrib.get('ascii_value') if record.find('radio_mode') is not None else None

                # Convert duration to minutes
                if duration_seconds is not None:
                    duration_minutes = duration_seconds // 60
                    duration_hours = duration_minutes // 60

                # Print the extracted details
                    

                print()
                print()
                print("--------------------------------------------------------------")
                print("|                   WIRELESS MAC ADDRESS FOUND               |")
                print("--------------------------------------------------------------")
                print(f"Username: {username}")
                print(f"SSID: {ssid}")
                print(f"VLAN: {vlan}")
                print(f"Role: {role}")
                print(f"Last AP Name: {last_ap_id}")
                print(f"Disconnect Time: {disconnect_time}")
                if duration_seconds is not None:
                    print(f"Duration: {duration_hours} hours, {duration_minutes % 60} minutes")
                else:
                    print("Duration: N/A")
                print(f"Radio Type: {radio_mode}")
                print()
                print("--------------------------------------------------------------")
                print()
                print()
                    
                # Check if the current record matches the MAC address
                client_mac = record.find('mac').text if record.find('mac') is not None else None
                if client_mac and client_mac.lower() == mac_address.lower():
                    # MAC address found in AirWave
                    session.close()
                    return True

        else:
            print('Failed to retrieve client search data')
    else:
        print('Login failed')

    # Close the session
    session.close()
    return False

def main():
    global mac_address_info  # Declare the global variable
    hostname = 'orion01.valdosta.edu'
    username = 'Jabba'
    password = 'thehut321!'
    vendors = ["Cisco", "Aruba Networks Inc"]
    exclude_strings = ["arubamc", "arubamm", "VSU-N", "OakDCTR", "VAL.BB.peach.net", "mDNS_", "voicegw", "CiscoWLC", "DC-", "C240", "netmgmt", "DataCenter"]

    while True:
        # Get MAC address from the user
        mac_address = get_user_mac()

        # Check AirWave for wireless devices
        if check_airwave_for_wireless_devices(mac_address):
            continue  # Loop immediately if MAC is found in AirWave

        # Connect to SolarWinds and store the list of switches
        switches = connect_to_solarwinds(hostname, username, password, vendors, exclude_strings)

        # Get MAC information from the switches
        get_mac_info(switches, mac_address)

        if mac_address_info:
            print(mac_address_info)
            mac_address_info = None  # Reset the flag for the next search
        else:
            print("MAC address not found.")


if __name__ == "__main__":
    main()

