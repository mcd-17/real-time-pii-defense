import csv
import json
import sys
import re

def is_pii_standalone(data):
    """
    Checks for standalone PII based on provided definitions.
    """
    phone_number_pattern = r'^\d{10}$'
    aadhar_number_pattern = r'^\d{12}$'
    passport_number_pattern = r'^[A-Z][0-9]{7}$'
    upi_id_pattern = r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$|^\d{10}@\w+$'
    
    for key, value in data.items():
        if isinstance(value, str):
            if key == 'phone' and re.match(phone_number_pattern, value):
                return True
            if key == 'aadhar' and re.match(aadhar_number_pattern, value.replace(" ", "")):
                return True
            if key == 'passport' and re.match(passport_number_pattern, value):
                return True
            if key == 'upi_id' and re.match(upi_id_pattern, value):
                return True
    return False

def is_pii_combinatorial(data):
    """
    Checks for combinatorial PII based on provided definitions.
    """
    
    combinatorial_keys = {
        'name', 'email', 'address', 'ip_address', 'device_id'
    }
    
    present_keys = combinatorial_keys.intersection(data.keys())
    
    # Exclude cases that are specifically listed as Non-PII (False Positives)
    # A single attribute from the list is not PII
    if len(present_keys) < 2:
        return False

    # Special check for 'name', 'first_name', 'last_name'
    has_full_name = ('name' in data and ' ' in data['name']) or ('first_name' in data and 'last_name' in data)
    
    # Check for other combinations
    if (has_full_name and ('email' in data or 'address' in data or 'ip_address' in data or 'device_id' in data)):
        return True
    
    if 'email' in data and ('address' in data or 'ip_address' in data or 'device_id' in data):
        return True
    
    if 'address' in data and ('ip_address' in data or 'device_id' in data):
        return True
    
    if 'ip_address' in data and 'device_id' in data:
        return True
        
    return False

def redact_pii(data):
    """
    Redacts PII data points.
    """
    redacted_data = data.copy()
    
    # Standalone PII redaction
    if is_pii_standalone(data):
        for key, value in data.items():
            if key == 'phone' and isinstance(value, str) and re.match(r'^\d{10}$', value):
                redacted_data[key] = f"{value[:2]}XXXXXX{value[-2:]}"
            elif key == 'aadhar' and isinstance(value, str) and re.match(r'^\d{12}$', value.replace(" ", "")):
                redacted_data[key] = f"{value[:4]} XXXX XXXX" 
            elif key == 'passport' and isinstance(value, str) and re.match(r'^[A-Z][0-9]{7}$', value):
                redacted_data[key] = f"{value[0]}XXXXXXX"
            elif key == 'upi_id' and isinstance(value, str):
                redacted_data[key] = "[REDACTED_UPI_ID]"

    # Combinatorial PII redaction
    if is_pii_combinatorial(data):
        for key, value in data.items():
            if key == 'name' and isinstance(value, str) and ' ' in value:
                parts = value.split(' ')
                redacted_data[key] = " ".join([f"{part[0]}X{'X' * (len(part) - 2)}" for part in parts])
            elif key == 'first_name' and isinstance(value, str):
                redacted_data[key] = f"{value[0]}X{'X' * (len(value) - 2)}"
            elif key == 'last_name' and isinstance(value, str):
                redacted_data[key] = f"{value[0]}X{'X' * (len(value) - 2)}"
            elif key == 'email' and isinstance(value, str):
                parts = value.split('@')
                redacted_data[key] = f"{parts[0][0]}XXXX@{parts[1]}"
            elif key == 'address' and isinstance(value, str):
                redacted_data[key] = "[REDACTED_ADDRESS]"
            elif key in ['ip_address', 'device_id']:
                redacted_data[key] = "[REDACTED_ID]"
                
    return redacted_data

def process_csv(input_filename, output_filename):
    with open(input_filename, 'r') as infile, open(output_filename, 'w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)
        
        # Write the header for the new CSV file
        writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])
        
        # Skip the header row from the input file
        next(reader)
        
        for row in reader:
            record_id = row[0]
            data_json_str = row[1]
            
            try:
                # Attempt to load the JSON data
                data = json.loads(data_json_str)
                
                # Determine if the record contains PII
                is_pii = is_pii_standalone(data) or is_pii_combinatorial(data)
                
                # Redact the PII if found
                redacted_data = redact_pii(data)
                
                writer.writerow([record_id, json.dumps(redacted_data), is_pii])
                
            except json.JSONDecodeError as e:
                # If there's a JSONDecodeError, print a helpful error message and skip the row
                print(f"Error decoding JSON for record_id {record_id}: {e}")
                print(f"Problematic data: {data_json_str}")
                # You can choose to write a row with an error message or skip it entirely
                writer.writerow([record_id, '{"error": "JSONDecodeError"}', False])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_your_full_name.py <input_csv_file>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    # The output filename needs to be in the format specified by the challenge
    output_file = f"redacted_output_{sys.argv[0].split('_')[-1].split('.')[0]}.csv"
    
    process_csv(input_file, output_file)
    print(f"Processing complete. Output saved to {output_file}")
