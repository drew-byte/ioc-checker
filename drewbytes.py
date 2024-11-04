import requests
from flask import Flask, render_template, request, send_file
import csv
import os
import json
from tqdm import tqdm

app = Flask(__name__)

# Your API keys
VIRUSTOTAL_API_KEYS = [
    '',
    '', # 3 API's
    ''
]
ABUSEIPDB_API_KEY = '' # 1 API
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3/'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    ioc_type = request.form.get('ioc_type')
    if file and ioc_type:
        iocs = file.read().decode('utf-8').splitlines()
        results = []
        print(f"Processing {ioc_type} with {len(iocs)} items.")  # Debugging line

        if ioc_type == 'hash':
            for ioc in tqdm(iocs):
                result = check_hash(ioc)
                if result:
                    md5 = result.get('data', {}).get('attributes', {}).get('md5', '')
                    sha1 = result.get('data', {}).get('attributes', {}).get('sha1', '')
                    sha256 = result.get('data', {}).get('attributes', {}).get('sha256', '')
                    filename = result.get('data', {}).get('attributes', {}).get('names', [])
                    filename_str = ', '.join(filename) if filename else 'N/A'
                    hits = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    results.append([md5, sha1, sha256, filename_str, hits])

        elif ioc_type == 'ip':
            for ioc in tqdm(iocs):
                vt_result, abuse_result = check_ip(ioc)
                if vt_result and abuse_result:
                    ip_address = vt_result.get('data', {}).get('id', '')
                    asn = vt_result.get('data', {}).get('attributes', {}).get('asn', '')
                    hits = vt_result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    usage_type = abuse_result.get('data', {}).get('usageType', '')
                    isp = abuse_result.get('data', {}).get('isp', '')
                    country = abuse_result.get('data', {}).get('countryCode', '')
                    domain = abuse_result.get('data', {}).get('domain', '')
                    results.append([ip_address, asn, hits, usage_type, isp, country, domain])

        elif ioc_type == 'domain':
            for ioc in tqdm(iocs):
                result = check_domain(ioc)
                if result:
                    domain = result.get('data', {}).get('id', '')
                    hits = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    results.append([domain, hits])

        print(f"Results: {results}")  # Debugging line
        # Store results in a session or pass directly for download
        return render_template('results.html', results=results, ioc_type=ioc_type)

    return "No file or IOC type selected"

@app.route('/download', methods=['GET'])
def download_results():
    # Retrieve the results from the query string
    results = request.args.get('results')
    if not results:
        return "No results provided", 400

    # Decode the JSON results
    try:
        results = json.loads(results)
    except json.JSONDecodeError:
        return "Failed to decode results", 400

    # Create a CSV file
    output_file = 'results.csv'
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write headers based on the type of IOC
        if isinstance(results[0], list) and len(results[0]) == 5:  # Hashes
            writer.writerow(['MD5', 'SHA1', 'SHA256', 'Filename', 'Hits'])
        elif isinstance(results[0], list) and len(results[0]) == 7:  # IPs
            writer.writerow(['IP Address', 'ASN', 'Hits', 'Usage Type', 'ISP', 'Country', 'Domain'])
        else:  # Domains
            writer.writerow(['Domain', 'Hits'])

        # Write data rows
        writer.writerows(results)

    return send_file(output_file, as_attachment=True)

def check_hash(ioc):
    api_key = get_api_key()
    url = f"{VIRUSTOTAL_API_URL}files/{ioc}"
    headers = {'x-apikey': api_key, 'accept': 'application/json'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def check_ip(ioc):
    api_key = get_api_key()
    vt_url = f"{VIRUSTOTAL_API_URL}ip_addresses/{ioc}"
    abuse_url = f"https://api.abuseipdb.com/api/v2/check"
    
    vt_headers = {'x-apikey': api_key, 'accept': 'application/json'}
    vt_response = requests.get(vt_url, headers=vt_headers)

    abuse_headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    abuse_response = requests.get(abuse_url, headers=abuse_headers, params={"ipAddress": ioc})

    if vt_response.status_code == 200 and abuse_response.status_code == 200:
        return vt_response.json(), abuse_response.json()
    return None, None

def check_domain(ioc):
    api_key = get_api_key()
    url = f"{VIRUSTOTAL_API_URL}domains/{ioc}"
    headers = {'x-apikey': api_key, 'accept': 'application/json'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def get_api_key():
    return VIRUSTOTAL_API_KEYS[0]  # Modify as needed for key rotation

if __name__ == '__main__':
    app.run(debug=True)
