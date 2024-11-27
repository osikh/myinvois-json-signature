import os
import requests
import json
import glob
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Route for rendering HTML page
@app.route('/')
def home():
    return render_template('index.html')

# API endpoint returning JSON data
@app.route('/api/greet/<name>')
def greet(name):
    response = {
        "message": f"Hello, {name}!"
    }
    return jsonify(response)

@app.route('/api/getcodes')
def getCodes():
    files = [
        'https://sdk.myinvois.hasil.gov.my/files/ClassificationCodes.json',
        'https://sdk.myinvois.hasil.gov.my/files/CountryCodes.json',
        'https://sdk.myinvois.hasil.gov.my/files/CurrencyCodes.json',
        'https://sdk.myinvois.hasil.gov.my/files/EInvoiceTypes.json',
        'https://sdk.myinvois.hasil.gov.my/files/MSICSubCategoryCodes.json',
        'https://sdk.myinvois.hasil.gov.my/files/PaymentMethods.json',
        'https://sdk.myinvois.hasil.gov.my/files/StateCodes.json',
        'https://sdk.myinvois.hasil.gov.my/files/TaxTypes.json',
        'https://sdk.myinvois.hasil.gov.my/files/UnitTypes.json'
    ]

    # final json response
    final_response = {
        "status": True,
        "files": {}
    }

    # Directory where the JSON files will be saved
    save_dir = 'static/codes/'
    
    # Ensure that the save directory exists
    os.makedirs(save_dir, exist_ok=True)
    
    # Iterate over the URLs in the files array
    for file_url in files:
        try:
            # Get the file name from the URL
            filename = file_url.split('/')[-1]
            
            # Send an HTTP request to fetch the JSON data from the URL
            response = requests.get(file_url)
            
            # Check if the request was successful (status code 200)
            if response.status_code == 200:
                # Parse the response JSON data
                json_data = response.json()
                
                # Define the path where the file will be saved
                file_path = os.path.join(save_dir, f"{filename}")
                
                # Write the JSON data to the file
                with open(file_path, 'w') as json_file:
                    json.dump(json_data, json_file, indent=4)
                
                final_response['files'][filename] = 200
            else:
                final_response['files'][filename] = response.status_code
        except Exception as e:
            final_response = {
                "status": False,
                "error": str(e)
            }

    return jsonify(final_response)

@app.route('/api/getcerts')
def getcerts():
    cert_files = glob.glob('..\cert\*.p12')
    # Create a list of dictionaries with 'fileName' as key and 'filePath' as value
    certs = [os.path.basename(file) for file in cert_files]
    return jsonify(certs)

@app.route('/api/signdoc')
def signdoc():
    return jsonify(certs)

if __name__ == '__main__':
    app.run(debug=True)
    # print(f"MyInvois JSON Tools: http://localhost:{PORT}")