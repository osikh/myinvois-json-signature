import json
import base64
import hashlib
import os
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import NameOID
import re
import random
import string
import pytz
from datetime import datetime, timedelta

def generate_random_string(length):
    # Create a pool of letters and digits
    characters = string.ascii_letters + string.digits
    # Randomly choose characters from the pool
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

"""Remove whitespace from JSON except for within string values."""
def minify_json_str(json_string: str):
    if not json_string:
        print("Invalid JSON content.")
        exit()

    minified_json = re.sub(r'("(?:\\.|[^"\\])*")|\s+', lambda m: m.group(1) if m.group(1) else '', json_string)
    return minified_json

# dict -> str + minify
def minify_json(json_data: dict) -> str:
    return json.dumps(json_data, separators=(',', ':'))

# Load the certificate and private key
def load_certificate(p12_path: str, password: str) -> rsa.RSAPrivateKey:
    with open(p12_path, "rb") as cert_file:
        p12_data = cert_file.read()
        
    # Load the PKCS#12 file
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(p12_data, password.encode(), backend=default_backend())
    
    return certificate, private_key, additional_certificates

def load_certificate_wo_pass(cert_path):
    """Load and return the certificate from a file."""
    with open(cert_path, "rb") as cert_file:
        cert_data = cert_file.read()
    cert = load_pem_x509_certificate(cert_data, default_backend())
    private_key = cert.private_key()

    return cert, private_key

def get_cert_info(certificate):
    # Extract certificate information
    cert_serial_number = certificate.serial_number
    cert_subject = certificate.subject.rfc4514_string({
        NameOID.EMAIL_ADDRESS: "E", 
        NameOID.SERIAL_NUMBER: "SERIALNUMBER", 
        NameOID.ORGANIZATION_IDENTIFIER: "OID.2.5.4.97", 
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU"
    })
    cert_issuer = certificate.issuer.rfc4514_string()
    cert_valid_from = certificate.not_valid_before_utc
    cert_valid_to = certificate.not_valid_after_utc

    return {
        "serial": cert_serial_number,
        "subject": cert_subject,
        "issuer": cert_issuer,
        "valid_from": cert_valid_from,
        "valid_to": cert_valid_to
    }

def sha256_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hashed_data = digest.finalize()
    return hashed_data

def rsa_sign(private_key, data):
    """Sign data using RSA private key."""
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

# Convert the bytes to Base64
def base64_encode(bytes: bytes) -> str:
    return base64.b64encode(bytes).decode('utf-8')

# Compute the SHA-256 hash of the certificate
def compute_cert_hash(certificate):
    # Get the raw data of the certificate
    cert_raw_data = certificate.public_bytes(serialization.Encoding.DER)
    
    # Compute the SHA-256 hash of the certificate
    sha256_hash = hashes.Hash(SHA256(), backend=default_backend())
    sha256_hash.update(cert_raw_data)
    cert_hash = sha256_hash.finalize()
    
    return cert_hash

def read_json_from_file(filepath) -> str:
    try:
        # Open the file in read mode
        with open(filepath, 'r') as file:
            # Load JSON content into a Python dictionary
            data = file.read()
            return data
    except FileNotFoundError:
        print(f"Error: The file at {filepath} was not found.")
    except json.JSONDecodeError:
        print(f"Error: The file at {filepath} is not a valid JSON file.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def create_json_signature(inputJson: str, certificate_file: str, certificate_pin: str) -> str:
    # LHDN required UTC timestamp
    # Using pytz to set timezone to UTC
    utc_timezone = pytz.utc

    # Format the signingDatetime as required
    # this datetime will be used as SIGNING TIMESTAMP
    utcDatetime = datetime.now(utc_timezone).strftime('%Y-%m-%dT%H:%M:%SZ')

    # fix it for easy debugging
    # utcDatetime = "2024-11-25T07:52:32Z"

    # Load the Certificate
    certificate, private_key, add_certificates = load_certificate(certificate_file, certificate_pin)
    certInfo = get_cert_info(certificate)

    minifiedJson = minify_json_str(inputJson)
    document = minifiedJson.encode('utf-8')

    documentHash = sha256_hash(document)
    docDigest = base64_encode(documentHash)

    # Either use Document
    signature = rsa_sign(private_key, document)

    # - OR -
    # use DocumentHash like this

    # signature = private_key.sign(
    #     documentHash,
    #     padding.PKCS1v15(),
    #     utils.Prehashed(hashes.SHA256())  # Indicate that the data is pre-hashed
    # )

    signatureBase64 = base64_encode(signature)

    # Compute the SHA-256 hash of the certificate
    # certHash = compute_cert_hash(certificate)
    # certDigest = base64_encode(certHash)

    certRawData = certificate.public_bytes(serialization.Encoding.DER)
    certHash = sha256_hash(certRawData)
    certDigest = base64_encode(certHash)

    issuerName = certInfo['issuer']
    subjectName = certInfo['subject']
    serialNumber = str(certInfo['serial'])

    certRawDataDigest = base64_encode(certRawData)

    # Construct the JSON string
    signProp = {
        "Target": "signature",
        "SignedProperties": [
            {
                "Id": "id-xades-signed-props",
                "SignedSignatureProperties": [
                    {
                        "SigningTime": [{"_": utcDatetime}],
                        "SigningCertificate": [
                            {
                                "Cert": [
                                    {
                                        "CertDigest": [
                                            {"DigestMethod": [{"_": "", "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"}],
                                            "DigestValue": [{"_": certDigest}]}
                                        ],
                                        "IssuerSerial": [
                                            {"X509IssuerName": [{"_": issuerName}], "X509SerialNumber": [{"_": serialNumber}]}
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }

    signProp = minify_json(signProp)
    signPropHash = sha256_hash(signProp.encode('utf-8'))
    signPropDigest = base64_encode(signPropHash)

    ublExtensions = {
        "UBLExtensions": [
            {
                "UBLExtension": [
                    {
                        "ExtensionURI": [
                            {"_": "urn:oasis:names:specification:ubl:dsig:enveloped:xades"}
                        ],
                        "ExtensionContent": [
                            {
                                "UBLDocumentSignatures": [
                                    {
                                        "SignatureInformation": [
                                            {
                                                "ID": [
                                                    {"_": "urn:oasis:names:specification:ubl:signature:1"}
                                                ],
                                                "ReferencedSignatureID": [
                                                    {"_": "urn:oasis:names:specification:ubl:signature:Invoice"}
                                                ],
                                                "Signature": [
                                                    {
                                                        "Id": "signature",
                                                        "Object": [
                                                            {
                                                                "QualifyingProperties": [
                                                                    {
                                                                        "Target": "signature",
                                                                        "SignedProperties": [
                                                                            {
                                                                                "Id": "id-xades-signed-props",
                                                                                "SignedSignatureProperties": [
                                                                                    {
                                                                                        "SigningTime": [
                                                                                            {"_": utcDatetime}
                                                                                        ],
                                                                                        "SigningCertificate": [
                                                                                            {
                                                                                                "Cert": [
                                                                                                    {
                                                                                                        "CertDigest": [
                                                                                                            {
                                                                                                                "DigestMethod": [
                                                                                                                    {"_": "", "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"}
                                                                                                                ],
                                                                                                                "DigestValue": [{"_": certDigest}]
                                                                                                            }
                                                                                                        ],
                                                                                                        "IssuerSerial": [
                                                                                                            {
                                                                                                                "X509IssuerName": [{"_": issuerName}],
                                                                                                                "X509SerialNumber": [{"_": serialNumber}]
                                                                                                            }
                                                                                                        ]
                                                                                                    }
                                                                                                ]
                                                                                            }
                                                                                        ]
                                                                                    }
                                                                                ]
                                                                            }
                                                                        ]
                                                                    }
                                                                ]
                                                            }
                                                        ],
                                                        "KeyInfo": [
                                                            {
                                                                "X509Data": [
                                                                    {
                                                                        "X509Certificate": [{"_": certRawDataDigest}],
                                                                        "X509SubjectName": [{"_": subjectName}],
                                                                        "X509IssuerSerial": [
                                                                            {
                                                                                "X509IssuerName": [{"_": issuerName}],
                                                                                "X509SerialNumber": [{"_": serialNumber}]
                                                                            }
                                                                        ]
                                                                    }
                                                                ]
                                                            }
                                                        ],
                                                        "SignatureValue": [{"_": signatureBase64}],
                                                        "SignedInfo": [
                                                            {
                                                                "SignatureMethod": [
                                                                    {"_": "", "Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
                                                                ],
                                                                "Reference": [
                                                                    {
                                                                        "Type": "http://uri.etsi.org/01903/v1.3.2#SignedProperties",
                                                                        "URI": "#id-xades-signed-props",
                                                                        "DigestMethod": [
                                                                            {"_": "", "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"}
                                                                        ],
                                                                        "DigestValue": [{"_": signPropDigest}]
                                                                    },
                                                                    {
                                                                        "Type": "",
                                                                        "URI": "",
                                                                        "DigestMethod": [
                                                                            {"_": "", "Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"}
                                                                        ],
                                                                        "DigestValue": [{"_": docDigest}]
                                                                    }
                                                                ]
                                                            }
                                                        ]
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ],
        "Signature": [
            {
                "ID": [{"_": "urn:oasis:names:specification:ubl:signature:Invoice"}],
                "SignatureMethod": [{"_": "urn:oasis:names:specification:ubl:dsig:enveloped:xades"}]
            }
        ]
    }

    documentJson = json.loads(minifiedJson)
    if "Invoice" in documentJson and len(documentJson["Invoice"]) > 0:
        documentJson["Invoice"][0]["UBLExtensions"] = ublExtensions["UBLExtensions"]
        documentJson["Invoice"][0]["Signature"] = ublExtensions["Signature"]

    # print(json.dumps({
    #     "docDigest": docDigest,
    #     "signatureBase64": signatureBase64,
    #     "certDigest": certDigest,
    #     "issuerName": issuerName,
    #     "serialNumber": serialNumber,
    #     "certRawDataDigest": certRawDataDigest,
    #     "signPropDigest": signPropDigest
    # }, indent=4))

    finalJson = minify_json(documentJson)
    return finalJson

def main():
    # Certificate file and PIN (for later use, e.g., for signing)
    certificate_file = 'cert/cert_dev.p12'
    certificate_pin = '__CERTIFICATE_PASSWORD__'
    inputJson = read_json_from_file('json_files/input.json')
    
    signedDoc = create_json_signature(inputJson, certificate_file, certificate_pin)

    print(signedDoc)

if __name__ == "__main__":
    main()