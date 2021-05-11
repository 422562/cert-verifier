# cert-verifier
### _Python tool for recognition of malicious SSL/TLS certificates_

**cert-verifier** is a Python3 tool written to accompany the diploma thesis _TLS Certificate Analysis_. Its purpose is to check an X.509 certificate (or multiple certificates) provided on input and decide whether or not does it show marks of previously analyzed malicious certificates. The verification process contains elements of machine learning to recognize randomly generated values and subsequent pattern matching to check for specific value structures of malicious certificates. Successful malicious certificate recognition was measured to be up to 91.78%.

## Installation
```sh
git clone https://github.com/
cd cert-verifier
python3 setup.py install
```
## Usage
```sh
cert-verifier.py -i <infile> -o <outfile> -m 1/2/3 -s
```
* -i <infile>: A single X.509 certificate file or a folder with multiple certificates in .PEM format
* -o <outfile>: In case of classification of multiple certificates, choose a file to print the results
* -m  <mode> 1/2/3: Classification mode(s) - choose at least one:
	1 - identify potentially malicious certificates by issuers with known issued malware.
	2 - identify default certificates misused in malware campaigns.
	3 - identify other certificates used in malware campaigns.
* -s: strict mode - if present, only certificates with known malicious common name will be identified.

## Example usage
This command will identify all potential malicious certificates in a given directory:
```sh
python3 cert-verifier.py -i ./certificates_directory -m 123
```
This command will identify 'default' certificates with malicious structure (mode 2) + strict mode is used - the common name must be present in a list of known malicious common names:
```sh
python3 cert-verifier.py -i ./certificates_directory -m 2 -s
```
This command will check a single .PEM certificate. A warning is printed if it has a malicious structure + it was issued by a legitimate issuer with known misissuance (mode 1) + strict mode is used -  the common name must be present in a list of known malicious common names:
```sh
python3 cert-verifier.py -i ./certificates_directory -m 1 -s
```