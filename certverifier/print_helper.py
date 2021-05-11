from time import time

def print_help():
	print("----------------------------------------------------------")
	print("| cert-verifier - an X.509 certificate verification tool |")
	print("----------------------------------------------------------")
	print("This tool is used for recognition of potential malicious SSL/TLS certificates.")
	print("Usage: cert-verifier.py -i <infile> -m 1/2/3 -s")
	print("* -i <infile>: A single X.509 certificate file or a folder with multiple certificates in .PEM format")
	print("* -o <outfile>: In case of classification of multiple certificates, choose a file to print the results")
	print("* -m  <mode> 1/2/3: Classification mode(s) - choose at least one:")
	print("\t1 - identify certificates from issuers with known issued malware")
	print("\t2 - identify default certificates misused in malware campaigns")
	print("\t3 - identify other certificates used in malware campaigns")
	print("* -s: strict mode - if present, only certificates with known malicious common name will be identified")
	print("Example usage: cert-verifier -i ./certificate_directory -m 123")
	print("\t- this option will identify all potential malicious certificates.")
				
def print_cert_result(certname, cert_type):
	print(certname)
	
	if cert_type == 0:
		print("This certificate's structure was found among malicious certificates, but the common name was not among known malicious values")
		
	elif cert_type == 1:
		print("WARNING - this certificate's issuer is known to have misissued certificates used in malware campaigns")
		
	elif cert_type == 2:
		print("WARNING - this type of default certificate has been previously misused in malware campaigns")
		
	elif cert_type == 3:
		print("WARNING - this certificate's structure is identical to certificates from malware campaigns")
	
	elif cert_type == 4:
		print("This certificate's structure was not found among malicious certificates")

def print_header(outfile):
	print("file, structure, type", file = outfile)
		
def print_to_file(outfile, file, cert_type):
	cert_string = ""
	if cert_type in (0, 4):
		cert_string = "benign"
	else:
		cert_string = "malign"
	cert_line = file + "," + cert_string + "," + str(cert_type)
	print(cert_line, file = outfile)
	
def print_classification_time(start_time):
	current_time = time()
	total_time = round(current_time - start_time, 2)
	print("Total classification time: " + str(total_time) + " seconds.")
	
def print_certificate_counts(cert_counts):
	print("Potential malicious certificates rejected by strict mode: " + str(cert_counts[0]))
	print("Potential malicious certificates by issuers with known misissuance: " + str(cert_counts[1]))
	print("Potential malicious certificates with default structure: " + str(cert_counts[2]))
	print("Potential malicious certificates of other type: " + str(cert_counts[3]))
	print("Benign certificates: " + str(cert_counts[4]))
	print("--")
