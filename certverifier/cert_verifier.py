from certverifier.print_helper import *
from certverifier.classify_features import *
import os, sys, getopt, codecs, csv
import pandas
from OpenSSL import crypto
from time import time



def main():
	argv = sys.argv[1:]
	infile = ""
	outfile = "output.csv"
	mode = "123"
	strict = False
	cert_count = 0
	
	try:
		opts, args = getopt.getopt(argv, "hi:o:m:s", ["infile=","outfile=","mode=","strict"])
	except getopt.GetoptError:
		print_help()
		sys.exit()
	for opt, arg in opts:
		if opt == "-h":
			print_help()
			sys.exit()
		if opt == "-i":
			infile = arg
		if opt == "-o":
			outfile = arg
		if opt == "-m":
			mode = arg
		if opt == "-s":
			strict = True
	
	
	patterns_df = pandas.read_csv(pkgfile("data/malicious-patterns-with-malware.csv"))
	malicious_patterns = patterns_df.drop('malware', axis = 1).values.tolist()
	malicious_subjectCNs = pandas.read_csv(pkgfile("data/malicious_subjectCN.csv"))['subject.CN'].values.tolist()
	classifiers = load_classifiers()
	count_vectorizers = load_count_vectorizers()
	
	# classify a single .PEM file
	if os.path.isfile(infile):
		with codecs.open(infile, 'r', 'utf-8') as certfile:
			certdata = certfile.read()
			cert = crypto.load_certificate(crypto.FILETYPE_PEM, certdata)
			class_dict = get_class_dict(cert, classifiers, count_vectorizers)
			cert_type = classify_cert(cert, mode, strict, class_dict, malicious_patterns, malicious_subjectCNs)
			print_cert_result(infile, cert_type)
	
	# classify a folder with .PEM certificates
	if os.path.isdir(infile):
		start_time = time()
		cert_counts = [0] * 5
		lst = os.listdir(infile)
		lst.sort()
		with codecs.open(outfile, 'w', 'utf-8') as out:
			print_header(out)
			for file in lst:
				with codecs.open(os.path.join(infile, file), 'r', 'utf-8') as certfile:
					certdata = certfile.read()
					cert = crypto.load_certificate(crypto.FILETYPE_PEM, certdata)
					class_dict = get_class_dict(cert, classifiers, count_vectorizers)
					cert_type = classify_cert(cert, mode, strict, class_dict, malicious_patterns, malicious_subjectCNs)
					print_to_file(out, file, cert_type)
					cert_counts[cert_type] += 1
					# print information to output about the progress
					if sum(cert_counts) % 100 == 0:
						print_certificate_counts(cert_counts)
		print_classification_time(start_time)
		print_certificate_counts(cert_counts)
	
if __name__ == "__main__":
	main(sys.argv[1:])

