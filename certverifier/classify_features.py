import datetime
import pickle
import pkg_resources
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB


SSL_DATEFORMAT = '%Y%m%d%H%M%SZ'


def pkgfile(filename):
	pkgfilename = pkg_resources.resource_filename(__name__, filename)
	return pkgfilename

def load_classifiers():
	clf = {}
	clf['subject.CN'] = pickle.load(open(pkgfile('models/subjectCN_model.sav'), 'rb'))
	clf['subject.OU'] = pickle.load(open(pkgfile('models/subjectOU_model.sav'), 'rb'))
	clf['subject.O'] = pickle.load(open(pkgfile('models/subjectO_model.sav'), 'rb'))
	clf['subject.L'] = pickle.load(open(pkgfile('models/subjectL_model.sav'), 'rb'))
	clf['subject.S'] = pickle.load(open(pkgfile('models/subjectS_model.sav'), 'rb'))
	clf['subject.C'] = pickle.load(open(pkgfile('models/subjectC_model.sav'), 'rb'))
	clf['subject.E'] = pickle.load(open(pkgfile('models/subjectE_model.sav'), 'rb'))
	clf['issuer.CN'] = pickle.load(open(pkgfile('models/issuerCN_model.sav'), 'rb'))
	return clf

def load_count_vectorizers():
	vec = {}
	vec['subject.CN'] = pickle.load(open(pkgfile('count_vectorizers/subjectCN_vectorizer.sav'), 'rb'))
	vec['subject.OU'] = pickle.load(open(pkgfile('count_vectorizers/subjectOU_vectorizer.sav'), 'rb'))
	vec['subject.O'] = pickle.load(open(pkgfile('count_vectorizers/subjectO_vectorizer.sav'), 'rb'))
	vec['subject.L'] = pickle.load(open(pkgfile('count_vectorizers/subjectL_vectorizer.sav'), 'rb'))
	vec['subject.S'] = pickle.load(open(pkgfile('count_vectorizers/subjectS_vectorizer.sav'), 'rb'))
	vec['subject.C'] = pickle.load(open(pkgfile('count_vectorizers/subjectC_vectorizer.sav'), 'rb'))
	vec['subject.E'] = pickle.load(open(pkgfile('count_vectorizers/subjectE_vectorizer.sav'), 'rb'))
	vec['issuer.CN'] = pickle.load(open(pkgfile('count_vectorizers/issuerCN_vectorizer.sav'), 'rb'))
	return vec

def get_subjectCN_class(cert, clf, vec):
	subjectCN = str(cert.get_subject().CN)
	subjectCN_class = clf['subject.CN'].predict(vec['subject.CN'].transform([subjectCN]))
	return subjectCN_class
	
def get_subjectOU_class(cert, clf, vec):
	subjectOU = str(cert.get_subject().OU)
	subjectOU_class = clf['subject.OU'].predict(vec['subject.OU'].transform([subjectOU]))
	return subjectOU_class
	
def get_subjectO_class(cert, clf, vec):
	subjectO = str(cert.get_subject().O)
	subjectO_class = clf['subject.O'].predict(vec['subject.O'].transform([subjectO]))
	return subjectO_class
	
def get_subjectL_class(cert, clf, vec):
	subjectL = str(cert.get_subject().L)
	subjectL_class = clf['subject.L'].predict(vec['subject.L'].transform([subjectL]))
	return subjectL_class
	
def get_subjectS_class(cert, clf, vec):
	subjectS = str(cert.get_subject().ST)
	subjectS_class = clf['subject.S'].predict(vec['subject.S'].transform([subjectS]))
	return subjectS_class
	
def get_subjectC_class(cert, clf, vec):
	subjectC = str(cert.get_subject().C)
	subjectC_class = clf['subject.C'].predict(vec['subject.C'].transform([subjectC]))
	return subjectC_class
	
def get_subjectE_class(cert, clf, vec):
	subjectE = str(cert.get_subject().emailAddress)
	subjectE_class = clf['subject.E'].predict(vec['subject.E'].transform([subjectE]))
	return subjectE_class
	
def get_issuerCN_class(cert, clf, vec):
	issuerCN = str(cert.get_issuer().CN)
	# if the subject common name is the same as issuer common name, the classes should be equal
	if cert.get_subject().CN == cert.get_issuer().CN:
		return get_subjectCN_class(cert, clf, vec)
	issuerCN_class = clf['issuer.CN'].predict(vec['issuer.CN'].transform([issuerCN]))
	return issuerCN_class
	
def get_selfsigned_class(cert):
	issuer = cert.get_issuer()
	subject = cert.get_subject()
	return issuer == subject
	
def get_keylength_class(cert):
	keylength = cert.get_pubkey().bits()
	if keylength == 256:
		return 0
	if keylength == 384:
		return 1
	if keylength == 512 or keylength == 521:
		return 2
	if keylength == 4096:
		return 3
	if keylength == 1024:
		return 4
	if keylength == 1039:
		return 3
	if keylength == 1536:
		return 6
	if keylength == 2024:
		return 7
	if keylength == 2048:
		return 8
	return 9

def get_algorithm_class(cert):
	algorithm = cert.get_signature_algorithm().decode('utf-8')
	if algorithm == "ecdsa-with-SHA256":
		return 0
	if algorithm == "ecdsa-with-SHA384":
		return 1
	if algorithm == "ecdsa-with-SHA512":
		return 2
	if algorithm == "md5WithRSAEncryption":
		return 3
	if algorithm == "sha1WithRSA" or algorithm == "sha1WithRSAEncryption":
		return 4
	if algorithm == "sha256WithRSAEncryption":
		return 5
	if algorithm == "sha384WithRSAEncryption":
		return 6
	return 7

def get_years_class(cert):
	duration_seconds = get_validity_duration(cert)
	years_only = duration_seconds // 86400 // 365
	if years_only == 0:
		return 0
	if years_only == 1:
		return 1
	if years_only == 2:
		return 2
	if years_only > 2 and years_only < 11:
		return 3
	return 4
	
def get_days_class(cert):
	duration_seconds = get_validity_duration(cert)
	days_only = (duration_seconds // 86400) % 365
	if days_only == 0:
		return 0
	if days_only == 1:
		return 1
	if days_only == 2:
		return 2
	if days_only == 90:
		return 3
	if days_only == 182:
		return 4
	return 5
	
def get_seconds_class(cert):
	duration_seconds = get_validity_duration(cert)
	seconds_only = duration_seconds % 86400
	if seconds_only == 0:
		return 0
	if seconds_only == 43200:
		return 1
	if seconds_only == 86399:
		return 2
	return 3
	
def get_validity_duration(cert):
	notBefore = cert.get_notBefore()
	notAfter = cert.get_notAfter()
	parsedNotBefore = datetime.datetime.strptime(notBefore.decode('UTF-8'), SSL_DATEFORMAT)
	parsedNotAfter = datetime.datetime.strptime(notAfter.decode('UTF-8'), SSL_DATEFORMAT)
	daycount = parsedNotAfter - parsedNotBefore
	validity = daycount.total_seconds()
	return validity

def get_class_dict(cert, clf, vec):
	cert_class = {}
	cert_class['subject.CN'] = int(get_subjectCN_class(cert, clf, vec))
	cert_class['subject.OU'] = int(get_subjectOU_class(cert, clf, vec))
	cert_class['subject.O'] = int(get_subjectO_class(cert, clf, vec))
	cert_class['subject.L'] = int(get_subjectL_class(cert, clf, vec))
	cert_class['subject.S'] = int(get_subjectS_class(cert, clf, vec))
	cert_class['subject.C'] = int(get_subjectC_class(cert, clf, vec))
	cert_class['subject.E'] = int(get_subjectE_class(cert, clf, vec))
	cert_class['issuer.CN'] = int(get_issuerCN_class(cert, clf, vec))
	cert_class['self.signed'] = int(get_selfsigned_class(cert))
	cert_class['algorithm'] = int(get_algorithm_class(cert))
	cert_class['keylength'] = int(get_keylength_class(cert))
	cert_class['seconds'] = int(get_seconds_class(cert))
	cert_class['days'] = int(get_days_class(cert))
	cert_class['years'] = int(get_years_class(cert))
	return cert_class

def classify_cert(cert, mode, strict, classification_dict, malicious_patterns, malicious_subjectCNs):
	# a classification string is a 14-int long string categorizing selected X.509 certificate features
	classification_string = list(classification_dict.values())
	
	# check if the classification string is present among patterns extracted from malicious certificates
	for pattern in malicious_patterns:
		# found a match - potential malicious certificate
		if classification_string == pattern:
			
		# if we're in strict mode - subject.CN must be from a list of known malicious subject.CNs
			if strict and str(cert.get_subject().CN) not in malicious_subjectCNs:
				return 0
		
			# malicious pattern & issuer with known misissuance:
			if '1' in mode and classification_dict['issuer.CN'] == 5:
				return 1
				
			# malicious pattern & 'default' type of certificate
			if '2' in mode and classification_dict['subject.CN'] == 1:
				return 2
				
			# malicious pattern - others (certs with random values etc.)
			if '3' in mode and classification_dict['issuer.CN'] != 5 and classification_dict['subject.CN'] != 1:
				return 3
			
	# non-malicious pattern
	return 4
