from setuptools import setup

setup(name='certverifier',
	 version='0.1',
	 description='SSL/TLS malicious certificate verifier tool',
	 author='Natalia Greguskova',
	 author_email='422562@mail.muni.cz',
	 license=license,
	 packages=['certverifier'],
	 include_package_data=True,
	 entry_points={
        'console_scripts': [
            'cert-verifier=certverifier.cert_verifier:main'
        ]
    },
)
