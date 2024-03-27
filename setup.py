from setuptools import setup, find_packages

setup(
    name='healthcheck',
    version='0.1',
    packages=find_packages(),
    py_modules=['Application'],
    install_requires=[
        'flask',
        'flask-sqlalchemy',
        'flask-bcrypt',
        'sqlalchemy-utils',
        'psycopg2-binary',
        'google-cloud-logging',
        'google-cloud-pubsub'
    ],
    entry_points={
        'console_scripts': [
            'Application = healthcheck.Application:main'
        ]
    }
)