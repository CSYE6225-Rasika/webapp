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
        'psycopg2-binary',
        'sqlalchemy-utils'
    ],
    entry_points={
        'console_scripts': [
            'Application = healthcheck.Application:main'
        ]
    }
)