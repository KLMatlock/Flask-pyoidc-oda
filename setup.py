from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup(
    name='Flask-pyoidc-oda',
    version='0.3.0',
    packages=['flask_pyoidc'],
    package_dir={'': 'src'},
    url='https://github.com/zamzterz/flask-pyoidc',
    license='Apache 2.0',
    author='Kevin Matlock',
    author_email='kevin.matlock@omicsautomation.com',
    description='Flask extension for OpenID Connect authentication, modified for use at ODA.',
    install_requires=[
        'oic==1.2.1',
        'Flask',
        'requests',
        'importlib_resources'
    ],
    package_data={'flask_pyoidc': ['parse_fragment.html']},
    long_description=long_description,
    long_description_content_type='text/markdown',
)
