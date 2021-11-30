import requests
from suds.client import Client
from flask import current_app

from lemur.plugins import lemur_globalsign as globalsign
from lemur.plugins.bases import IssuerPlugin

GLOBALSIGN_PRODUCTS = [ 
    'EV_SHA2', #ExtendedSSL
    'OV_SHA2', #OrganizationSSL
    'DV_SHA2', #DomainSSL used in Email Order
    'DV_HIGH_URL_SHA2', #DomainSSL used in HTTP Order
    'DV_HIGH_DNS_SHA2', #DomainSSL uned in DNS Order
    'DV_LOW_SHA2', #AlphaSSL used in Email Order
    'DV_LOW_URL_SHA2', #AlphaSSL used in HTTP Order
    'DV_LOW_DNS_SHA2' #AlphaSSL used in DNS Order
]

def build_globalsign_object(client, csr, issuer_options):
    '''Set the incoming issuer options to GlobalSign fields/options.
    :param csr:
    :param options:
    :return: dict or valid GlobalSign options
    
    Requesting a new globalsign certificate: {'destinations': [], 'key_type': 'ECCPRIME256V1', 'country': 'US', 'rotation': True, 'common_name': '*.gigenet.com', 'validity_end': <Arrow [2022-11-30T15:09:48.721000+00:00]>, 'description': 'GigeNET Wildcard', 'organizational_unit': 'IT', 'replaces': [], 'extensions': {'sub_alt_names': {'names': <SubjectAlternativeName(<GeneralNames([<DNSName(value='*.gigenet.com')>])>)>}, 'custom': [{'is_critical': False, 'oid': 'ProductCode', 'encoding': 'string', 'value': 'DV_LOW_DNS_SHA2'}, {'is_critical': False, 'oid': 'BaseOption', 'encoding': 'string', 'value': 'wildcard'}]}, 'rotation_policy': RotationPolicy(days=30, name=default), 'location': 'Arlighton Heights', 'authority': Authority(name=GlobalSign), 'notifications': [Notification(label=DEFAULT_SUPPORT_30_DAY), Notification(label=DEFAULT_SUPPORT_15_DAY), Notification(label=DEFAULT_SUPPORT_2_DAY)], 'roles': [], 'validity_start': <Arrow [2021-11-30T15:09:48.721000+00:00]>, 'dns_provider': None, 'validity_years': None, 'state': 'IL', 'replacements': [], 'organization': 'GigeNET', 'owner': 'support@gigenet.com', 'creator': User(username=lemur)}'''

    product_code = 'DV_LOW_DNS_SHA2'
    if issuer_options['custom']['ProductCode']:
        if issuer_options['custom']['ProductCode'] in GLOBALSIGN_PRODUCTS:
            product_code = issuer_options['custom']['ProductCode']
        else:
            raise Exception("Unsupported product code.")

    base_option = None
    if issuer_options['custom']['BaseOption']:
        if issuer_options['custom']['BaseOption'].lower() in ['wildcard', 'gip]':
            base_option = issuer_options['custom']['BaseOption']
        else:
            raise Exception("Unsupported base option, expected wildcard/GIP.")

    order_kind = 'new'
    if issuer_options['custom']['OrderKind']:
        if issuer_options['custom']['OrderKind'] in ['new', 'renewal', 'transfer ']:
            order_kind = issuer_options['custom']['OrderKind']
        else:
             raise Exception("Unsupported order type, expected new/renewal/transfer.")


class GlobalSignIssuerPlugin(IssuerPlugin):
    title = "GlobalSign"
    slug = "globalsign-issuer"
    description = "Enables the creation of certificates by the GlobalSign SSL API Documentation v4.9 API."
    version = globalsign.VERSION

    author = "Scott Ehas"
    author_url = "https://github.com/ScottJEhas/lemur_globalsign.git"

    def __init__(self, *args, **kwargs):
        self.session = requests.Session()
        super(GlobalSignIssuerPlugin, self).__init__(*args, **kwargs)

    def create_certificate(self, csr, issuer_options):
        """
        Creates a GlobalSign certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """

        url = "{0}/kb/ws/v1/ServerSSLService?wsdl".format(current_app.config.get("GLOBALSIGN_API_URL") )
        username =  current_app.config.get("GLOBALSIGN_API_USERNAME")
        password =  current_app.config.get("GLOBALSIGN_API_PASSWORD")

        client = Client(url, username=username, password=password)  
        globalsign_data = build_globalsign_object(client, csr, issuer_options)

        current_app.logger.info(
            "Requesting a new globalsign certificate: {0}".format(csr)
        )
        current_app.logger.info(
            "Requesting a new globalsign certificate: {0}".format(issuer_options)
        )

        #return None, None, random.randrange(100000, 9999999)
        #test, current_app.config.get("GLOBALSIGN_INTERMEDIATE"), random.randrange(100000, 9999999)

    def get_ordered_certificate(self, cert):
        """ Retrieve a certificate via order id """

        current_app.logger.info(
            "Requesting PEM from pending globalsign certificate: {0}".format(cert)
        )
        
    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        role = {"username": "", "password": "", "name": "globalsign"}  
        return current_app.config.get("GLOBALSIGN_ROOT"), "", [role]
