import requests
from re import search
from suds.client import Client
from flask import current_app

from lemur.plugins import lemur_globalsign as globalsign
from lemur.plugins.bases import IssuerPlugin

GLOBALSIGN_PRODUCTS = [ 
    'EV_SHA2', #ExtendedSSL
    'OV_SHA2', #OrganizationSSL
    'DV_SHA2', #DomainSSL Email Order
    'DV_HIGH_URL_SHA2', #DomainSSL HTTP Order
    'DV_HIGH_DNS_SHA2', #DomainSSL DNS Order
    'DV_LOW_SHA2', #AlphaSSL Email Order
    'DV_LOW_URL_SHA2', #AlphaSSL HTTP Order
    'DV_LOW_DNS_SHA2' #AlphaSSL DNS Order
]

def build_globalsign_object(client, csr, issuer_options):
    '''Set the incoming issuer options to GlobalSign fields/options.
    :param csr:
    :param options:
    :return: dict or valid GlobalSign options
    
    Requesting a new globalsign certificate: {'destinations': [], 'key_type': 'ECCPRIME256V1', 'country': 'US', 'rotation': True, 'common_name': '*.gigenet.com', 'validity_end': <Arrow [2022-11-30T15:09:48.721000+00:00]>, 'description': 'GigeNET Wildcard', 'organizational_unit': 'IT', 'replaces': [], 'extensions': {'sub_alt_names': {'names': <SubjectAlternativeName(<GeneralNames([<DNSName(value='*.gigenet.com')>])>)>}, 'custom': [{'is_critical': False, 'oid': 'ProductCode', 'encoding': 'string', 'value': 'DV_LOW_DNS_SHA2'}, {'is_critical': False, 'oid': 'BaseOption', 'encoding': 'string', 'value': 'wildcard'}]}, 'rotation_policy': RotationPolicy(days=30, name=default), 'location': 'Arlighton Heights', 'authority': Authority(name=GlobalSign), 'notifications': [Notification(label=DEFAULT_SUPPORT_30_DAY), Notification(label=DEFAULT_SUPPORT_15_DAY), Notification(label=DEFAULT_SUPPORT_2_DAY)], 'roles': [], 'validity_start': <Arrow [2021-11-30T15:09:48.721000+00:00]>, 'dns_provider': None, 'validity_years': None, 'state': 'IL', 'replacements': [], 'organization': 'GigeNET', 'owner': 'support@gigenet.com', 'creator': User(username=lemur)}'''

    order_kind = 'new'
    if 'OrderKind' in issuer_options['extensions']['custom']:
        if issuer_options['extensions']['custom']['OrderKind'].lower() in ['new', 'renewal', 'transfer ']:
            order_kind = issuer_options['extensions']['custom']['OrderKind']
        else:
             raise Exception("Unsupported order kind in custom options. Expected these values: new, renewal, or transfer.")

    product_code = 'DV_LOW_SHA2'
    if 'ProductCode' in issuer_options['extensions']['custom']:
        if issuer_options['extensions']['custom']['ProductCode'].upper() in GLOBALSIGN_PRODUCTS:
            product_code = issuer_options['extensions']['custom']['ProductCode']
        else:
            raise Exception("Unsupported product code in custum options. Please see API documentation for product codes.")

    base_option = None
    if 'BaseOption' in issuer_options['extensions']['custom']:
        if issuer_options['extensions']['custom']['BaseOption'].lower() in ['wildcard', 'gip']:
            base_option = issuer_options['extensions']['custom']['BaseOption']
        else:
            raise Exception("Unsupported extra base option in custom options. Expected these values: wildcard or GIP.")

    product_type = None
    product_function_name = None

    '''
    No current use for Extended or Organization validated SSL's
    # if search('EV_' , product_code): 
    #    product_type = 'QbV1EVOrderRequest'
    #elif search('OV_' , product_code):
    #    product_type = 'QbV1OVOrderRequest'
    '''

    if search('DV_' , product_code):
        if search('URL' , product_code):
            product_type = 'QbV1UrlVerificationRequest'
            product_function_name = 'URLVerification'
        elif search('DNS' , product_code):
            product_type = 'QbV1DvDnsOrderRequest'
            product_function_name = 'DVDNSOrder'
        else:
            product_type = 'QbV1DvOrderRequest'
            product_function_name = 'DVOrder'
    else:
        raise Exception("Unsupported Domain Product type.")

    globalsign_obj = client.factory.create(product_type)

    globalsign_obj.OrderRequestHeader.AuthToken['UserName'] = current_app.config.get("GLOBALSIGN_API_USERNAME")
    globalsign_obj.OrderRequestHeader.AuthToken['Password'] = current_app.config.get("GLOBALSIGN_API_PASSWORD")
    globalsign_obj.OrderRequestParameter['ProductCode'] = product_code
    globalsign_obj.OrderRequestParameter['OrderKind'] = order_kind
    globalsign_obj.OrderRequestParameter['Licenses'] = 1
    globalsign_obj.OrderRequestParameter.ValidityPeriod['Months'] = 12 #GlobalSign Will only issue 1 Year SSL's.
    globalsign_obj.OrderRequestParameter['CSR'] = csr
    globalsign_obj.ContactInfo['Email'] = issuer_options['owner']
    
    #DNS needs ApproverEmail

    current_app.logger.info(
        "GlobalSign Object: {0}".format(globalsign_obj)
    )

    return product_function_name, globalsign_obj

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
        function_name, globalsign_data = build_globalsign_object(client, csr, issuer_options)

        method = getattr(client.service, function_name)
        request = method(globalsign_data)

        current_app.logger.info(
            "Requesting a new globalsign certificate: {0}".format(request)
        )

        #return None, None, "globalSign Tractions ID"

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
