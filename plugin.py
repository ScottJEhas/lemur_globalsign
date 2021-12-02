import requests
from re import search
from suds.client import Client
from flask import current_app

from lemur.plugins import lemur_globalsign as globalsign
from lemur.extensions import metrics
from lemur.plugins.bases import IssuerPlugin
from lemur.logs import service as log_service

GLOBALSIGN_ERRORS = {
    '-5001': 'Phishing warning CN matched in phishing database The Common Name has expressions that match our Phishing/Keyword warning list. ',
    '-101': 'Invalid parameter entered.',
    '-102': 'An essential parameter is missing.', 
    '-103': 'A parameter is too long.',
    '-104': 'The format for a parameter is incorrect',
    '-105': 'Invalid Parameter.',
    '-109': 'Missing Parameter',
    '-3002': 'Domain not found in WHOIS database.',
    '-3012': 'We have been unable to validate your domain through a Domain Name Search.',
    '-3013': 'We are currently experiencing issues in connecting to a DNS service to resolve your domain.',
    '-3019': 'We are currently experiencing issues in searching the DNS service to resolve your domain.',
    '-3022': 'We were unable to find the SOA Record of the DNS',
    '-3025': 'We were unable to find the SOA Record of the DNS',
    '-3026': 'We were unable to find the DNS txt record for DNS',
    '-4001': 'Login failure invalid user ID or password.',
    '-4003': 'Specified OrderID/Voucher Number does not exist.',
    '-4004': 'The specified OrderID already exists. Please make sure you supplied a valid OrderID.',
    '-4005': 'Your request has not been accepted due to a logical limitation.',
    '-4006': 'Unable to process this request. It could be that the Common Name in your CSR does not match the Common Name in the original order, or the format of the Common Name is incorrect, or the Encryption type of your CSR is not RSA nor ECC, or the length of the Key of the CSR is insufficient. Please make sure that the CSR provided coincides with these conditions.',
    '-4007': 'Specified CSR is invalid.',
    '-4008': 'Target CERT is expired or inaccessible.',
    '-4009': 'Specified ApproverEmail is invalid.',
    '-4016': 'The certificate has been already reissued.',
    '-4201': 'This IP Address is not registered for API access.',
    '-6002': 'Specified certificate is invalid.',
    '-6007': 'The public key is already used.',
    '-6017': 'Maximum number of SANs options have been exceeded.',
    '-6018': 'Specified SubjectAltName is invalid.',
    '-6021': 'CN in CSR and FQDN are not same.',
    '-6035': 'Validity Period Warning.',
    '-6101': 'Your account does not have enough remaining balance to process this request.',
    '-6102': 'Specified order cannot be a renewal.',
    '-9025': 'Could not renew because you have no renewal authority.',
    '-9100': 'Unable to process this request.',
    '-9101': 'Illegal SAN Option',
    '-9151': 'Unable to use ReissueWithoutCSR on a certificate that does not support AutoCSR.',
    '-9152': 'The format of the ApproverURL specified is incorrect.',
    '-9200': 'The type of your user is not allowed to use this API.',
    '-9902': 'You do not have permission to access the OrderID specified.',
    '-9911': 'There are insufficient funds in the account to complete the order process.',
    '-9912': 'There is insufficient funds in the account to complete the order process.',
    '-9915': 'The OrderID you are trying to modify has been cancelled previously.',
    '-9916': 'We were not able to find the OrderID specified. ',
    '-9925': 'The Common Name of your CSR or the FQDN you have entered does not match the type of BaseOption you provided.',
    '-9936': 'The key you used in your CSR is either too short (RSA minimum 2048, ECC minimum 256).',
    '-9938': 'The certificate you are trying to modify has already been modified.',
    '-9939': 'The state of this account is either invalid, stopped or locked.',
    '-9940': 'The specified NotBefore or NotAfter should not be before the current date/time.',
    '-9949': 'The NotAfter specified is after the calculated BaseLine Validity Limit.',
    '-9952': 'The Top Level Domain you specified is not supported.',
    '-9953': 'Cannot complete this request because the region or country of your Domain is not permitted.'
}

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

def globalsign_build_order(client, csr, issuer_options):
    """
    Set the incoming issuer options to GlobalSign fields/options.
    :param csr:
    :param options:
    :return: dict or valid GlobalSign options
    """

    order_kind = 'new'
    if 'OrderKind' in issuer_options['extensions']['custom']:
        if issuer_options['extensions']['custom']['OrderKind'].lower() in ['new', 'renewal', 'transfer ']:
            order_kind = issuer_options['extensions']['custom']['OrderKind']
        else:
             raise Exception("Unsupported order kind in custom options. Expected these values: new, renewal, or transfer.")

    product_code = 'DV_LOW_DNS_SHA2'
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
        raise Exception("Unsupported GlobalSign Product.")

    globalsign_obj = client.factory.create(product_type)

    globalsign_obj.OrderRequestHeader.AuthToken['UserName'] = current_app.config.get("GLOBALSIGN_API_USERNAME")
    globalsign_obj.OrderRequestHeader.AuthToken['Password'] = current_app.config.get("GLOBALSIGN_API_PASSWORD")
    globalsign_obj.OrderRequestParameter['ProductCode'] = product_code
    if base_option:
        globalsign_obj.OrderRequestParameter['BaseOption']  = base_option
    globalsign_obj.OrderRequestParameter['OrderKind'] = order_kind
    globalsign_obj.OrderRequestParameter['Licenses'] = 1
    globalsign_obj.OrderRequestParameter.ValidityPeriod['Months'] = 12 #GlobalSign Will only issue 1 Year SSL's.
    globalsign_obj.OrderRequestParameter['CSR'] = csr
    globalsign_obj.ContactInfo['FirstName'] = current_app.config.get("GLOBALSIGN_FIRSTNAME")
    globalsign_obj.ContactInfo['LastName'] = current_app.config.get("GLOBALSIGN_LASTNAME")
    globalsign_obj.ContactInfo['Phone'] = current_app.config.get("GLOBALSIGN_PHONE")
    globalsign_obj.ContactInfo['Email'] = issuer_options['owner']
    
    #DNS needs ApproverEmail
    #DNS needs OrderID

    #current_app.logger.info(
    #    "GlobalSign Object: {0}".format(globalsign_obj)
    #)

    return product_function_name, globalsign_obj

def globalsign_get_order_information(orderID):
    """
    Get the GlobalSign order information.
    :param orderID:
    :return: dict or valid GlobalSign options
    """

    url = "{0}/kb/ws/v1/GASService?wsdl".format(current_app.config.get("GLOBALSIGN_API_URL") )
    username =  current_app.config.get("GLOBALSIGN_API_USERNAME")
    password =  current_app.config.get("GLOBALSIGN_API_PASSWORD")

    client = Client(url, username=username, password=password)  

    order = client.factory.create('QbV1GetOrderByOrderIdRequest')
    order.QueryRequestHeader.AuthToken['UserName'] = username
    order.QueryRequestHeader.AuthToken['Password'] = password
    order.OrderID = orderID 

    request = client.service.GetOrderByOrderID(order)

    if  request.OrderResponseHeader.SuccessCode != '0':
        raise Exception(GLOBALSIGN_ERRORS[request.OrderResponseHeader.Errors.Error[-1]['ErrorCode']])

def globalsign_modify_order(orderID, action):
    """
    Modify the GlobalSign SSL order.
    :param orderID:
    :return: dict or valid GlobalSign options
    """

    url = "{0}/kb/ws/v1/ServerSSLService?wsdl".format(current_app.config.get("GLOBALSIGN_API_URL") )
    username =  current_app.config.get("GLOBALSIGN_API_USERNAME")
    password =  current_app.config.get("GLOBALSIGN_API_PASSWORD")

    client = Client(url, username=username, password=password)  

    globalsign_obj = client.factory.create('QbV1ModifyOrderRequest')
    globalsign_obj.OrderRequestHeader.AuthToken['UserName'] = username
    globalsign_obj.OrderRequestHeader.AuthToken['Password'] = password
    globalsign_obj.OrderID = orderID
    globalsign_obj.ModifyOrderOperation = action

    request = client.service.ModifyOrder(globalsign_obj)

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
        function_name, globalsign_data = globalsign_build_order(client, csr, issuer_options)

        method = getattr(client.service, function_name)
        request = method(globalsign_data)

        current_app.logger.info(
            "Requesting a new globalsign certificate: {0}".format(request)
        )

        return None, None, request.OrderID

    def get_ordered_certificate(self, pending_cert):
        """ Retrieve a certificate via order id """

        current_app.logger.info(
            "Requesting PEM from pending globalsign certificate: {0}".format(pending_cert)
        )

        globalsign_get_order_information(pending_cert.external_id)
        
    def revoke_certificate(self, certificate, reason):
        """
        Revoke a GlobalSign certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        current_app.logger.info(
            "Started the globalsign revoke process for {0}".format(certificate.name)
        )

        globalsign_modify_order(certificate.external_id, 'REVOKE')

        current_app.logger.info(
            "Revoked globalsign certificate order: {0}".format(certificate.external_id)
        )

        metrics.send("globalsign_revoke_certificate_success", "counter", 1)

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        """
        Cancels a GlobalSign certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """

        current_app.logger.info(
            "Started to process globalsign certificate cancellation for {0}".format(pending_cert.name)
        )

        globalsign_modify_order(pending_cert.external_id,  'CANCEL')

        current_app.logger.debug(
            "Cancelled globalsign certificate order: {0}".format(request)
        )

        metrics.send("globalsign_cancel_certificate_success", "counter", 1)

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