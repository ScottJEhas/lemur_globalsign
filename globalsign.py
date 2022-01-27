import re, json
from suds.client import Client
from lemur.dns_providers import service as dns_provider_service
from lemur.plugins.lemur_globalsign import powerdns
from lemur.logs import service as log_service
from flask import current_app

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

class GlobalSign(object):
    """
    The base GlobalSign Class
    """

    def factory_option(self, product):

        if re.search('DNS' , product):
            return 'DVDNSOrder', 'QbV1DvDnsOrderRequest'
        elif re.search('URL' , product):
            return 'URLVerification',  'QbV1UrlVerificationRequest'

        raise Exception("Got an unsupported GlobalSign product type.")

    def get_dns_provider(self, type):
        provider_types = {
            "powerdns": powerdns
        }
        provider = provider_types.get(type)
        if not provider:
            raise UnknownProvider("No such DNS provider: {}".format(type))
        return provider

    def create_dns_record(self, dns_provider_id, fqdn,  dnstxt):

        dns_provider_plugin = None
        all_dns_providers = dns_provider_service.get_all_dns_providers()
        for provider in all_dns_providers:

            dns_provider_options = json.loads(provider.credentials)
            account_number = dns_provider_options.get("account_id")
            dns_provider_plugin = self.get_dns_provider(provider.provider_type)

            if dns_provider_plugin != None:
                break

        dns_provider_plugin.create_txt_record(fqdn, dnstxt, account_number=account_number)
           
    def check_dns_record(self, fqdn,  dnstxt):

        dns_provider_plugin = None
        all_dns_providers = dns_provider_service.get_all_dns_providers()
        for provider in all_dns_providers:
            
            dns_provider_plugin = self.get_dns_provider(provider.provider_type)

            if dns_provider_plugin != None:
                break

        records = dns_provider_plugin._get_txt_records(fqdn)

        is_valid = False
        for record in records:

            if record.content.strip('"') == dnstxt:
                is_valid = True
                break
        
        return is_valid

    def get_dns_txt_record(self, fqdn):

        dns_provider_plugin = None
        all_dns_providers = dns_provider_service.get_all_dns_providers()
        for provider in all_dns_providers:
            
            dns_provider_plugin = self.get_dns_provider(provider.provider_type)

            if dns_provider_plugin != None:
                break

        records = dns_provider_plugin._get_txt_records(fqdn)

        dnstxt = None
        for record in records:
            if '_globalsign-domain-verification' in record.content.strip('"'):
                dnstxt =  record.content.strip('"')
                break
        
        return dnstxt

    def delete_dns_record(self, fqdn,  dnstxt):

        dns_provider_plugin = None
        all_dns_providers = dns_provider_service.get_all_dns_providers()
        for provider in all_dns_providers:

            dns_provider_options = json.loads(provider.credentials)
            account_number = dns_provider_options.get("account_id")
            dns_provider_plugin = self.get_dns_provider(provider.provider_type)

            if dns_provider_plugin != None:
                break

        dns_provider_plugin.delete_txt_record(change_id=None, account_number=account_number, domain=fqdn,  token=dnstxt)

    def issue_ssl(self, csr, issuer_options):

        url = "{0}/kb/ws/v1/ServerSSLService?wsdl".format(current_app.config.get("GLOBALSIGN_API_URL") )
        client = Client(url, username=current_app.config.get("GLOBALSIGN_API_USERNAME"),  \
            password=current_app.config.get("GLOBALSIGN_API_PASSWORD"))  

        _soap_function_name, _product_type = self.factory_option(issuer_options.get('gsproduct'))

        globalsign_obj = client.factory.create(_product_type)

        globalsign_obj.OrderRequestHeader.AuthToken['UserName'] = current_app.config.get("GLOBALSIGN_API_USERNAME")
        globalsign_obj.OrderRequestHeader.AuthToken['Password'] = current_app.config.get("GLOBALSIGN_API_PASSWORD")
        globalsign_obj.OrderRequestParameter['ProductCode'] = issuer_options.get('gsproduct')
        if issuer_options.get('wildcard') == True:
            globalsign_obj.OrderRequestParameter['BaseOption']  = 'wildcard'
        globalsign_obj.OrderRequestParameter['OrderKind'] = 'new'
        globalsign_obj.OrderRequestParameter['Licenses'] = 1
        globalsign_obj.OrderRequestParameter.ValidityPeriod['Months'] = 12 
        globalsign_obj.OrderRequestParameter['CSR'] = csr
        globalsign_obj.ContactInfo['FirstName'] = current_app.config.get("GLOBALSIGN_FIRSTNAME")
        globalsign_obj.ContactInfo['LastName'] = current_app.config.get("GLOBALSIGN_LASTNAME")
        globalsign_obj.ContactInfo['Phone'] = current_app.config.get("GLOBALSIGN_PHONE")
        globalsign_obj.ContactInfo['Email'] = issuer_options.get('owner')

        method = getattr(client.service, _soap_function_name)
        request = method(globalsign_obj)

        if request['OrderResponseHeader']['SuccessCode'] != 0:
            error = request['OrderResponseHeader']['Errors']['Error'][0]['ErrorCode']
            raise Exception("GlobalSign returned an error: {0}".format(GLOBALSIGN_ERRORS[error]))

        if _soap_function_name == 'DVDNSOrder':

            self.create_dns_record(issuer_options.get('dns_provider'), issuer_options.get('common_name'), request['DNSTXT'])
            if self.check_dns_record(issuer_options.get('common_name'), request['DNSTXT']) == False:
                current_app.logger.info(
                    "The DNS records was not created during the order process for domain {0} with record {1}: ".format(issuer_options.get('common_name'), request['DNSTXT'])
                )

        '''URL
        Request Info (QbV1UrlVerificationResponse){
   OrderResponseHeader =
      (OrderResponseHeader){
         SuccessCode = 0
         Errors = ""
         Timestamp = "2022-01-26T18:47:53.646-05:00"
      }
   OrderID = "CEAP220127609254"
   MetaTag = "<meta name="_globalsign-domain-verification" content="M4NeIJJe1k2jVKRkwjfRVyLVYmuwLUrNCo8X_8oIXY" />"
   VerificationURLList =
      (VerificationUrlList){
         VerificationURL[] =
            "ldemo.chi3.gigenet.com",
      }
 }:
        '''
        return request['OrderID']

    def retrieve_ssl(self, pending_cert):

        url = "{0}/kb/ws/v1/GASService?wsdl".format(current_app.config.get("GLOBALSIGN_API_URL") )
        client = Client(url, username=current_app.config.get("GLOBALSIGN_API_USERNAME"),  \
            password=current_app.config.get("GLOBALSIGN_API_PASSWORD"))  

        order = client.factory.create('QbV1GetOrderByOrderIdRequest')
        order.QueryRequestHeader.AuthToken['UserName'] = current_app.config.get("GLOBALSIGN_API_USERNAME")
        order.QueryRequestHeader.AuthToken['Password'] = current_app.config.get("GLOBALSIGN_API_PASSWORD")
        order.OrderID = pending_cert.external_id
        order.OrderQueryOption.ReturnOrderOption = 'true'
        order.OrderQueryOption.ReturnCertificateInfo = 'true'
        order.OrderQueryOption.ReturnFulfillment = 'true'
        order.OrderQueryOption.ReturnCACerts = 'true'

        request = client.service.GetOrderByOrderID(order)

        _soap_function_name, _product_type = self.factory_option(request['OrderDetail']['OrderInfo']['ProductCode'])

        if int(request.OrderDetail.OrderInfo.OrderStatus) == 1:
            url = "{0}/kb/ws/v1/ServerSSLService?wsdl".format(current_app.config.get("GLOBALSIGN_API_URL") )
            verify_client = Client(url, username=current_app.config.get("GLOBALSIGN_API_USERNAME"),  \
                password=current_app.config.get("GLOBALSIGN_API_PASSWORD"))              
            
            if _soap_function_name == 'DVDNSOrder':
                verify_ssl = verify_client.factory.create('QbV1DnsVerificationForIssueRequest')
                verify_ssl.OrderRequestHeader.AuthToken['UserName'] = current_app.config.get("GLOBALSIGN_API_USERNAME")
                verify_ssl.OrderRequestHeader.AuthToken['Password'] = current_app.config.get("GLOBALSIGN_API_PASSWORD")
                verify_ssl.ApproverFQDN = pending_cert.cn
                verify_ssl.OrderID = pending_cert.external_id
                request = verify_client.service.DVDNSVerificationForIssue(verify_ssl)

                if int(request.URLVerificationForIssue.CertificateInfo.CertificateStatus) == 4:
                    intermediate = None
                    for CACert in request.URLVerificationForIssue.Fulfillment.CACertificates.CACertificate:
                        if CACert.CACertType == "INTER":
                            intermediate = CACert.CACert

                    certificate = request.URLVerificationForIssue.Fulfillment.ServerCertificate.X509Cert

                    dnstxt = self.get_dns_txt_record(pending_cert.cn)
                    self.delete_dns_record(pending_cert.cn, dnstxt)

                    return {'body': certificate, 'chain': intermediate, 'external_id': pending_cert.external_id}

        elif int(request.OrderDetail.OrderInfo.OrderStatus) == 4:

            intermediate = None
            for CACert in request.OrderDetail.Fulfillment.CACertificates.CACertificate:
                if CACert.CACertType == "INTER":
                    intermediate = CACert.CACert
    
            certificate =request.OrderDetail.Fulfillment.ServerCertificate.X509Cert

            return {'body': certificate, 'chain': intermediate, 'external_id': pending_cert.external_id}

        return {'body': None, 'chain': None, 'external_id': pending_cert.external_id}

    def modify_ssl(externalId, action):
        """
        Modify the GlobalSign SSL order.
        :param orderID:
        :return: dict or valid GlobalSign options
        """

        url = "{0}/kb/ws/v1/ServerSSLService?wsdl".format(current_app.config.get("GLOBALSIGN_API_URL") )
        client = Client(url, username=current_app.config.get("GLOBALSIGN_API_USERNAME"),  \
            password=current_app.config.get("GLOBALSIGN_API_PASSWORD"))  

        globalsign_obj = client.factory.create('QbV1ModifyOrderRequest')
        globalsign_obj.OrderRequestHeader.AuthToken['UserName'] = current_app.config.get("GLOBALSIGN_API_USERNAME")
        globalsign_obj.OrderRequestHeader.AuthToken['Password'] = current_app.config.get("GLOBALSIGN_API_PASSWORD")
        globalsign_obj.OrderID = externalId
        globalsign_obj.ModifyOrderOperation = action

        request = client.service.ModifyOrder(globalsign_obj)