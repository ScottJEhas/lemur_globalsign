from re import search
from flask import current_app

from lemur.plugins import lemur_globalsign as globalsign
from lemur.extensions import metrics
from lemur.plugins.bases import IssuerPlugin

from lemur.plugins.lemur_globalsign.globalsign import GlobalSign

class GlobalSignIssuerPlugin(IssuerPlugin):
    title = "GlobalSign"
    slug = "globalsign-issuer"
    description = "Enables the creation of certificates by the GlobalSign SSL API Documentation v4.9 API."
    version = globalsign.VERSION

    author = "Scott Ehas"
    author_url = "https://github.com/ScottJEhas/lemur_globalsign.git"

    def __init__(self, *args, **kwargs):
        super(GlobalSignIssuerPlugin, self).__init__(*args, **kwargs)

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


    def create_certificate(self, csr, issuer_options):
        """
        Creates a GlobalSign certificate using DNS challenge.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """

        gs = GlobalSign()
        externalId = gs.issue_ssl(csr, issuer_options)

        return None, None, externalId

    def get_ordered_certificate(self, pending_cert):
        """ Retrieve a certificate via order id """

        gs = GlobalSign()
        certificateData = gs.retrieve_ssl(pending_cert)

        if certificateData['body'] != None:
            return certificateData

    def revoke_certificate(self, certificate, reason):
        """
        Revoke a GlobalSign certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """

        gs = GlobalSign()
        gs.modify_ssl(certificate.external_id, 'REVOKE')

        metrics.send("globalsign_revoke_certificate_success", "counter", 1)

    def cancel_ordered_certificate(self, pending_cert, **kwargs):
        """
        Cancels a GlobalSign certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        gs = GlobalSign()
        gs.modify_ssl(pending_cert.external_id, 'CANCEL')

        metrics.send("globalsign_cancel_certificate_success", "counter", 1)

