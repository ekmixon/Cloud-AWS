import logging
import os

import boto3


class CredVault():

    def __init__(self):
        self.region = os.environ['AWS_REGION']
        self.logger = logging.getLogger()
        self.logger.setLevel(level=logging.INFO)

    def _getParameter(self, param_name):
        """
        This function reads a secure parameter from AWS' SSM service.
        The request must be passed a valid parameter name, as well as
        temporary credentials which can be used to access the parameter.
        The parameter's value is returned.
        """
        # Create the SSM Client
        try:

            ssm = boto3.client('ssm', region_name=self.region)
            self.logger.debug(f'Got ssm Client {ssm}')
            # Get the requested parameter
            response = ssm.get_parameters(
                Names=[
                    param_name,
                ],
                WithDecryption=True
            )
            self.logger.debug(f'Got response to get params {response}')
        except Exception as e:
            self.logger.debug(f'Got exception to get params {e}')

        return response['Parameters'][0]['Value']

    def get(self):
        try:
            self.falcon_client_id = self._getParameter("FIG_FALCON_CLIENT_ID")
            self.falcon_client_secret = self._getParameter("FIG_FALCON_CLIENT_SECRET")
            self.logger.debug(f'self.falcon_client_id {self.falcon_client_secret}')
            return {
                'falcon_client_id': self.falcon_client_id,
                'falcon_client_secret': self.falcon_client_secret,
            }


        except Exception as e:
            self.logger.debug(f'Got exception to get params {e}')
