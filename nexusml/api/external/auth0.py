import re
import uuid

import requests
from flask import json
from requests import Response
import os

from werkzeug.exceptions import BadRequest

from dojo.api.database.organizations import OrganizationDB
from dojo.env import ENV_OAUTH_DOJO_ACTIONS_CLIENT_ID, ENV_OAUTH_CONNECTION_ID
from dojo.env import ENV_OAUTH_DOJO_ACTIONS_CLIENT_SECRET
from dojo.env import ENV_OAUTH_DOMAIN
from dojo.env import ENV_OAUTH_DOJO_ACTIONS_CLIENT_ID


class Oauth:
    oauth_domain_url: str = f'https://{os.environ[ENV_OAUTH_DOMAIN]}'
    oauth_user_url: str = f'https://{os.environ[ENV_OAUTH_DOMAIN]}/api/v2/users'

    def __init__(self, oauth_token: str = "") -> None:
        self._oauth_token: str = oauth_token
        self.authorization_headers: dict = {'Authorization': 'Bearer ' + oauth_token}

        if oauth_token == "":
            self.set_header()

    def set_header(self) -> None:
        oauth_token: str = self._get_oauth_management_api_token()
        self.authorization_headers = {'Authorization': 'Bearer ' + oauth_token}
        self._oauth_token = oauth_token

    def _get_oauth_management_api_token(self) -> str:
        """

        Returns:

        """
        # Used to get the oauth management api token that allows us to access the user info stored in oauth databases
        access_token_to_return: str
        payload: dict = {
            'grant_type': 'client_credentials',
            'client_id': os.environ[ENV_OAUTH_DOJO_ACTIONS_CLIENT_ID],
            'client_secret': os.environ[ENV_OAUTH_DOJO_ACTIONS_CLIENT_SECRET],
            'audience': f'{self.oauth_domain_url}/api/v2/'
        }

        headers: dict = {'Content-Type': 'application/json'}

        response: Response = requests.post(f'/oauth/token',
                                           json=payload, headers=headers)
        json_data: dict = response.json()
        access_token_to_return = json_data['access_token']

        return access_token_to_return

    def match_oauth_user_uuid_or_email(self, access_token: str, user_uuid_or_email: str) -> dict:
        """

        Args:
            access_token (str):
            user_uuid_or_email:

        Returns:

        """
        account_data: dict

        regex_email = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        if re.fullmatch(regex_email, user_uuid_or_email):
            url: str = f'{self.oauth_user_url}?q=email:{user_uuid_or_email}&search_engine=v3'
        else:
            url: str = f'{self.oauth_user_url}/{user_uuid_or_email}'

        response: Response = requests.get(url, headers=self.authorization_headers)
        if response.status_code != 200:
            raise BadRequest(description=f'No oauth Account associated with email "{user_uuid_or_email}"')

        account_data = response.json()
        if account_data and isinstance(account_data, list):
            account_data: dict = account_data[0]

        return account_data

    def delete_oauth_user(self, oauth_id: str) -> None:
        url = f'{self.oauth_user_url}/{oauth_id}'
        res = requests.delete(url, headers=self.authorization_headers)
        if res.status_code != 204:
            raise BadRequest(description="Invalid status code received from the external service.")

    def create_user_account(self, email: str, org_uuid: str) -> int:
        oauth_user_id: int

        payload = {'email': email,
                   'connection': 'Username-Password-Authentication',
                   'password': f'{uuid.uuid4()}',
                   'email_verified': True,
                   'user_metadata': {
                       'organization_id': f'{org_uuid}'
                   }}

        res = requests.post(self.oauth_user_url, json=payload, headers=self.authorization_headers)

        oauth_user_id = json.loads(res.text)['user_id']
        return oauth_user_id

    def send_invitation_from_oauth(self, email: str) -> str:
        url: str = f'{self.oauth_domain_url}/api/v2/tickets/password-change'
        payload = {'result_url': 'https://app.enaia.ai',
                   'connection_id': os.environ[ENV_OAUTH_CONNECTION_ID],
                   'email': email,
                   'ttl_sec': 604800000,
                   'mark_email_as_verified': True}  # expires after 7 days

        res = requests.post(url, json=payload, headers=self.authorization_headers)
        if res.status_code != 204:
            raise BadRequest(description=f"Unable to send invitation email from Oauth to email - {email}.")

        ticket_url: str = json.loads(res.text)['ticket']
        return ticket_url
