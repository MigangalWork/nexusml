import re
import urllib.parse
import uuid

import requests
from flask import json, g
from requests import Response
import os

from werkzeug.exceptions import BadRequest

from nexusml.env import ENV_AUTH0_DOJO_ACTIONS_CLIENT_ID, ENV_OAUTH_CONNECTION_ID, ENV_AUTH0_CLIENT_ID, \
    ENV_AUTH0_CLIENT_SECRET
from nexusml.env import ENV_AUTH0_DOMAIN


class Auth0Manager:
    auth0_domain_url: str = f'https://{os.environ[ENV_AUTH0_DOMAIN]}'
    auth0_user_url: str = f'https://{os.environ[ENV_AUTH0_DOMAIN]}/api/v2/users'

    def __init__(self, auth0_token: str = "") -> None:
        self._auth0_token: str = auth0_token
        self.authorization_headers: dict = {'Authorization': 'Bearer ' + auth0_token}

        if auth0_token == "":
            self.set_header()

    def set_header(self) -> None:
        auth0_token: str = self._get_auth0_management_api_token()
        self.authorization_headers = {'Authorization': 'Bearer ' + auth0_token}
        self._auth0_token = auth0_token

    def _get_auth0_management_api_token(self) -> str:
        """
        Retrieves the Auth0 Management API token required for accessing the Auth0 database.

        This function sends a POST request to the Auth0 token endpoint with the necessary credentials,
        including client ID, client secret, and audience. The returned access token is used for making
        further Auth0 Management API calls.

        Returns:
            str: The Auth0 Management API access token.
        """
        access_token: str
        payload: dict = {
            'grant_type': 'client_credentials',
            'client_id': os.environ[ENV_AUTH0_CLIENT_ID],
            'client_secret': os.environ[ENV_AUTH0_CLIENT_SECRET],
            'audience': f'{self.auth0_domain_url}/api/v2/'
        }

        headers: dict = {'Content-Type': 'application/json'}

        response_data: Response = requests.post(f'{self.auth0_domain_url}/oauth/token',
                                                json=payload,
                                                headers=headers)
        json_data: dict = response_data.json()
        access_token = json_data['access_token']

        return access_token


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
            url: str = f'{self.auth0_user_url}?q=email:{user_uuid_or_email}&search_engine=v3'
        else:
            url: str = f'{self.auth0_user_url}/{user_uuid_or_email}'

        response: Response = requests.get(url, headers=self.authorization_headers)
        if response.status_code != 200:
            raise BadRequest(description=f'No oauth Account associated with email "{user_uuid_or_email}"')

        account_data = response.json()
        if account_data and isinstance(account_data, list):
            account_data: dict = account_data[0]

        return account_data

    def get_auth0_user_data(self, auth0_id_or_email: str) -> dict:
        """
        Matches an Auth0 ID or email to retrieve the associated user data.

        This function checks if the provided identifier is an email or an Auth0 ID, constructs the appropriate URL,
        and sends a GET request to retrieve the user account data. If the identifier is an email, it searches by email;
        otherwise, it searches by Auth0 ID.

        WARNING: If more than one user data is received in the response, only the first user data will be returned

        Args:
            auth0_id_or_email (str): The Auth0 ID or email to match.

        Returns:
            dict: The matched user data.

        Raises:
            BadRequest: If no Auth0 user is associated with the provided identifier.
        """
        auth0_user_data: dict
        encoded_email_or_auth0_id = urllib.parse.quote(auth0_id_or_email)

        regex_email = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        if re.fullmatch(regex_email, auth0_id_or_email):
            url = f'{self.auth0_user_url}?q=email:{encoded_email_or_auth0_id}&search_engine=v3'
        else:
            url = f'{self.auth0_user_url}/{encoded_email_or_auth0_id}'

        response: Response = requests.get(url, headers=self.authorization_headers)
        if response.status_code != 200:
            raise BadRequest(description=f'No Auth0 user associated with "{auth0_id_or_email}"')

        auth0_user_data = response.json()
        if auth0_user_data and isinstance(auth0_user_data, list):
            auth0_user_data: dict = auth0_user_data[0]

        return auth0_user_data

    def delete_auth0_user(self, auth0_id: str) -> None:
        """
        Deletes an Auth0 user account based on the provided Auth0 ID.

        This function retrieves an Auth0 management API token, constructs the URL for the user deletion endpoint,
        and sends a DELETE request to remove the user.

        Args:
            auth0_id (str): The Auth0 ID of the user to delete.

        Raises:
            requests.HTTPError: If the DELETE request does not return a status code of 2XX.
        """
        url = f'{self.auth0_user_url}/{auth0_id}'
        response: Response = requests.delete(url, headers=self.authorization_headers)
        response.raise_for_status()

    def patch_auth0_user(self, updated_data: dict):
        url = f'{self.auth0_user_url}/{g.user_auth0_id}'
        headers: dict = self.authorization_headers
        headers['content-type'] = 'application/json'

        response: Response = requests.patch(url, json=updated_data, headers=headers)
        response.raise_for_status()
