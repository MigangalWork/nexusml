import pytest
from werkzeug.exceptions import BadRequest
from requests import Response
import requests

from nexusml.env import ENV_AUTH0_CLIENT_ID, ENV_AUTH0_CLIENT_SECRET
from nexusml.api.external.auth0 import Auth0Manager


class TestAuth0Manager:
    """Tests for the Auth0Manager class as a whole."""

    @pytest.fixture(autouse=True)
    def setup_environment(self, monkeypatch):
        """Setup environment variables for tests."""
        Auth0Manager.auth0_domain_url = 'https://example.auth0.com'
        Auth0Manager.auth0_user_url = 'https://example.auth0.com/api/v2/users'

        monkeypatch.setenv(ENV_AUTH0_CLIENT_ID, 'your_client_id')
        monkeypatch.setenv(ENV_AUTH0_CLIENT_SECRET, 'your_client_secret')

    class TestInit:
        """Tests for the __init__ method of Auth0Manager."""

        def test_initialization_with_token(self):
            auth0_token: str = 'some_token'
            auth0_manager: Auth0Manager = Auth0Manager(auth0_token=auth0_token)
            assert auth0_manager._auth0_token == auth0_token
            assert auth0_manager.authorization_headers['Authorization'] == f'Bearer {auth0_token}'

        def test_initialization_without_token(self, mocker):
            mock_set_header = mocker.patch.object(Auth0Manager, 'set_header')
            Auth0Manager()
            mock_set_header.assert_called_once()

    class TestSetHeader:
        """Tests for the set_header method of Auth0Manager."""

        def test_set_header(self, mocker):
            aut0_manager: Auth0Manager = Auth0Manager(auth0_token='existing_token')
            mocker.patch.object(aut0_manager, '_get_auth0_management_api_token', return_value='new_token')

            aut0_manager.set_header()

            assert aut0_manager._auth0_token == 'new_token'
            assert aut0_manager.authorization_headers['Authorization'] == 'Bearer new_token'

    class TestGetAuth0ManagementApiToken:
        """Tests for the _get_auth0_management_api_token method of Auth0Manager."""

        def test_get_auth0_management_api_token(self, mocker):
            aut0_manager: Auth0Manager = Auth0Manager(auth0_token='some_token')
            mock_response = mocker.Mock(spec=Response)
            mock_response.json.return_value = {'access_token': 'mock_access_token'}
            mocker.patch('requests.post', return_value=mock_response)

            token = aut0_manager._get_auth0_management_api_token()

            assert token == 'mock_access_token'
            requests.post.assert_called_once_with(
                'https://example.auth0.com/oauth/token',
                json={
                    'grant_type': 'client_credentials',
                    'client_id': 'your_client_id',
                    'client_secret': 'your_client_secret',
                    'audience': 'https://example.auth0.com/api/v2/',
                },
                headers={'Content-Type': 'application/json'}
            )

    class TestGetAuth0UserData:
        """Tests for the get_auth0_user_data method of Auth0Manager."""

        def test_get_auth0_user_data_by_email(self, mocker):
            aut0_manager: Auth0Manager = Auth0Manager(auth0_token='some_token')
            mock_response = mocker.Mock(spec=Response)
            mock_response.status_code = 200
            mock_response.json.return_value = [{'email': 'user@example.com'}]
            mocker.patch('requests.get', return_value=mock_response)

            result = aut0_manager.get_auth0_user_data(auth0_id_or_email='user@example.com')

            assert result == {'email': 'user@example.com'}
            requests.get.assert_called_once_with(
                'https://example.auth0.com/api/v2/users?q=email:user%40example.com&search_engine=v3',
                headers=aut0_manager.authorization_headers
            )

        def test_get_auth0_user_data_by_auth0_id(self, mocker):
            manager = Auth0Manager(auth0_token='some_token')
            mock_response = mocker.Mock(spec=Response)
            mock_response.status_code = 200
            mock_response.json.return_value = {'user_id': 'auth0|123456'}
            mocker.patch('requests.get', return_value=mock_response)

            result = manager.get_auth0_user_data(auth0_id_or_email='auth0|123456')

            assert result == {'user_id': 'auth0|123456'}
            requests.get.assert_called_once_with(
                'https://example.auth0.com/api/v2/users/auth0%7C123456',
                headers=manager.authorization_headers
            )

        def test_get_auth0_user_data_not_found(self, mocker):
            aut0_manager: Auth0Manager = Auth0Manager(auth0_token='some_token')
            mock_response = mocker.Mock(spec=Response)
            mock_response.status_code = 404
            mocker.patch('requests.get', return_value=mock_response)

            with pytest.raises(BadRequest):
                aut0_manager.get_auth0_user_data(auth0_id_or_email='unknown_user')

    class TestDeleteAuth0User:
        """Tests for the delete_auth0_user method of Auth0Manager."""

        def test_delete_auth0_user(self, mocker):
            aut0_manager: Auth0Manager = Auth0Manager(auth0_token='some_token')
            mock_response = mocker.Mock(spec=Response)
            mock_response.raise_for_status = mocker.Mock()
            mocker.patch('requests.delete', return_value=mock_response)

            aut0_manager.delete_auth0_user(auth0_id='auth0|123456')

            requests.delete.assert_called_once_with(
                'https://example.auth0.com/api/v2/users/auth0|123456',
                headers=aut0_manager.authorization_headers
            )

        def test_delete_auth0_user_failed(self, mocker):
            aut0_manager: Auth0Manager = Auth0Manager(auth0_token='some_token')
            mock_response = mocker.Mock(spec=Response)
            mock_response.raise_for_status.side_effect = requests.HTTPError("User deletion failed")
            mocker.patch('requests.delete', return_value=mock_response)

            with pytest.raises(requests.HTTPError):
                aut0_manager.delete_auth0_user(auth0_id='auth0|123456')

    class TestPatchAuth0User:
        """Tests for the patch_auth0_user method of Auth0Manager."""

        def test_patch_auth0_user(self, mocker, app):
            aut0_manager: Auth0Manager = Auth0Manager(auth0_token='some_token')
            mock_response = mocker.Mock(spec=Response)
            mock_response.raise_for_status = mocker.Mock()
            mocker.patch('requests.patch', return_value=mock_response)

            with app.app_context():
                mocker.patch('nexusml.api.external.auth0.g',
                             new_callable=mocker.PropertyMock,
                             user_auth0_id='auth0|123456')
                aut0_manager.patch_auth0_user(updated_data={'email': 'newemail@example.com'})

            requests.patch.assert_called_once_with(
                'https://example.auth0.com/api/v2/users/auth0|123456',
                json={'email': 'newemail@example.com'},
                headers={'Authorization': 'Bearer some_token', 'content-type': 'application/json'}
            )

        def test_patch_auth0_user_failed(self, mocker, app):
            aut0_manager: Auth0Manager = Auth0Manager(auth0_token='some_token')
            mock_response = mocker.Mock(spec=Response)
            mock_response.raise_for_status.side_effect = requests.HTTPError("User patch failed")
            mocker.patch('requests.patch', return_value=mock_response)

            with app.app_context():
                mocker.patch('nexusml.api.external.auth0.g',
                             new_callable=mocker.PropertyMock,
                             user_auth0_id='auth0|123456')

                with pytest.raises(requests.HTTPError):
                    aut0_manager.patch_auth0_user(updated_data={'email': 'newemail@example.com'})
