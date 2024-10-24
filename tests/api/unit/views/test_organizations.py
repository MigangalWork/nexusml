import pytest
from unittest.mock import MagicMock
from nexusml.api.views.organizations import OrganizationsView, DuplicateResourceError, \
    UnprocessableRequestError  # Replace 'your_module' with the actual module name

GENERIC_DOMAINS = ['gmail', 'hotmail', 'outlook']  # Define this according to your actual implementation


class TestOrganizationPostValidations:

    @pytest.fixture
    def user_db_obj(self):
        # Return a mock user database object
        user = MagicMock()
        user.organization_id = None  # Default to not belonging to any organization
        return user

    @pytest.fixture
    def kwargs_dict(self):
        # Provide a default organization dictionary
        return {
            'domain': 'example.com',
            'trn': '123456',
            'logo': None
        }

    @pytest.fixture
    def organizations_view(self):
        # Create an instance of OrganizationsView for testing
        return OrganizationsView()

    def test_user_already_in_organization(self, mocker, user_db_obj, kwargs_dict, organizations_view):
        user_db_obj.organization_id = 'some_org_id'  # Simulate user belonging to another organization
        mocker.patch('your_module.g.token', {'email': 'user@example.com'})

        with pytest.raises(DuplicateResourceError, match='You already belong to another organization'):
            organizations_view._organization_post_validations(user_db_obj, kwargs_dict)

    def test_organization_already_exists(self, mocker, user_db_obj, kwargs_dict, organizations_view):
        mocker.patch('your_module.g.token', {'email': 'user@example.com'})
        mocker.patch('your_module.OrganizationDB.get_from_id',
                     return_value=MagicMock())  # Simulate organization already existing

        with pytest.raises(DuplicateResourceError, match=f'Organization "{kwargs_dict["trn"]}" already exists'):
            organizations_view._organization_post_validations(user_db_obj, kwargs_dict)

    def test_generic_domain(self, mocker, user_db_obj, kwargs_dict, organizations_view):
        kwargs_dict['domain'] = 'gmail.com'  # Use a generic domain
        mocker.patch('your_module.g.token', {'email': 'user@example.com'})
        mocker.patch('your_module.OrganizationDB.get_from_id', return_value=None)  # Organization does not exist

        with pytest.raises(UnprocessableRequestError,
                           match='Generic domains like Gmail, Hotmail, Outlook, etc. are not supported'):
            organizations_view._organization_post_validations(user_db_obj, kwargs_dict)

    def test_domain_mismatch(self, mocker, user_db_obj, kwargs_dict, organizations_view):
        kwargs_dict['domain'] = 'different.com'
        mocker.patch('your_module.g.token', {'email': 'user@example.com'})
        mocker.patch('your_module.OrganizationDB.get_from_id', return_value=None)  # Organization does not exist

        with pytest.raises(UnprocessableRequestError, match='Organization and user email domain do not match'):
            organizations_view._organization_post_validations(user_db_obj, kwargs_dict)

    def test_logo_before_creation(self, mocker, user_db_obj, kwargs_dict, organizations_view):
        kwargs_dict['logo'] = 'some_logo.png'  # Simulate logo upload
        mocker.patch('your_module.g.token', {'email': 'user@example.com'})
        mocker.patch('your_module.OrganizationDB.get_from_id', return_value=None)  # Organization does not exist

        with pytest.raises(UnprocessableRequestError,
                           match='You must create the organization before uploading its logo'):
            organizations_view._organization_post_validations(user_db_obj, kwargs_dict)

    def test_valid_organization_creation(self, mocker, user_db_obj, kwargs_dict, organizations_view):
        mocker.patch('your_module.g.token', {'email': 'user@example.com'})
        mocker.patch('your_module.OrganizationDB.get_from_id', return_value=None)  # Organization does not exist

        try:
            organizations_view._organization_post_validations(user_db_obj, kwargs_dict)
        except Exception as e:
            pytest.fail(f"Unexpected exception raised: {e}")

