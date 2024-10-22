# TODO: Try to make this module independent from `nexusml.api`

from datetime import datetime
from datetime import timedelta
import os
from typing import List, Union
import uuid

import jwt
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import ForeignKey
from sqlalchemy import JSON
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import Text
from sqlalchemy import UniqueConstraint
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.dialects.mysql import INTEGER
from sqlalchemy.dialects.mysql import MEDIUMINT
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import relationship

from nexusml.api.utils import config
from nexusml.constants import ADMIN_ROLE
from nexusml.constants import API_NAME
from nexusml.constants import API_VERSION
from nexusml.constants import MAINTAINER_ROLE
from nexusml.constants import NUM_RESERVED_CLIENTS
from nexusml.database.base import BinaryUUID
from nexusml.database.base import DBModel
from nexusml.database.base import Entity
from nexusml.database.core import db
from nexusml.database.core import db_commit
from nexusml.database.core import db_rollback
from nexusml.database.core import save_to_db
from nexusml.database.utils import save_or_ignore_duplicate
from nexusml.enums import InviteStatus
from nexusml.env import ENV_WEB_CLIENT_ID

#################
# Organizations #
#################


class OrganizationDB(Entity):
    """
    Attributes:
        - organization_id (PK): surrogate key
        - trn (unique): Tax Registration Number (TRN). It might also be known as the Tax Identification Number (TIN),
                        Taxpayer Identification Number (TIN), Value-Added Tax (VAT) number, VAT ID,
                        VAT registration number, or Business Registration Number.
        - name: name of the organization
        - domain: organization's domain (e.g. "neuraptic.ai")
        - address: business legal address
        - logo (FK): surrogate key of the file containing the image
    """

    __tablename__ = 'organizations'

    organization_id = Column(MEDIUMINT(unsigned=True), primary_key=True, autoincrement=True)
    trn = Column(String(32), unique=True, nullable=False)
    name = Column(String(64), nullable=False)
    domain = Column(String(64), nullable=False)
    address = Column(String(128), nullable=False)

    # We set the logo in `database.models.files` due to the circular dependency
    # logo = Column(INTEGER(unsigned=True), ForeignKey(OrgFileDB.file_id, ondelete='SET NULL'))

    # Children (One-to-Many relationships)
    users = db.relationship('UserDB', backref='user', cascade='all, delete-orphan', lazy='dynamic')
    # Note: don't pass `backref` because `OrganizationER` defines a parent (many-to-one) relationship with this class
    # users = db.relationship('UserDB', backref='user', cascade='all, delete-orphan', lazy='dynamic')
    roles = relationship('RoleDB', cascade='all, delete-orphan', lazy='selectin')
    collaborators = db.relationship('CollaboratorDB', cascade='all, delete-orphan', lazy='dynamic')


class OrganizationER(DBModel):
    """ Represents an entity or an association of an organization.

    Attributes:
        - organization_id (FK): parent organization's surrogate key
    """
    __abstract__ = True

    @declared_attr
    def organization_id(cls):
        return Column(MEDIUMINT(unsigned=True),
                      ForeignKey(OrganizationDB.organization_id, ondelete='CASCADE'),
                      nullable=False)

    @declared_attr
    def organization(cls):
        return relationship('OrganizationDB')

    @classmethod
    def filter_by_organization(cls, organization_id) -> list:
        return cls.query().filter_by(organization_id=organization_id).all()


###################################
# Users, Roles, and Collaborators #
###################################


class UserDB(Entity):
    """ Users.

    WARNING: User profile data is not stored in NexusML, since it is downloaded from the associated Auth0 user.

    Attributes:
        - user_id (PK): surrogate key
        - organization_id (FK): surrogate key of the organization to which the user belongs
    """
    __tablename__ = 'users'

    uuid = Column(BinaryUUID, unique=True, nullable=False, default=uuid.uuid4)
    auth0_id = Column(String(64), unique=True, nullable=False)  # Generated by Auth0
    user_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    organization_id = Column(INTEGER(unsigned=True), ForeignKey(OrganizationDB.organization_id))

    # organization = db.relationship('OrganizationDB', backref=db.backref('UserDB'))

    # Many-to-Many relationships
    roles = db.relationship('RoleDB',
                            secondary='user_roles',
                            backref=db.backref('users', lazy='dynamic'),
                            lazy='selectin')

    @classmethod
    def filter_by_organization(cls, organization_id) -> list:
        return cls.query().filter_by(organization_id=organization_id).all()


class RoleDB(Entity, OrganizationER):
    """ Roles

    Attributes:
        - role_id (PK): role's surrogate key
        - organization_id (FK): surrogate key of the organization to which the role belongs
        - name: role name (unique for each organization)
        - description: role description
    """
    __tablename__ = 'roles'
    __table_args__ = (UniqueConstraint('organization_id', 'name'),)

    role_id = Column(MEDIUMINT(unsigned=True), primary_key=True, autoincrement=True)
    name = Column(String(64), nullable=False)
    description = Column(String(256))


class CollaboratorDB(Entity, OrganizationER):
    """ Collaborators (external users not belonging to the organization).

    Attributes:
        - collaborator_id (PK): surrogate key
        - user_id (FK): surrogate key of the user acting as a collaborator
        - organization_id (FK): surrogate key of the organization the user is collaborating with
    """
    __tablename__ = 'collaborators'
    __table_args__ = (UniqueConstraint('organization_id', 'user_id'),)

    collaborator_id = Column(INTEGER(unsigned=True), primary_key=True, autoincrement=True)
    user_id = Column(INTEGER(unsigned=True), ForeignKey(UserDB.user_id, ondelete='CASCADE'))

    # Parents (Many-to-One relationships)
    user = relationship('UserDB')


user_roles = Table('user_roles',
                   db.Model.metadata,
                   Column('user_id',
                          INTEGER(unsigned=True),
                          ForeignKey(UserDB.user_id, ondelete='CASCADE'),
                          primary_key=True,
                          nullable=False),
                   Column('role_id',
                          MEDIUMINT(unsigned=True),
                          ForeignKey(RoleDB.role_id, ondelete='CASCADE'),
                          primary_key=True,
                          nullable=False),
                   mysql_engine='InnoDB')


###########
# Clients #
###########


def _generate_api_key(client_uuid: str,
                      scopes: List[str] = None,
                      expire_at: datetime = None,
                      never_expire: bool = False) -> str:
    now = datetime.utcnow()
    # Set expiration datetime
    if not never_expire:
        if expire_at is None:
            exp_delta = timedelta(seconds=config.get('security')['api_keys']['expiration'])
            expire_at = now + exp_delta
        assert expire_at > now
    # Set scopes (default = all supported client scopes)
    if scopes is not None:
        assert all(scope in client_scopes for scope in scopes)  # some API scopes are supported only for users
    else:
        scopes = client_scopes
    # Build token
    # See https://www.iana.org/assignments/jwt/jwt.xhtml#claims
    token_claims = {
        'iss': API_NAME,
        'aud': client_uuid,
        'iat': now,
        'jti': str(uuid.uuid4()),
        'scope': (' '.join(sorted(scopes))),
        'api_version': API_VERSION,
    }
    if not never_expire:
        token_claims['exp'] = expire_at
    return jwt.encode(payload=token_claims, key=config.rsa_private_key(), algorithm='RS256')


def _client_default_api_key(context):
    return _generate_api_key(client_uuid=str(context.get_current_parameters()['uuid']))


class ClientDB(Entity, OrganizationER):
    """ Clients consuming the API.

    Attributes:
        - client_id (PK): surrogate key
        - organization_id (FK): surrogate key of the organization to which the client belongs
        - name: client name
        - description: client description
        - icon (FK): surrogate key of the file containing the image
        - api_key: JSON Web Token (JWT) bearer token to include in API requests made by the client
    """
    __tablename__ = 'clients'

    client_id = Column(MEDIUMINT(unsigned=True), primary_key=True, autoincrement=True)
    auth0_id = Column(String(64), nullable=True, default=None)  # Generated by Auth0
    name = Column(String(64), nullable=False)
    description = Column(String(256))
    # We set the icon in `database.models.files` due to the circular dependency
    # icon = Column(INTEGER(unsigned=True), ForeignKey(OrgFileDB.file_id, ondelete='SET NULL'))
    api_key = Column(Text, nullable=False, default=_client_default_api_key)  # TODO: can we set a fixed length?

    def update_api_key(self, scopes: List[str] = None, expire_at: datetime = None, never_expire: bool = False) -> str:
        """ Updates client's API key.

        Args:
            scopes: list of scopes. If not provided, all scopes will be included
            expire_at: expiration datetime (UTC). If not provided, it will be retrieved from the app config
            never_expire: if `True`, the API key will never expire. In such a case, `expire_at` argument will be
                          ignored and the `exp` claim will not be included in the API key token.

        Returns:
            str: JSON Web Token (JWT) bearer token to include in API requests made by the client
        """

        # Update database object
        self.api_key = _generate_api_key(client_uuid=str(self.uuid),
                                         scopes=scopes,
                                         expire_at=expire_at,
                                         never_expire=never_expire)
        db_commit()
        return self.api_key


client_scopes = sorted([
    # Organizations
    'organizations.read',
    # Tasks
    'tasks.read',
    'tasks.update',
    'tasks.delete',
    # Files
    'files.create',
    'files.read',
    'files.delete',
    # Models
    'models.create',
    'models.read',
    # Examples
    'examples.create',
    'examples.read',
    'examples.update',
    'examples.delete',
    # Predictions
    'predictions.create',
    'predictions.read',
    'predictions.delete'
])


##############################################
# Entities created/modified by users/clients #
##############################################


class ImmutableEntity(Entity):
    """
    Attributes:
        - created_at: creation date
        - created_by_user: surrogate key of the user who created the entity
        - created_by_client: surrogate key of the client which created the entity
    """
    __abstract__ = True

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    @declared_attr
    def created_by_user(cls):
        return Column(INTEGER(unsigned=True), ForeignKey(UserDB.user_id, ondelete='SET NULL'))

    @declared_attr
    def created_by_client(cls):
        return Column(MEDIUMINT(unsigned=True), ForeignKey(ClientDB.client_id, ondelete='SET NULL'))


class MutableEntity(Entity):
    """
    Attributes:
        - created_at: creation date
        - created_by_user: surrogate key of the user who created the entity
        - created_by_client: surrogate key of the client which created the entity
        - modified_at: modification date
        - modified_by_user: surrogate key of the user who last modified the entity
        - modified_by_client: surrogate key of the client which last modified the entity
        - synced_by_users: surrogate keys of the users that retrieved the last version of the entity
        - synced_by_clients: surrogate keys of the clients that retrieved the last version of the entity
    """
    __abstract__ = True

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    modified_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    synced_by_users = Column(MutableList.as_mutable(JSON(none_as_null=True)), default=[])
    synced_by_clients = Column(MutableList.as_mutable(JSON(none_as_null=True)), default=[])

    @declared_attr
    def created_by_user(cls):
        return Column(INTEGER(unsigned=True), ForeignKey(UserDB.user_id, ondelete='SET NULL'))

    @declared_attr
    def created_by_client(cls):
        return Column(MEDIUMINT(unsigned=True), ForeignKey(ClientDB.client_id, ondelete='SET NULL'))

    @declared_attr
    def modified_by_user(cls):
        return Column(INTEGER(unsigned=True), ForeignKey(UserDB.user_id, ondelete='SET NULL'))

    @declared_attr
    def modified_by_client(cls):
        return Column(MEDIUMINT(unsigned=True), ForeignKey(ClientDB.client_id, ondelete='SET NULL'))

    def update_sync_state(self, agent: Union[UserDB, ClientDB], commit: bool = True) -> bool:
        """
        Updates object's sync state for the given agent.

        Args:
            agent (Union[UserDB, ClientDB]): user or client
            commit (bool): commit changes

        Returns:
            bool: `True` if the sync state was updated (i.e., the agent was out of sync)
        """
        init_users = list(self.synced_by_users or [])
        init_clients = list(self.synced_by_clients or [])

        if self.synced_by_users is None:
            self.synced_by_users = []
        if self.synced_by_clients is None:
            self.synced_by_clients = []

        if isinstance(agent, UserDB) and agent.user_id not in self.synced_by_users:
            self.synced_by_users.append(agent.user_id)
        if isinstance(agent, ClientDB) and agent.client_id not in self.synced_by_clients:
            self.synced_by_clients.append(agent.client_id)

        if self.synced_by_users != init_users or self.synced_by_clients != init_clients:
            if commit:
                save_to_db(self)
            return True
        else:
            return False


#################
# Invitations #
#################


class InvitationDB(OrganizationER):
    """
    Invitations sent to users to join an organization.

    Attributes:
        id_ (int): Surrogate key of the invitation.
        uuid (UUID): Unique identifier for the invited user.
        email (str): Email address of the invited user.
        status (InviteStatus): Current status of the invitation (e.g., pending, accepted).
        created_at (datetime): Timestamp when the invitation was created.

    Enums:
        InviteStatus: Enum representing the possible statuses of an invitation:
            - pending (0): Invitation is pending.
            - accepted (1): Invitation has been accepted.
    """

    __tablename__ = 'invitations'

    id_ = Column(MEDIUMINT(unsigned=True), primary_key=True, autoincrement=True)
    uuid = Column(BinaryUUID, unique=True, nullable=False, default=uuid.uuid4)
    email = Column(String(64), nullable=False)
    status = Column(Enum(InviteStatus), nullable=False, default=InviteStatus.PENDING)
    created_at = Column(DATETIME, nullable=False, default=datetime.utcnow)


#############
# Wait list #
#############


class WaitList(DBModel):
    """
    List of accounts that tried to create an organization after the limit of organizations was exceeded.

    Attributes:
        - id_ (PK): surrogate key
        - uuid (unique): user UUID
        - email (unique): user email
        - first_name: given name
        - last_name: family name
        - company: company name
        - request_date: datetime at which the user joined the wait list
    """

    __tablename__ = 'waitlist'

    id_ = Column(MEDIUMINT(unsigned=True), primary_key=True, autoincrement=True)
    uuid = Column(BinaryUUID, unique=True, nullable=False)
    email = Column(String(64), unique=True, nullable=False)
    first_name = Column(String(64))
    last_name = Column(String(64))
    company = Column(String(64))
    request_date = Column(DateTime, nullable=False, default=datetime.utcnow)


#########################
# Database default rows #
#########################


def create_default_organization():
    default_org = OrganizationDB.get(organization_id=1)
    if default_org is None:
        default_org = OrganizationDB(organization_id=1,
                                     trn='',
                                     name='NexusML',
                                     domain='',
                                     address='')
        save_to_db(default_org)


def create_default_admin_and_maintainer_roles():
    """
    Create default roles
    """

    roles = [
        RoleDB(role_id=1, organization_id=1, name=ADMIN_ROLE, description='Administrator'),
        RoleDB(role_id=2, organization_id=1, name=MAINTAINER_ROLE, description='Maintainer')
    ]

    for role in roles:
        try:
            save_to_db(role)
        except Exception:
            db_rollback()
            continue

    admin = RoleDB.get(role_id=1)
    maintainer = RoleDB.get(role_id=2)
    assert admin.name == ADMIN_ROLE
    assert maintainer.name == MAINTAINER_ROLE
    assert admin.organization_id == 1
    assert maintainer.organization_id == 1


KNOWN_CLIENT_IDS = {
    'default': 1,
    'web': 2,
}

KNOWN_CLIENT_UUIDS = {
    'web': os.environ[ENV_WEB_CLIENT_ID],
}


def create_known_clients_and_reserved_clients():
    # Create the default client for testing purposes
    default_client = ClientDB(client_id=KNOWN_CLIENT_IDS['default'],
                              organization_id=1,
                              name='Default Client',
                              description='Default client for testing purposes')
    save_or_ignore_duplicate(default_client)

    # Create NexusML Web App
    web_app = ClientDB(client_id=KNOWN_CLIENT_IDS['web'],
                       organization_id=1,
                       auth0_id=KNOWN_CLIENT_UUIDS['web'],
                       name='NexusML Web App',
                       description='Interactive web application')
    saved = save_or_ignore_duplicate(web_app)
    if saved:
        web_app.update_api_key(expire_at=(datetime.utcnow() + timedelta(seconds=1)))  # disable API keys in the Web App

    # Create reserved clients
    reserved_clients = [
        ClientDB(client_id=x, organization_id=1, name=f'Reserved Official Client {x}')
        for x in range(max(KNOWN_CLIENT_IDS.values()) + 2, NUM_RESERVED_CLIENTS + 2)
    ]
    for reserved_client in reserved_clients:
        saved = save_or_ignore_duplicate(reserved_client)
        if saved:
            reserved_client.update_api_key(expire_at=(datetime.utcnow() + timedelta(seconds=1)))  # disable API keys


#########
# Types #
#########

Agent = Union[UserDB, ClientDB]
