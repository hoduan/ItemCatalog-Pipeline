from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random, string
from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))


class User_Profile(Base):
	__tablename__ = 'user_profile'
        id = Column(Integer, primary_key=True)
        first_name = Column(String)
        last_name = Column(String)
        username = Column(String)
        email = Column(String(250), unique=True)

class User(Base):
        __tablename__ = 'user'
        user_profile_id = Column(Integer, ForeignKey('user_profile.id'), primary_key=True)
        username = Column(String, nullable=False)
	email = Column(String(250))
        password_hash = Column(String(64), nullable=False)
	picture = Column(String(250))
	user_profile = relationship(User_Profile)

        def hash_password(self, password):
                self.password_hash = pwd_context.encrypt(password)

        def verify_password(self, password):
                return pwd_context.verify(password, self.password_hash)


        def generate_auth_token(self, expiration=600):
                s = Serializer(secret_key, expires_in = expiration)
                return s.dumps({'id': self.id})


        @staticmethod
        def verify_auth_token(token):
                s = Serializer(secret_key)
                try:
                        data = s.loads(token)
                except SignatureExpired:
                        return None
                except BadSignature:
                        return None

                user_id = data['id']
                return user_id

	@classmethod
	def find_by_email(cls, email):
		
		return cls.query.filter_by(email=email).first()

	@classmethod
	def find_by_id(cls, _id):
		return cls.query.filter_by(user_profile_id=_id).first() 

        @property
        def serialize(self):
                return {
                        'username': self.username,
                        'id': self.id
                }
class Google_Account(Base):
	__tablename__ = 'google_account'
	user_profile_id = Column(Integer, ForeignKey('user_profile.id'), primary_key=True)
	google_id = Column(Integer, nullable=False)
	user_profile = relationship(User_Profile)
	

class Facebook_Account(Base):
	__tablename__ = 'facebook_account'
        user_profile_id = Column(Integer, ForeignKey('user_profile.id'), primary_key=True)
        facebook_id = Column(Integer, nullable=False)
	user_profile = relationship(User_Profile)


class Category(Base):
        __tablename__ = 'category'
        id = Column(Integer, primary_key = True)
        name = Column(String, nullable=False)
        description = Column(String)

        @property
        def serialize(self):
                return {
                        'id': self.id,
                        'name': self.name,
                        'description': self.description
                }

class Item(Base):
	__tablename__ = 'item'
        id = Column(Integer, primary_key = True)
        name = Column(String, nullable=False)
        description = Column(String)
	category_id = Column(Integer, ForeignKey('category.id'))
	category = relationship(Category)

        @property
        def serialize(self):
                return {
                        'id': self.id,
                        'Title': self.name,
                        'description': self.description,
			'category_id': self.category_id
                }





engine = create_engine('sqlite:///catalog.db')
Base.metadata.create_all(engine)
