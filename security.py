from models import User


def authenticate(email, password):
	user = User.find_by_email(email)
	if user and user.password == user.hash_password(password):
		return user


def identity(payload):
	user_profile_id = payload['identity']
	return User.find_by_id(user_id)
