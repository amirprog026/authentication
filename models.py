from peewee import *
db=SqliteDatabase("usersdb.db")
class user(Model):
    username=CharField(max_length=50,primary_key=True)
    password=CharField()
    email=CharField(Null=True,unique=True)
    Name=CharField(Null=True)
    LastName=CharField(Null=True)
    class Meta:
        database=db

    @classmethod
    def create_user(cls, username, password, email=None, Name=None, LastName=None):
        try:
            user = cls.create(
                username=username,
                password=password,
                email=email,
                Name=Name,
                LastName=LastName
            )
            return user
        except IntegrityError as e:
            print(f"Error creating user: {e}")
            return None

    @classmethod
    def get_user_by_username(cls, username):
        try:
            return cls.get(cls.username == username)
        except cls.DoesNotExist:
            print(f"User with username {username} does not exist.")
            return None

    @classmethod
    def update_user(cls, username, password=None, email=None, Name=None, LastName=None):
        user = cls.get_user_by_username(username)
        if user:
            if password is not None:
                user.password = password
            if email is not None:
                user.email = email
            if Name is not None:
                user.Name = Name
            if LastName is not None:
                user.LastName = LastName
            user.save()
            return user
        return None

    @classmethod
    def delete_user(cls, username):
        user = cls.get_user_by_username(username)
        if user:
            user.delete_instance()
            return True
        return False
