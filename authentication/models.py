from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.translation import gettext_lazy as _

class Organization(models.Model):
    title = models.CharField(max_length=255,unique=True)
    def __str__(self):
        return self.title

class ACL(models.Model):
    acltype = models.CharField(max_length=255)
    topic = models.CharField(max_length=255)
    priority = models.IntegerField(default=-1)
    allow = models.CharField(max_length=255)
    def __str__(self):
        return self.allow + ' ' + self.acltype + ' on ' + self.topic

class Role(models.Model):
    organization = models.ForeignKey(to=Organization,on_delete=models.CASCADE,blank=True,null=True)
    rolename = models.CharField(max_length=255,unique=True)
    acls = models.ManyToManyField(to=ACL,blank=True)
    def __str__(self):
        return self.rolename

class RoleWithPriority (models.Model):
    role = models.ForeignKey(to=Role,on_delete=models.CASCADE)
    priority = models.IntegerField(default=-1)
    def __str__(self):
        return str(self.role.rolename) + ' With Priority ' + str(self.priority)
        

class UserManager(BaseUserManager):
    def create_user(self,username,email,password=None):
        if username is None:
            raise TypeError('Users Should Have A Username')
        if email is None:
            raise TypeError('Users Should Have A Email')
        
        user = self.model(username=username,email=self.normalize_email(email))
        user.set_password(password)
        return user

    def create_superuser(self,username,email,password):
        if password is None:
            raise TypeError('Password Should Not Be None')
        user = self.create_user(username,email,password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user

class Client(models.Model):
    username = models.CharField(max_length=255,unique=True,db_index=True)
    password = models.CharField(_("password"), max_length=128,blank=True,null=True)
    client_ID = models.CharField(max_length=255,unique=True,blank=True,null=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_add = models.DateTimeField(auto_now=True)
    roles = models.ManyToManyField(to=RoleWithPriority, blank=True,)
    organization = models.ForeignKey(to=Organization,on_delete=models.CASCADE,blank=True,null=True)


    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.username
        
class ClientWithPriority(models.Model):
    client = models.ForeignKey(to=Client,on_delete=models.CASCADE)
    priority = models.IntegerField(default=-1)
    def __str__(self):
        return str(self.client.username) + ' With Priority ' + str(self.priority)

class User(AbstractBaseUser,PermissionsMixin):
    username = models.CharField(max_length=255,unique=True,db_index=True)
    email = models.EmailField(max_length=255,unique=True,db_index=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_add = models.DateTimeField(auto_now=True)
    is_superuser = models.BooleanField(default=False)


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.username

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return{
            'refresh': str(refresh),
            'access':str(refresh.access_token)
        }

class Group(models.Model):
    organization = models.ForeignKey(to=Organization,on_delete=models.CASCADE,blank=True,null=True)
    groupname = models.CharField(max_length=255,unique=True,db_index=True)
    roles = models.ManyToManyField(to=RoleWithPriority)
    clients = models.ManyToManyField(to=ClientWithPriority)

    def __str__(self):
        return self.groupname

class AnonymousGroup(models.Model):
    group = models.ForeignKey(to=Group,on_delete=models.CASCADE)

    def __str__(self):
        return self.group.groupname


