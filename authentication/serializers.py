from rest_framework import serializers
from .models import ACL, Client, Group, Role, User
from rest_framework_simplejwt.tokens import RefreshToken , TokenError

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255,min_length=3)
    password = serializers.CharField(max_length = 68 , min_length = 4,write_only=True)
    username = serializers.CharField(max_length = 255 , min_length = 3,read_only=True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self,obj):
        user = User.objects.get(email=obj['email'])
        return {
            'access':user.tokens()['access'],
            'refresh':user.tokens()['refresh']
        }

    class Meta:
        model = User
        fields = ['email','password','username','tokens']

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    default_error_messages = {
        'bad_token':('token is expired or invalid')
    }
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')



class CreateClientSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=255,required=True)
    password = serializers.CharField(max_length=68,min_length=6,write_only=True)
    class Meta: 
        model=Client
        fields = ['username','password']

    def validate(self, attrs):
        username = attrs.get('username','')
        if len(Client.objects.filter(username=username))!= 0:
            raise serializers.ValidationError('A Username With These Credentials Already Exists.')
        if not username.isalnum():
            raise serializers.ValidationError('The Username Should Only Have AlphaNumeric Characters.')
        return attrs

    def create(self, validated_data):
        return Client.objects.create(**validated_data)

class UsernameSerializer(serializers.ModelSerializer):
     class Meta:
         model = Client
         fields = ['username']

class UsernamePasswordSerializer(serializers.ModelSerializer):
    class Meta:
         model = Client
         fields = ['username','password']

class CreateGroupSerializer(serializers.ModelSerializer):
    groupname = serializers.CharField(max_length=255,required=True)
    class Meta: 
        model= Group
        fields = ['groupname']

    def validate(self, attrs):
        groupname = attrs.get('groupname','')
        if len(Group.objects.filter(groupname=groupname))!= 0:
            raise serializers.ValidationError('A Group With This Name Already Exists.')
        if not groupname.isalnum():
            raise serializers.ValidationError('The Group Name Should Only Have AlphaNumeric Characters.')
        return attrs

    def create(self, validated_data):
        return Group.objects.create(**validated_data)

class GroupnameSerializer(serializers.ModelSerializer):
    class Meta:
         model = Group
         fields = ['groupname']

class CreateRoleSerializer(serializers.ModelSerializer):
    rolename = serializers.CharField(max_length=255,required=True)
    class Meta: 
        model= Role
        fields = ['rolename']

    def validate(self, attrs):
        rolename = attrs.get('rolename','')
        if len(Role.objects.filter(rolename=rolename))!= 0:
            raise serializers.ValidationError('A Role With This Name Already Exists.')
        if not rolename.isalnum():
            raise serializers.ValidationError('The Role Name Should Only Have AlphaNumeric Characters.')
        return attrs

    def create(self, validated_data):
        return Role.objects.create(**validated_data)

class RolenameSerializer(serializers.ModelSerializer):
    class Meta:
         model = Role
         fields = ['rolename']

class GroupRolePrioritySerializer(serializers.ModelSerializer):
    class Meta:
         model = Group, Role
         fields = ['groupname','rolename','priority']

class GroupRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group, Role
        fields = ['groupname','rolename']

class RoleACLPrioritySerializer(serializers.ModelSerializer):
    class Meta:
        model = Role , ACL
        fields = ['rolename','acltype','topic','allow','priority']

class RoleACLSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role , ACL
        fields = ['rolename','acltype','topic']

class ACLSerializer(serializers.ModelSerializer):
    class Meta:
        model = ACL
        fields = ['acltype','allow']

class SetClientIDSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client
        fields = ['username', 'client_ID']

class GroupClientSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group , Client
        fields = ['groupname','username']

class ClientRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Client , Role
        fields = ['username','rolename']

class ClientRolePrioritySerializer(serializers.ModelSerializer):
    class Meta:
        model = Client , Role
        fields = ['username','rolename','priority']

class GroupClientPrioritySerializer(serializers.ModelSerializer):
    class Meta:
        model = Group , Client
        fields = ['groupname','username','priority']