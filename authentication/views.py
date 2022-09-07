from rest_framework import generics,status
from rest_framework.response import Response
from djangoproject_sh.settings import ADMIN_PASSWORD, ADMIN_USERNAME
from .models import *
from .serializers import *
from rest_framework import permissions
from .utils import istopic
import subprocess

acltypes = ['publishClientSend','publishClientReceive','subscribeLiteral', 'subscribePattern', 'unsubscribeLiteral', 'unsubscribePattern']
allows = ['allow','deny']


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    def post(self,request):
        user = request.data
        serializer = self.serializer_class(data=user) 
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)

class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)




class GetDefaultACLAccessView(generics.GenericAPIView):
    def get(self,request):
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'getDefaultACLAccess'], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            return Response(process.stdout ,status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SetDefaultACLAccessView(generics.GenericAPIView):
    serializer_class = ACLSerializer
    def post(self,request):
        if request.data["acltype"] not in acltypes or request.data["allow"] not in allows:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'setDefaultACLAccess',request.data["acltype"],request.data["allow"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            return Response({'message':"Default Access ACL Changed."},status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetAnonymousGroupView(generics.GenericAPIView):
    def get(self,request):
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'getAnonymousGroup'], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            return Response(process.stdout ,status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SetAnonymousGroupView(generics.GenericAPIView):
    serializer_class = GroupnameSerializer
    def post(self,request):
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'setAnonymousGroup',request.data["groupname"]], stdout=subprocess.PIPE, universal_newlines=True)
        if Group.objects.filter(groupname = request.data["groupname"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            if  AnonymousGroup.objects.count() != 0:
                AnonymousGroup.objects.filter().delete()
            group = Group.objects.get(groupname = request.data["groupname"])
            anonymous_group = AnonymousGroup(group = group)
            anonymous_group.save()
            return Response({'message':"Group Set As Anonymous Group."} ,status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class CreateClientView(generics.GenericAPIView):
    serializer_class = CreateClientSerializer
    def post(self,request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'createClient',user["username"],'-p',user["password"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            serializer.save()
            user_data = serializer.data
            return Response(data=user_data, status=status.HTTP_201_CREATED)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ClientsListAPIView(generics.GenericAPIView):
    def get(self,request):
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'listClients'], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            return Response(process.stdout ,status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteClientAPIView(generics.GenericAPIView):
    serializer_class = UsernameSerializer
    def post(self,request):
        if Client.objects.filter(username = request.data["username"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        user = request.data
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'deleteClient',user["username"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            Client.objects.get(username = user["username"]).delete()
            return Response({'message':'client deleted.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SetClientPasswordView(generics.GenericAPIView):
    serializer_class = UsernamePasswordSerializer 
    def post(self,request):
        if Client.objects.filter(username = request.data["username"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        user = request.data
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'setClientPassword',user["username"],user["password"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            client = Client.objects.get(username = user["username"])
            client.password = user["password"]
            client.save()
            return Response({'message':'client password changed.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetClientView(generics.GenericAPIView):
    serializer_class = UsernameSerializer
    def post(self,request):
        if Client.objects.filter(username = request.data["username"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        user = request.data
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'getClient',user["username"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            return Response(process.stdout, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class EnableClientView(generics.GenericAPIView):
    serializer_class = UsernameSerializer
    def post(self,request):
        if Client.objects.filter(username = request.data["username"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        user = request.data
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'enableClient',user["username"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            client = Client.objects.get(username = user["username"])
            client.is_active = True
            client.save()
            return Response({'message':"user enabled."}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DisableClientView(generics.GenericAPIView):
    serializer_class = UsernameSerializer
    def post(self,request):
        if Client.objects.filter(username = request.data["username"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        user = request.data
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'disableClient',user["username"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            client = Client.objects.get(username = user["username"])
            client.is_active = False
            client.save()
            return Response({'message':"user disabled."}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SetClientIDView(generics.GenericAPIView):
    serializer_class = SetClientIDSerializer
    def post(self,request):
        if Client.objects.filter(username = request.data["username"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        user = request.data
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'setClientId',user["username"],user["Client_ID"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            client = Client.objects.get(username = user["username"])
            client.client_ID = user["Client_ID"]
            client.save()
            return Response({'message':"Client ID Changed"}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AddClientRole(generics.GenericAPIView):
    serializer_class = ClientRolePrioritySerializer
    def post(self,request):
        if Client.objects.filter(username = request.data["username"]).count() == 0 or Role.objects.filter(rolename = request.data["rolename"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        priority = '-1'
        if 'priority' in request.data:
            priority = request.data["priority"]
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'addClientRole',request.data["username"],request.data["rolename"],priority], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            client = Client.objects.get(username = request.data["username"])
            role = Role.objects.get(rolename = request.data["rolename"])
            if client.roles.filter(role = role).count() != 0:
                return Response({'message':'this client already has this role'}, status=status.HTTP_400_BAD_REQUEST)
            if RoleWithPriority.objects.filter(role = role , priority = priority).count() == 0: 
                rolewp = RoleWithPriority(role=role,priority=priority)
            else:
                rolewp = RoleWithPriority.objects.get(role = role , priority = priority)
            rolewp.save()
            client.roles.add(rolewp)
            client.save()
            return Response({'message':'client role added.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RemoveClientRole(generics.GenericAPIView):
    serializer_class = ClientRoleSerializer
    def post(self,request):
        if Client.objects.filter(username = request.data["username"]).count() == 0 or Role.objects.filter(rolename = request.data["rolename"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'removeClientRole',request.data["username"],request.data["rolename"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            role = Role.objects.get(rolename = request.data["rolename"])
            client = Client.objects.get(username = request.data["username"])
            client.roles.get(role = role).delete()
            client.save()
            return Response({'message':'client role removed.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class CreateGroupView(generics.GenericAPIView):
    serializer_class = CreateGroupSerializer
    def post(self,request):
        group = request.data
        serializer = self.serializer_class(data=group)
        serializer.is_valid(raise_exception=True)
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'createGroup',group["groupname"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            serializer.save()
            group_data = serializer.data
            return Response(data=group_data, status=status.HTTP_201_CREATED)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteGroupView(generics.GenericAPIView):
    serializer_class = GroupnameSerializer
    def post(self,request):
        if Group.objects.filter(groupname = request.data["groupname"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        group = request.data
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'deleteGroup',group["groupname"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            Group.objects.get(groupname = group["groupname"]).delete()
            return Response({'message':'group deleted.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AddGroupRoleView(generics.GenericAPIView):
    serializer_class = GroupRolePrioritySerializer
    def post(self,request):
        if Group.objects.filter(groupname = request.data["groupname"]).count() == 0 or Role.objects.filter(rolename = request.data["rolename"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        priority = '-1'
        if 'priority' in request.data:
            priority = request.data["priority"]
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'addGroupRole',request.data["groupname"],request.data["rolename"],priority], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            group = Group.objects.get(groupname = request.data["groupname"])
            role = Role.objects.get(rolename = request.data["rolename"])
            if group.roles.filter(role = role).count() != 0:
                return Response({'message':'this group already has this role'}, status=status.HTTP_400_BAD_REQUEST)
            if RoleWithPriority.objects.filter(role = role , priority = priority).count() == 0: 
                rolewp = RoleWithPriority(role=role,priority=priority)
            else:
                rolewp = RoleWithPriority.objects.get(role = role , priority = priority)
            rolewp.save()
            group.roles.add(rolewp)
            group.save()
            return Response({'message':'group role added.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RemoveGroupRoleView(generics.GenericAPIView):
    serializer_class = GroupRoleSerializer
    def post(self,request):
        if Group.objects.filter(groupname = request.data["groupname"]).count() == 0 or Role.objects.filter(rolename = request.data["rolename"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'removeGroupRole',request.data["groupname"],request.data["rolename"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            group = Group.objects.get(groupname = request.data["groupname"])
            role = Role.objects.get(rolename = request.data["rolename"])
            group.roles.get(role = role).delete()
            group.save()
            return Response({'message':'group role removed.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)
   

class AddGroupClientView(generics.GenericAPIView):
    serializer_class = GroupClientPrioritySerializer
    def post(self,request):
        if Group.objects.filter(groupname = request.data["groupname"]).count() == 0 or Client.objects.filter(username = request.data["username"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        priority = '-1'
        if 'priority' in request.data:
            priority = request.data["priority"]
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'addGroupClient',request.data["groupname"],request.data["username"],priority], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            group = Group.objects.get(groupname = request.data["groupname"])
            client = Client.objects.get(username = request.data["username"])
            if group.clients.filter(client = client).count() != 0:
                print(group.clients.filter(client = client))
                return Response({'message':'this group already has this client'}, status=status.HTTP_400_BAD_REQUEST)
            if ClientWithPriority.objects.filter(client = client , priority = priority).count() == 0: 
                clientwp = ClientWithPriority(client=client,priority=priority)
            else:
                clientwp = ClientWithPriority.objects.get(client = client , priority = priority)
            clientwp.save()
            group.clients.add(clientwp)
            group.save()
            return Response({'message':'client added to group.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RemoveGroupClientView(generics.GenericAPIView):
    serializer_class = GroupClientSerializer
    def post(self,request):
        if Group.objects.filter(groupname = request.data["groupname"]).count() == 0 or Client.objects.filter(username = request.data["username"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'removeGroupClient',request.data["groupname"],request.data["username"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            group = Group.objects.get(groupname = request.data["groupname"])
            client = Client.objects.get(username = request.data["username"])
            group.clients.get(client = client).delete()
            group.save()
            return Response({'message':'group client removed.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetGroupView(generics.GenericAPIView):
    serializer_class = GroupnameSerializer
    def post(self,request):
        if Group.objects.filter(groupname = request.data["groupname"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        group = request.data
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'getGroup',group["groupname"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            return Response(process.stdout, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ListGroupsView(generics.GenericAPIView):
    def get(self,request):
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'listGroups'], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            return Response(process.stdout ,status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class CreateRoleView(generics.GenericAPIView):
    serializer_class = CreateRoleSerializer
    def post(self,request):
        role = request.data
        serializer = self.serializer_class(data=role)
        serializer.is_valid(raise_exception=True)
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'createRole',role["rolename"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            serializer.save()
            role_data = serializer.data
            return Response(data=role_data, status=status.HTTP_201_CREATED)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteRoleView(generics.GenericAPIView):
    serializer_class = RolenameSerializer
    def post(self,request):
        if Role.objects.filter(rolename = request.data["rolename"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        role = request.data
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'deleteRole',role["rolename"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            Role.objects.get(rolename = role["rolename"]).delete()
            return Response({'message':'role deleted.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AddRoleACLView(generics.GenericAPIView):
    serializer_class = RoleACLPrioritySerializer
    def post(self,request):
        if Role.objects.filter(rolename = request.data["rolename"]).count() == 0 or request.data["acltype"] not in acltypes or request.data["allow"] not in allows or (not istopic(request.data["topic"]) and Client.objects.filter(username = request.data["topic"]).count() == 0 and Group.objects.filter(groupname = request.data["topic"]).count() == 0):
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        priority = '-1'
        if istopic(request.data["topic"]):
            topic = request.data["topic"] = '"' + request.data["topic"] + '"'
        else:
            topic = request.data["topic"]
        if 'priority' in request.data:
            priority = request.data["priority"]
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'addRoleACL',request.data["rolename"],request.data["acltype"],topic,request.data["allow"],priority], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            role = Role.objects.get(rolename = request.data["rolename"])
            acl = ACL(acltype=request.data['acltype'],topic=request.data['topic'],allow=request.data['allow'],priority=priority)
            acl.save()
            role.acls.add(acl)
            role.save()
            return Response({'message':'ACL added to role.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RemoveRoleACLView(generics.GenericAPIView):
    serializer_class = RoleACLSerializer
    def post(self,request):
        if Role.objects.filter(rolename = request.data["rolename"]).count() == 0 or request.data["acltype"] not in acltypes or (not istopic(request.data["topic"]) and Client.objects.filter(username = request.data["topic"]).count() == 0 and Group.objects.filter(groupname = request.data["topic"]).count() == 0):
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        if istopic(request.data["topic"]):
            topic = request.data["topic"] = '"' + request.data["topic"] + '"'
        else:
            topic = request.data["topic"]
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'removeRoleACL',request.data["rolename"],request.data["acltype"],topic], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            role = Role.objects.get(rolename = request.data["rolename"])
            acl = role.acls.get(acltype=request.data["acltype"],topic=request.data["topic"])
            role.acls.remove(acl)
            role.save()
            return Response({'message':'ACL removed from role.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetRoleView(generics.GenericAPIView):
    serializer_class = RolenameSerializer
    def post(self,request):
        if Role.objects.filter(rolename = request.data["rolename"]).count() == 0:
            return Response({'message':"Invalid"},status=status.HTTP_400_BAD_REQUEST)
        role = request.data
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'getRole',role["rolename"]], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            return Response(process.stdout, status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ListRolesView(generics.GenericAPIView):
    def get(self,request):
        process = subprocess.run(['mosquitto_ctrl','-u',ADMIN_USERNAME,'-P',ADMIN_PASSWORD,'dynsec', 'listRoles'], stdout=subprocess.PIPE, universal_newlines=True)
        if type(process) == subprocess.CompletedProcess and process.returncode == 0:
            return Response(process.stdout ,status=status.HTTP_200_OK)
        else:
            return Response({'message':"something happened,it's on us."},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

