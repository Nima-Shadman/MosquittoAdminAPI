from django.urls import path
from .views import *
urlpatterns= [

    path('login/', LoginAPIView.as_view(), name="login"),
    path('logout/', LogoutAPIView.as_view(), name="logout"),


    path('get-default-acl/', GetDefaultACLAccessView.as_view(), name="get-default-acl"),
    path('set-default-acl/', SetDefaultACLAccessView.as_view(), name="set-default-acl"),
    path('get-anonymous/',GetAnonymousGroupView.as_view(), name="get-anonymous"),
    path('set-anonymous/', SetAnonymousGroupView.as_view(), name="set-anonymous"),


    path('create-client/', CreateClientView.as_view(), name="create-client"),
    path('list-clients/', ClientsListAPIView.as_view(), name="list-clients"),
    path('delete-client/', DeleteClientAPIView.as_view(), name="delete-client"),
    path('set-password/', SetClientPasswordView.as_view(), name="set-password"),
    path('client-info/', GetClientView.as_view(), name="client-info"),
    path('enable/', EnableClientView.as_view(), name="enable"),
    path('disable/', DisableClientView.as_view(), name="disable"),
    path('set-id/', SetClientIDView.as_view(), name="set-id"),
    path('add-client-role/', AddClientRole.as_view(), name="add-client-role"),
    path('remove-client-role/', RemoveClientRole.as_view(), name="remove-client-role"),


    path('create-group/', CreateGroupView.as_view(), name="create-group"),
    path('delete-group/', DeleteGroupView.as_view(), name="delete-group"),
    path('group-info/', GetGroupView.as_view(), name="group-info"),
    path('list-groups/', ListGroupsView.as_view(), name="list-group"),
    path('add-group-role/', AddGroupRoleView.as_view(), name="add-group-role"),
    path('remove-group-role/', RemoveGroupRoleView.as_view(), name="remove-group-role"),
    path('add-group-client/', AddGroupClientView.as_view(), name="add-group-client"),
    path('remove-group-client/', RemoveGroupClientView.as_view(), name="remove-group-client"),


    path('create-role/', CreateRoleView.as_view(), name="create-role"),
    path('delete-role/', DeleteRoleView.as_view(), name="delete-role"),
    path('role-info/', GetRoleView.as_view(), name="role-info"),
    path('list-roles/', ListRolesView.as_view(), name="list-role"),
    path('add-role-acl/', AddRoleACLView.as_view(), name="add-role-acl"),
    path('remove-role-acl/', RemoveRoleACLView.as_view(), name="remove-role-acl"),

]