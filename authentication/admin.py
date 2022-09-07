from django.contrib import admin
from .models import *
admin.site.register(Client)
admin.site.register(User)
admin.site.register(Role)
admin.site.register(Organization)
admin.site.register(ACL)
admin.site.register(Group)
admin.site.register(RoleWithPriority)
admin.site.register(ClientWithPriority)
admin.site.register(AnonymousGroup)




