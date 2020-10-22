from django.contrib import admin
from .models import Account, PhoneOtp

# Register your models here.


class AccountAdmin(admin.ModelAdmin):
    search_fields = ('email',)


admin.site.register(Account, AccountAdmin)
admin.site.register(PhoneOtp, AccountAdmin)
