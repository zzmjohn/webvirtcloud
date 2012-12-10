from django.db import models
from django.contrib.auth.models import User


class Host(models.Model):
    hostname = models.CharField(max_length=20)
    ipaddr = models.IPAddressField()
    login = models.CharField(max_length=20)
    passwd = models.CharField(max_length=20)
    is_deleted = models.BooleanField(default=False)
    user = models.ForeignKey(User)

    def __unicode__(self):
        return self.hostname


class Flavor(models.Model):
    name = models.CharField(max_length=20)
    vcpu = models.IntegerField()
    ram = models.BigIntegerField()
    hdd = models.BigIntegerField()
    price = models.IntegerField()
    user = models.ForeignKey(User)
    is_deleted = models.BooleanField(default=False)

    def __unicode__(self):
        return self.name


class Order(models.Model):
    user = models.ForeignKey(User)
    flavor = models.ForeignKey(Flavor)
    name = models.CharField(max_length=20)
    is_active = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    date_create = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return self.name


class Vds(models.Model):
    user = models.ForeignKey(User)
    flavor = models.ForeignKey(Flavor)
    host = models.ForeignKey(Host)
    order = models.ForeignKey(Order)
    name = models.CharField(max_length=20)
    vname = models.CharField(max_length=20)
    vnc_passwd = models.CharField(max_length=20)
    desc = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    date_create = models.DateTimeField(auto_now_add=True)
    date_delete = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return self.name


class Deligation(models.Model):
    admin = models.ForeignKey(User, related_name=u'admin_id')
    user = models.ForeignKey(User)


class Log(models.Model):
    host = models.CharField(max_length=20)
    message = models.CharField(max_length=255)
    date = models.DateTimeField(auto_now_add=True, blank=True)
    user = models.ForeignKey(User)

    def __unicode__(self):
        return self.message
