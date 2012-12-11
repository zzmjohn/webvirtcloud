# -*- coding: utf-8 -*-
from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect
from django.template import RequestContext
from webvirtcloud.polls.models import *

# Funciton

def add_log(host, msg, user):
    """
    Create log message in DB for user and libvirt actions.

    """

    log_msg = Log(host=host, message=msg, user_id=user)
    log_msg.save()


def libvirt_conn(host):
    """
    Function for connect to libvirt host.
    Create exceptions and return if not connnected.

    """

    import libvirt

    def creds(credentials, user_data):
        for credential in credentials:
            if credential[0] == libvirt.VIR_CRED_AUTHNAME:
                credential[4] = host.login
                if len(credential[4]) == 0:
                    credential[4] = credential[3]
            elif credential[0] == libvirt.VIR_CRED_PASSPHRASE:
                credential[4] = host.passwd
            else:
                return -1
        return 0

    flags = [libvirt.VIR_CRED_AUTHNAME, libvirt.VIR_CRED_PASSPHRASE]
    auth = [flags, creds, None]
    uri = 'qemu+tcp://%s/system' % host.ipaddr

    try:
        conn = libvirt.openAuth(uri, auth, 0)
        return conn
    except libvirt.libvirtError as e:
        return {'error': e.message}


def mailsend(fromaddr, toaddr, subject, text):
    import smtplib
    from time import strftime
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    dtime = strftime("%d %B, %H:%M ")
    msg = MIMEMultipart()
    msg['From'] = fromaddr
    msg['To'] = toaddr
    msg['Subject'] = subject
    mattch = MIMEText(text + '\n\n' + dtime + '\n', 'plain', 'utf-8')
    msg.attach(mattch)
    s = smtplib.SMTP('localhost')
    #s.login(username, password)
    try:
        s.sendmail(fromaddr, toaddr, msg.as_string())
    except:
        pass
    s.quit()


# Site urls

def index(request):
    """
    Start page.

    """

    if request.user.is_authenticated():
        return HttpResponseRedirect('/home')
    else:
        return HttpResponseRedirect('/login')

    return render_to_response('index.html', locals(), context_instance=RequestContext(request))


def home(request):
    """
    Home page for user and admins.

    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')

    vds = Vds.objects.filter(user=request.user, is_active=1)
    vds_count = len(vds)

    host = Host.objects.filter(user=request.user, is_deleted=0)
    host_count = len(host)

    orders = 0

    if not is_user:
        try:
            deligate_user = Deligation.objects.filter(admin=request.user)
        except:
            deligate_user = None

        if deligate_user:
            for usr in deligate_user:
                try:
                    order = Order.objects.filter(user=usr.user_id, is_deleted=0, is_active=0)
                    orders = orders + len(order)
                except:
                    order = None

    try:
        order = Order.objects.filter(user=request.user, is_deleted=0, is_active=0)
        orders = orders + len(order)
    except:
        order = None

    return render_to_response('home.html', locals(), context_instance=RequestContext(request))


def profile(request):
    """
    Auth block

    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')

    if request.method == 'POST':
        if 'update' in request.POST:
            user = User.objects.get(id=request.user.id)
            if request.POST.get('firstname', ''):
                user.first_name = request.POST.get('firstname', '')
            if request.POST.get('lastname', ''):
                user.last_name = request.POST.get('lastname', '')
            if request.POST.get('email', ''):
                user.email = request.POST.get('email', '')
            user.save()
        if 'newpasswd' in request.POST:
            user_id = request.POST.get('user_id', '')
            password1 = request.POST.get('password1', '')
            password2 = request.POST.get('password2', '')
            errors = []
            if not password1:
                msg = "Enter password"
                errors.append(msg)
            elif not password2:
                msg = "Enter confirm password"
                errors.append(msg)
            elif password1 != password2:
                errors.append('Password mismatch')
            if not errors:
                update_user = User.objects.get(id=user_id)
                update_user.set_password(password2)
                update_user.save()
                messages = []
                messages.append('Password seccesfyl changed')

    return render_to_response('profile.html', locals(), context_instance=RequestContext(request))


def servers(request):
    """
    SERVERS block

    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')

    if is_user:
        db_flavors = Flavor.objects.filter(user=is_user.admin_id, is_deleted=0)
    else:
        db_flavors = Flavor.objects.filter(user=request.user, is_deleted=0)

    flavors = {}
    for flavor in db_flavors:
        flavors[flavor.id] = (flavor.name, flavor.vcpu, flavor.ram, flavor.hdd, flavor.price)

    dis_orders = {}
    orders = Order.objects.filter(user=request.user.id, is_active=0)

    for order in orders:
        flavor = Flavor.objects.get(id=order.flavor_id)
        dis_orders[order.id] = (order.name, flavor.name, flavor.vcpu,
                                flavor.ram, flavor.hdd)

    servers = {}
    if is_user:
        vds = Vds.objects.filter(user=request.user.id, is_active=1)
        for vm in vds:
            flavor = Flavor.objects.get(id=vm.flavor_id)
            servers[vm.id] = (vm.name, flavor.vcpu, flavor.ram, flavor.hdd)
    else:
        delig_user = Deligation.objects.filter(admin=request.user)
        if delig_user:
            for usr in delig_user:
                users = User.objects.get(id=usr.user_id)
                users_vds = Vds.objects.filter(user=usr.user_id, is_active=1)
                for vm in users_vds:
                    flavor = Flavor.objects.get(id=vm.flavor_id)
                    servers[vm.id] = (vm.name, users.id, users.username, flavor.vcpu, flavor.ram, flavor.hdd)

        admin_vds = Vds.objects.filter(user=request.user, is_active=1)
        for vm in admin_vds:
            flavor = Flavor.objects.get(id=vm.flavor_id)
            servers[vm.id] = (vm.name, request.user.id, request.user.username, flavor.vcpu, flavor.ram, flavor.hdd)

    if request.method == 'POST':
        name = request.POST.get('server_name', '')
        flavor = request.POST.get('flavor', '')

        import re
        errors = []
        have_simbol = re.search('[^a-zA-Z0-9\_]+', name)

        if not name:
            msg = 'No name has been entered'
            errors.append(msg)
        elif len(name) > 12:
            msg = 'The name must not exceed 12 characters'
            errors.append(msg)
        else:
            if have_simbol:
                msg = 'The host name must not contain any characters'
                errors.append(msg)
            else:
                try:
                    vds_is = Vds.objects.get(name=name, is_active=1, is_deleted=0, user=request.user)
                except:
                    vds_is = None
                try:
                    orders_is = Order.objects.get(name=name, is_active=0, is_deleted=0, user=request.user)
                except:
                    orders_is = None
                if vds_is:
                    msg = 'Name virtual instance alredy use'
                    errors.append(msg)
                if orders_is:
                    msg = 'Name Orders alredy exist'
                    errors.append(msg)
        if not errors:
            from datetime import datetime
            messages = []
            order = Order(user=request.user, flavor_id=flavor, name=name, date_create=datetime.now())
            order.save()

            hostname = '-'
            if is_user:
                adm_msg = 'Create order for the virtual instance: %s, User: %s' % (name, request.user.username)
                add_log(hostname, adm_msg, is_user.admin_id)

            usr_msg = 'Create order for the virtual instance: %s' % name
            add_log(hostname, usr_msg, request.user.id)
            messages.append(usr_msg)

            if is_user:
                adm_user = User.objects.get(id=is_user.admin_id)
                fromaddr = user.username + ' <' + user.email + '>'
                toaddr = adm_user.email
                subject = 'New order for instance'
                text = """Hello,\n\nUser, %s create order to new virtual instance.\n""" % request.user.username
                mailsend(fromaddr, toaddr, subject, text)

    return render_to_response('servers.html', locals(), context_instance=RequestContext(request))


def vds(request, vds_id):
    """
    VDS block

    """

    from libvirt import libvirtError

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')

    def all_storages():
        storages = {}
        for storage in conn.listStoragePools():
            stg = conn.storagePoolLookupByName(storage)
            status = stg.isActive()
            storages[storage] = status
        for storage in conn.listDefinedStoragePools():
            stg = conn.storagePoolLookupByName(storage)
            status = stg.isActive()
            storages[storage] = status
        return storages

    def find_all_iso(storages):
        import re
        iso = []
        for storage in storages:
            stg = conn.storagePoolLookupByName(storage)
            stg.refresh(0)
            for img in stg.listVolumes():
                if re.findall(".iso", img):
                    img = re.sub('.iso', '', img)
                    iso.append(img)
        return iso

    def add_iso(image, storages):
        image = image + '.iso'
        for storage in storages:
            stg = conn.storagePoolLookupByName(storage)
            for img in stg.listVolumes():
                if image == img:
                    if dom.info()[0] == 1:
                        vol = stg.storageVolLookupByName(image)
                        xml = """<disk type='file' device='cdrom'>
                                    <driver name='qemu' type='raw'/>
                                    <target dev='hdc' bus='ide'/>
                                    <source file='%s'/>
                                    <readonly/>
                                 </disk>""" % vol.path()
                        dom.attachDevice(xml)
                        xmldom = dom.XMLDesc(0)
                        conn.defineXML(xmldom)
                    if dom.info()[0] == 5:
                        vol = stg.storageVolLookupByName(image)
                        xml = dom.XMLDesc(0)
                        newxml = "<disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>\n      <source file='%s'/>" % vol.path()
                        xmldom = xml.replace("<disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>", newxml)
                        conn.defineXML(xmldom)

    def remove_iso(image, storages):
        image = image + '.iso'
        if dom.info()[0] == 1:
            xml = """<disk type='file' device='cdrom'>
                         <driver name="qemu" type='raw'/>
                         <target dev='hdc' bus='ide'/>
                         <readonly/>
                      </disk>"""
            dom.attachDevice(xml)
            xmldom = dom.XMLDesc(0)
            conn.defineXML(xmldom)
        if dom.info()[0] == 5:
            for storage in storages:
                stg = conn.storagePoolLookupByName(storage)
                for img in stg.listVolumes():
                    if image == img:
                        vol = stg.storageVolLookupByName(image)
                        xml = dom.XMLDesc(0)
                        xmldom = xml.replace("<source file='%s'/>\n" % vol.path(), '')
                        conn.defineXML(xmldom)

    def find_iso(image, storages):
        image = image + '.iso'
        for storage in storages:
            stg = conn.storagePoolLookupByName(storage)
            stg.refresh(0)
            try:
                vol = stg.storageVolLookupByName(image)
            except:
                vol = None
        return vol.name()

    def dom_media():
        import virtinst.util as util
        import re

        xml = dom.XMLDesc(0)
        media = util.get_xml_path(xml, "/domain/devices/disk[2]/source/@file")
        if media:
            vol = conn.storageVolLookupByPath(media)
            img = re.sub('.iso', '', vol.name())
            return img
        else:
            return None

    def dom_undefine():
        import virtinst.util as util

        xml = dom.XMLDesc(0)
        media = util.get_xml_path(xml, "/domain/devices/disk[1]/source/@file")
        vol = conn.storageVolLookupByPath(media)
        vol.delete(0)
        dom.undefine()

    def dom_uptime():
        nanosec = dom.info()[4]
        minutes = nanosec * 1.66666666666667E-11
        minutes = round(minutes, 0)
        return minutes

    if not is_user:
        vds = Vds.objects.get(id=vds_id)
    else:
        vds = Vds.objects.get(id=vds_id, user=request.user)

    flavor = Flavor.objects.get(id=vds.flavor_id)
    host = Host.objects.get(id=vds.host_id)

    from datetime import datetime
    vds_age = datetime.now() - vds.date_create

    conn = libvirt_conn(host)

    if type(conn) == dict:
        add_log(host.hostname, conn.values()[0], request.user.id)
        return HttpResponseRedirect('/servers/')
    else:
        dom = conn.lookupByName(vds.vname)

        storages = all_storages()
        iso_images = find_all_iso(storages)
        media = dom_media()
        uptime = dom_uptime()

        if request.method == 'POST':
            if 'start' in request.POST:
                try:
                    dom.create()
                    msg = 'Start instance'
                    add_log(vds.name, msg, request.user.id)
                    return HttpResponseRedirect(request.get_full_path())
                except libvirtError as msg_error:
                    add_log(vds.name, msg_error.message, request.user.id)
            if 'power' in request.POST:
                if 'reboot' == request.POST.get('power', ''):
                    try:
                        dom.destroy()
                        dom.create()
                        msg = 'Reboot instance'
                        add_log(vds.name, msg, request.user.id)
                        return HttpResponseRedirect(request.get_full_path())
                    except libvirtError as msg_error:
                        add_log(vds.name, msg_error.message, request.user.id)
                if 'shutdown' == request.POST.get('power', ''):
                    try:
                        dom.shutdown()
                        msg = 'Shutdown instance'
                        add_log(vds.name, msg, request.user.id)
                        return HttpResponseRedirect(request.get_full_path())
                    except libvirtError as msg_error:
                        add_log(vds.name, msg_error.message, request.user.id)
            if 'suspend' in request.POST:
                try:
                    dom.suspend()
                    msg = 'Suspend instance'
                    add_log(vds.name, msg, request.user.id)
                    return HttpResponseRedirect(request.get_full_path())
                except libvirtError as msg_error:
                    add_log(vds.name, msg_error.message, request.user.id)
            if 'resume' in request.POST:
                try:
                    dom.resume()
                    msg = 'Resume instance'
                    add_log(vds.name, msg, request.user.id)
                    return HttpResponseRedirect(request.get_full_path())
                except libvirtError as msg_error:
                    add_log(vds.name, msg_error.message, request.user.id)
            if 'delete' in request.POST:
                try:
                    if dom.info()[0] == 1:
                        dom.destroy()
                    dom_undefine()
                    upd_vds = Vds.objects.get(id=vds_id)
                    upd_vds.is_active = False
                    upd_vds.is_deleted = True
                    upd_vds.date_delete = datetime.now()
                    upd_vds.save()
                    if is_user:
                        adm_msg = 'User: %s, delete instance: %s' % (request.user.username, vds.name)
                        add_log(host.hostname, adm_msg, is_user.admin_id)
                    usr_msg = 'Delete instance'
                    add_log(vds.name, usr_msg, vds.user_id)
                except libvirtError as msg_error:
                    add_log(vds.name, msg_error.message, request.user.id)
                return HttpResponseRedirect('/servers/')
            if 'snapshot' in request.POST:
                try:
                    import time
                    xml = """<domainsnapshot>\n
                                 <name>%d</name>\n
                                 <state>shutoff</state>\n
                                 <creationTime>%d</creationTime>\n""" % (time.time(), time.time())
                    xml += dom.XMLDesc(0)
                    xml += """<active>0</active>\n
                              </domainsnapshot>"""
                    dom.snapshotCreateXML(xml, 0)
                    msg = 'Create instance snapshot'
                    add_log(vds.name, msg, request.user.id)
                    messages = []
                    messages.append('Create snapshot for instance successful')
                    return HttpResponseRedirect(request.get_full_path())
                except libvirtError as msg_error:
                    add_log(vds.name, msg_error.message, request.user.id)
            if 'remove_iso' in request.POST:
                image = request.POST.get('iso_img', '')
                remove_iso(image, storages)
                img_name = image + '.iso'
                msg = 'Disconnected media: %s' % img_name
                add_log(host.hostname, msg, request.user.id)
                return HttpResponseRedirect(request.get_full_path())
            if 'add_iso' in request.POST:
                image = request.POST.get('iso_img', '')
                add_iso(image, storages)
                img_name = image + '.iso'
                msg = 'Connected media: %s' % img_name
                add_log(host.hostname, msg, request.user.id)
                return HttpResponseRedirect(request.get_full_path())

        conn.close()

    return render_to_response('vds.html', locals(), context_instance=RequestContext(request))


def vnc(request, vds_id):
    """
    VNC block

    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')

    def vnc_port():
        import virtinst.util as util
        dom = conn.lookupByName(vds.vname)
        xml = dom.XMLDesc(0)
        port = util.get_xml_path(xml, "/domain/devices/graphics/@port")
        return port

    if not is_user:
        vds = Vds.objects.get(id=vds_id)
        host = Host.objects.get(id=request.user.id)
    else:
        vds = Vds.objects.get(id=vds_id, user=request.user)
        host = Host.objects.get(id=vds.host_id)

    conn = libvirt_conn(host)

    if type(conn) == dict:
        add_log(host.hostname, conn.values()[0], request.user.id)
        return HttpResponseRedirect('/servers/')
    else:
        vnc_port = vnc_port()

        conn.close()

    return render_to_response('vnc.html', locals(), context_instance=RequestContext(request))


def support(request):
    """
    Support page

    """

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None
        return HttpResponseRedirect('/home/')

    if request.method == 'POST':
        if 'send' in request.POST:
            subject = request.POST.get('subject', '')
            text = request.POST.get('text', '')
            user_id = request.POST.get('user_id', '')
            user = User.objects.get(id=user_id)
            from_user = user.username + ' <' + user.email + '>'
            adm_user = User.objects.get(id=is_user.admin_id)
            mailsend(from_user, adm_user.email, subject, text)
            messages = []
            messages.append('Email send seccesfyl to your cloud administrator')

    return render_to_response('support.html', locals(), context_instance=RequestContext(request))


def manage(request):
    """
    Managemen interface

    """

    import socket

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')
    if is_user:
        return HttpResponseRedirect('/home')

    all_host = {}
    hosts = Host.objects.filter(user=request.user, is_deleted=0)
    all_orders = Order.objects.filter(is_active=0)

    for host in hosts:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host.ipaddr, 16509))
            s.close()
            status = 1
        except:
            status = 2
        all_host[host.id] = (host.hostname, host.ipaddr, status)

    if request.method == 'POST':
        if 'addhost' in request.POST:
            hostname = request.POST.get('hostname', '')
            ipaddr = request.POST.get('ipaddr', '')
            kvm_login = request.POST.get('kvm_login', '')
            kvm_passwd1 = request.POST.get('kvm_passwd1', '')
            kvm_passwd2 = request.POST.get('kvm_passwd2', '')

            import re
            errors = []
            have_simbol = re.search('[^a-zA-Z0-9\_]+', hostname)
            ip_have_simbol = re.search('[^a-z0-9\.\-]+', ipaddr)
            domain = re.search('[\.]+', ipaddr)
            privat_ip = re.search('^0\.|^255\.', ipaddr)

            if not hostname:
                msg = 'No hostname has been entered'
                errors.append(msg)
            elif len(hostname) > 12:
                msg = 'The host name must not exceed 12 characters'
                errors.append(msg)
            else:
                if have_simbol:
                    msg = 'The host name must not contain any characters'
                    errors.append(msg)
                else:
                    have_host = Host.objects.filter(user=request.user, hostname=hostname, is_deleted=0)
                    have_ip = Host.objects.filter(user=request.user, ipaddr=ipaddr, is_deleted=0)
                    if have_host or have_ip:
                        msg = 'This host is already connected'
                        errors.append(msg)
            if not ipaddr:
                msg = 'No IP address has been entered'
                errors.append(msg)
            elif privat_ip:
                msg = 'IP address can not be a private address space'
                errors.append(msg)
            else:
                if ip_have_simbol or not domain:
                    msg = 'Hostname must contain only numbers, or the domain name separated by "."'
                    errors.append(msg)
            if not kvm_login:
                msg = 'No KVM login has been entered'
                errors.append(msg)
            if not kvm_passwd1:
                msg = 'No KVM password has been entered'
                errors.append(msg)
            if not kvm_passwd2:
                msg = 'No KVM password confirm has been entered'
                errors.append(msg)
            else:
                if kvm_passwd1 != kvm_passwd2:
                    msg = 'Your password didn\'t match. Please try again.'
                    errors.append(msg)
            if not errors:
                add_host = Host(hostname=hostname, ipaddr=ipaddr, login=kvm_login, passwd=kvm_passwd1, user=request.user)
                add_host.save()
                msg = 'Add host server'
                add_log(hostname, msg, request.user.id)
                return HttpResponseRedirect(request.get_full_path())

    return render_to_response('manage.html', locals(), context_instance=RequestContext(request))


def host(request, srv_id):
    """
    Host block in management interface

    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')
    if is_user:
        return HttpResponseRedirect('/home')

    def get_mem_usage():
        allmem = conn.getInfo()[1] * 1048576
        get_freemem = conn.getMemoryStats(-1, 0)
        if type(get_freemem) == dict:
            freemem = (get_freemem.values()[0] + \
                       get_freemem.values()[2] + \
                       get_freemem.values()[3]) * 1024
            percent = (freemem * 100) / allmem
            percent = 100 - percent
            memusage = (allmem - freemem)
        else:
            memusage = None
            percent = None
        return allmem, memusage, percent

    def get_cpu_usage():
        prev_idle = 0
        prev_total = 0
        cpu = conn.getCPUStats(-1, 0)
        if type(cpu) == dict:
            for num in range(2):
                    idle = conn.getCPUStats(-1, 0).values()[1]
                    total = sum(conn.getCPUStats(-1, 0).values())
                    diff_idle = idle - prev_idle
                    diff_total = total - prev_total
                    diff_usage = (1000 * (diff_total - diff_idle) / \
                                  diff_total + 5) / 10
                    prev_total = total
                    prev_idle = idle
                    if num == 0:
                        import time
                        time.sleep(1)
                    else:
                        if diff_usage < 0:
                            diff_usage = 0
        else:
            diff_usage = None
        return diff_usage

    def get_host_info():
        import virtinst.util as util
        info = []
        xml_info = conn.getSysinfo(0)
        info.append(conn.getHostname())
        info.append(conn.getInfo()[2])
        info.append(util.get_xml_path(xml_info, "/sysinfo/processor/entry[6]"))
        info.append(get_cpu_usage())
        info.append(get_mem_usage())
        info.append(conn.getLibVersion())
        return info

    def test_cpu():
        import re
        xml = conn.getCapabilities()
        kvm = re.search('kvm', xml)
        if kvm:
            return True
        else:
            return False

    host = Host.objects.get(id=srv_id, user=request.user.id)
    host_vds = Vds.objects.filter(host=host.id, is_deleted=0)

    all_vds = {}
    for vds in host_vds:
        vds_user = User.objects.get(id=vds.user_id)
        flavor = Flavor.objects.get(id=vds.flavor_id, user=request.user.id)
        all_vds[vds.id] = (vds.name, vds.vname, vds_user.id, vds_user.username, flavor.vcpu, flavor.ram, flavor.hdd)

    conn = libvirt_conn(host)

    if type(conn) == dict:
        add_log(host.hostname, conn.values()[0], request.user.id)
    else:
        kvm_support = test_cpu()
        if not kvm_support:
            errors = []
            errors.append('Your CPU doesn\'t support hardware virtualization')

        host_info = get_host_info()
        conn.close()

    if request.method == 'POST':
        if 'delhost' in request.POST:
            del_host = Host.objects.get(id=srv_id)
            hostname = del_host.hostname
            del_host.is_deleted = True
            del_host.save()
            msg = 'Delete host'
            add_log(hostname, msg, request.user.id)
            return HttpResponseRedirect('/manage/')

    return render_to_response('host.html', locals(), context_instance=RequestContext(request))


def order(request):
    """
    Order block in management interface
    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')

    orders = {}

    try:
        db_all_users = Deligation.objects.filter(admin=request.user)
    except:
        db_all_users = None

    if db_all_users:
        for db_user in db_all_users:
            try:
                order = Order.objects.get(user=db_user.user_id, is_deleted=0, is_active=0)
                flavor = Flavor.objects.get(id=order.flavor_id)
                users = User.objects.get(id=db_user.user_id)
                orders[order.id] = (users.id, users.username, order.name, flavor.name, order.date_create, order.is_active)
            except:
                pass

    try:
        db_orders = Order.objects.filter(user=request.user, is_deleted=0, is_active=0)
    except:
        db_orders = None

    if db_orders:
        for order in db_orders:
            flavor = Flavor.objects.get(id=order.flavor_id)
            users = User.objects.get(id=order.user_id)
            orders[order.id] = (users.id, users.username, order.name, flavor.name, order.date_create, order.is_active)

    hosts = {}
    try:
        all_hosts = Host.objects.filter(user=request.user)
    except:
        all_hosts = None
    if all_hosts:
        for host in all_hosts:
            hosts[host.id] = host.hostname

    if request.method == 'POST':
        if 'delorder' in request.POST:
            order_id = request.POST.get('order_id', '')
            del_order = Order.objects.get(id=order_id)
            server_name = del_order.name
            del_order.is_deleted = 1
            del_order.save()

            hostname = '-'
            if is_user:
                adm_msg = 'Delete order to for the virtual instance: %s, User: %s' % (server_name, users.username)
                add_log(hostname, adm_msg, is_user.admin_id)
                usr_msg = 'Delete order to for the virtual instance: %s' % server_name
                add_log(hostname, usr_msg, request.user.id)
            else:
                usr_msg = 'Admin delete order to for the virtual instance: %s' % server_name
                add_log(hostname, usr_msg, del_order.user_id)
                usr_msg = 'Delete order to for the virtual instance: %s, User: %s' % (server_name, users.username)
                add_log(hostname, usr_msg, request.user.id)

            return HttpResponseRedirect(request.get_full_path())

    return render_to_response('order.html', locals(), context_instance=RequestContext(request))


def flavor(request):
    """
    Flavors block

    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')

    if is_user:
        db_flavors = Flavor.objects.filter(user=is_user.admin_id, is_deleted=0)
    else:
        db_flavors = Flavor.objects.filter(user=request.user, is_deleted=0)

    flavors = {}
    for flavor in db_flavors:
        use_vds = Vds.objects.filter(flavor=flavor.id, is_deleted=0)
        use_order = Order.objects.filter(flavor=flavor.id, is_active=0, is_deleted=0)
        if use_vds or use_order:
            usage = True
        else:
            usage = False
        flavors[flavor.id] = (flavor.name, flavor.vcpu, flavor.ram, flavor.hdd, flavor.price, usage)

    price_form = []
    for digit in range(0, 201):
        price_form.append(digit)

    if request.method == 'POST':
        if 'addflavor' in request.POST:
            name = request.POST.get('name', '')
            vcpu = request.POST.get('vcpu', '')
            ram = request.POST.get('ram', '')
            hdd = request.POST.get('hdd', '')
            price = request.POST.get('price', '')

            import re
            errors = []
            have_simbol = re.search('[^a-zA-Z0-9\_]+', name)

            if not name:
                msg = 'No name has been entered'
                errors.append(msg)
            elif len(name) > 12:
                msg = 'The name must not exceed 12 characters'
                errors.append(msg)
            else:
                if have_simbol:
                    msg = 'The host name must not contain any characters'
                    errors.append(msg)
                else:
                    try:
                        flavor_is = Flavor.objects.get(name=name, user=request.user)
                    except:
                        flavor_is = None
                    if flavor_is:
                        msg = 'Name flavor alredy use'
                        errors.append(msg)
            if not errors:
                add_flavor = Flavor(name=name, vcpu=vcpu, ram=ram, hdd=hdd, price=price, user=request.user)
                add_flavor.save()
                msg = 'Add flavor: %s' % name
                hostname = '-'
                add_log(hostname, msg, request.user.id)
                return HttpResponseRedirect(request.get_full_path())
        if 'delflavor' in request.POST:
            flavor_id = request.POST.get('flavor_id', '')
            del_flavor = Flavor.objects.get(id=flavor_id, user=request.user)
            msg = 'Delete flavor: %s' % del_flavor.name
            del_flavor.is_deleted = 1
            del_flavor.save()
            hostname = '-'
            add_log(hostname, msg, request.user.id)
            return HttpResponseRedirect(request.get_full_path())

    return render_to_response('flavor.html', locals(), context_instance=RequestContext(request))


def users(request):
    """
    Users block

    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')
    if is_user:
        return HttpResponseRedirect('/home')

    try:
        admin_users = Deligation.objects.filter(admin=request.user)
    except:
        admin_users = None

    all_users = {}
    if admin_users:
        for adm_user in admin_users:
            db_user = User.objects.get(id=adm_user.user_id)
            all_users[db_user.id] = (db_user.username, db_user.first_name, db_user.last_name, db_user.email, db_user.is_active)

    if request.method == 'POST':
        if 'adduser' in request.POST:
            username = request.POST.get('username', '')
            email = request.POST.get('email', '')
            password1 = request.POST.get('password1', '')
            password2 = request.POST.get('password2', '')

            import re
            errors = []
            have_simbol = re.search('[^a-zA-Z0-9\_]+', username)

            if not username:
                msg = 'No hostname has been entered'
                errors.append(msg)
            elif len(username) > 12:
                msg = 'The username must not exceed 12 characters'
                errors.append(msg)
            else:
                if have_simbol:
                    msg = 'The host name must not contain any characters'
                    errors.append(msg)
                else:
                    try:
                        user_is = User.objects.get(username=username)
                    except:
                        user_is = None
                    if user_is:
                        msg = 'Username alredy exist'
                        errors.append(msg)
            if not email:
                msg = 'No email has been entered'
                errors.append(msg)
            else:
                try:
                    email_is = User.objects.get(email=email)
                except:
                    email_is = None
                if email_is:
                    msg = 'Email alredy use'
                    errors.append(msg)
            if not password1:
                msg = 'No password has been entered'
                errors.append(msg)
            if not password2:
                msg = 'No password confirm has been entered'
                errors.append(msg)
            else:
                if password1 != password2:
                    msg = 'Your password didn\'t match. Please try again.'
                    errors.append(msg)
            if not errors:
                from django.contrib.auth.models import User as Useradd
                add_user = Useradd.objects.create_user(username, email, password1)
                add_user.is_staff = True
                add_user.save()
                check_user = User.objects.get(username=username, email=email)
                deligation = Deligation(user=check_user, admin=request.user)
                deligation.save()
                msg = 'Create new user: %s' % username
                hostname = '-'
                add_log(hostname, msg, request.user.id)
                return HttpResponseRedirect(request.get_full_path())

    return render_to_response('users.html', locals(), context_instance=RequestContext(request))


def users_profile(request, usr_id):
    """
    Users profile block

    """

    try:
        is_user = Deligation.objects.get(user=request.user.id)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')
    if is_user:
        return HttpResponseRedirect('/home')

    try:
        profile = Deligation.objects.get(admin=request.user.id, user=usr_id)
    except:
        profile = None

    try:
        have_vds = Vds.objects.filter(user=profile.user_id, is_deleted=0)
    except:
        have_vds = None

    try:
        have_orders = Order.objects.filter(user=profile.user_id, is_deleted=0, is_active=0)
    except:
        have_orders = None

    if profile:
        profile_user = User.objects.get(id=profile.user_id)

    if request.method == 'POST':
        if 'update' in request.POST:
            user_id = request.POST.get('user_id', '')
            update_data = User.objects.get(id=user_id)
            if request.POST.get('firstname', ''):
                update_data.first_name = request.POST.get('firstname', '')
            if request.POST.get('lastname', ''):
                update_data.last_name = request.POST.get('lastname', '')
            if request.POST.get('email', ''):
                update_data.email = request.POST.get('email', '')
            update_data.save()
            msg = 'Update info user: %s' % profile_user.username
            hostname = '-'
            add_log(hostname, msg, request.user.id)
            return HttpResponseRedirect(request.get_full_path())
        if 'activate' in request.POST:
            user_id = request.POST.get('user_id', '')
            update_user = User.objects.get(id=user_id)
            update_user.is_active = True
            update_user.save()
            msg = 'Activate user: %s' % profile_user.username
            hostname = '-'
            add_log(hostname, msg, request.user.id)
            return HttpResponseRedirect(request.get_full_path())
        if 'block' in request.POST:
            user_id = request.POST.get('user_id', '')
            update_user = User.objects.get(id=user_id)
            update_user.is_active = False
            update_user.save()
            msg = 'Block user: %s' % profile_user.username
            hostname = '-'
            add_log(hostname, msg, request.user.id)
            return HttpResponseRedirect(request.get_full_path())
        if 'newpasswd' in request.POST:
            user_id = request.POST.get('user_id', '')
            password1 = request.POST.get('password1', '')
            password2 = request.POST.get('password2', '')
            errors = []
            if not password1:
                msg = "Enter password"
                errors.append(msg)
            elif not password2:
                msg = "Enter confirm password"
                errors.append(msg)
            elif password1 != password2:
                errors.append('Password mismatch')
            if not errors:
                update_user = User.objects.get(id=user_id)
                update_user.set_password(password2)
                update_user.save()
                msg = 'Change password user: %s' % profile_user.username
                hostname = '-'
                add_log(hostname, msg, request.user.id)
                messages = []
                messages.append('Password seccesfyl changed')
        if 'delete' in request.POST:
            user_id = request.POST.get('user_id', '')
            del_user = User.objects.get(id=user_id)
            del_user.delete()
            msg = 'Delete user: %s' % profile_user.username
            hostname = '-'
            add_log(hostname, msg, request.user.id)
            return HttpResponseRedirect('/users/')

    return render_to_response('users_profile.html', locals(), context_instance=RequestContext(request))


def log(request):
    """
    Generate user logs.

    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')

    all_logs = Log.objects.filter(user=request.user).order_by('-date')[:50]

    return render_to_response('log.html', locals(), context_instance=RequestContext(request))


def newvm(request, srv_id):
    """
    NewVM block

    """

    from libvirt import libvirtError

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')
    if is_user:
        return HttpResponseRedirect('/home')

    def test_cpu():
        import re
        xml = conn.getCapabilities()
        kvm = re.search('kvm', xml)
        if kvm:
            return True
        else:
            return False

    def all_networks():
        virtnet = {}
        for network in conn.listNetworks():
            net = conn.networkLookupByName(network)
            status = net.isActive()
            virtnet[network] = status
        for network in conn.listDefinedNetworks():
            net = conn.networkLookupByName(network)
            status = net.isActive()
            virtnet[network] = status
        return virtnet

    def all_storages():
        storages = {}
        for storage in conn.listStoragePools():
            stg = conn.storagePoolLookupByName(storage)
            status = stg.isActive()
            storages[storage] = status
        for storage in conn.listDefinedStoragePools():
            stg = conn.storagePoolLookupByName(storage)
            status = stg.isActive()
            storages[storage] = status
        return storages

    def add_vol(name, size):
        size = int(size) * 1073741824
        xml = """
            <volume>
                <name>%s.img</name>
                <capacity>%s</capacity>
                <allocation>0</allocation>
                <target>
                    <format type='qcow2'/>
                </target>
            </volume>""" % (name, size)
        stg.createXML(xml, 0)

    def add_vm(name, ram, vcpu, image, net, passwd):
        import virtinst.util as util
        import re

        arch = conn.getInfo()[0]
        hostcap = conn.getCapabilities()
        iskvm = re.search('kvm', hostcap)

        xml_machine = conn.getCapabilities()
        machine = util.get_xml_path(xml_machine, "/capabilities/guest/arch/machine/@canonical")

        emulator = []
        xml_emul = conn.getCapabilities()
        arch = conn.getInfo()[0]
        if arch == 'x86_64':
            emulator.append(util.get_xml_path(xml_emul, "/capabilities/guest[1]/arch/emulator"))
            emulator.append(util.get_xml_path(xml_emul, "/capabilities/guest[2]/arch/emulator"))
        else:
            emulator = util.get_xml_path(xml_emul, "/capabilities/guest/arch/emulator")

        if iskvm:
            dom_type = 'kvm'
        else:
            dom_type = 'qemu'

        xml = """<domain type='%s'>
                  <name>%s</name>
                  <memory>%s</memory>
                  <currentMemory>%s</currentMemory>
                  <vcpu>%s</vcpu>
                  <os>
                    <type arch='%s' machine='%s'>hvm</type>
                    <boot dev='hd'/>
                    <boot dev='cdrom'/>
                    <bootmenu enable='yes'/>
                  </os>
                  <features>
                    <acpi/>
                    <apic/>
                    <pae/>
                  </features>
                  <clock offset='utc'/>
                  <on_poweroff>destroy</on_poweroff>
                  <on_reboot>restart</on_reboot>
                  <on_crash>restart</on_crash>
                  <devices>""" % (dom_type, name, ram, ram, vcpu, arch, machine)

        if arch == 'x86_64':
            xml += """<emulator>%s</emulator>""" % (emulator[1])
        else:
            xml += """<emulator>%s</emulator>""" % (emulator)

        xml += """<disk type='file' device='disk'>
                      <driver name='qemu' type='qcow2'/>
                      <source file='%s'/>
                      <target dev='hda' bus='ide'/>
                    </disk>
                    <disk type='file' device='cdrom'>
                      <driver name='qemu' type='raw'/>
                      <source file=''/>
                      <target dev='hdc' bus='ide'/>
                      <readonly/>
                    </disk>
                    <controller type='ide' index='0'>
                      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x1'/>
                    </controller>
                    """ % (image)

        if re.findall("br", net):
            xml += """<interface type='bridge'>
                    <source bridge='%s'/>""" % (net)
        else:
            xml += """<interface type='network'>
                    <source network='%s'/>""" % (net)

        xml += """<address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
                    </interface>
                    <input type='tablet' bus='usb'/>
                    <input type='mouse' bus='ps2'/>
                    <graphics type='vnc' port='-1' autoport='yes' keymap='en-us' passwd='%s'/>
                    <video>
                      <model type='cirrus' vram='9216' heads='1'/>
                      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
                    </video>
                    <memballoon model='virtio'>
                      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
                    </memballoon>
                  </devices>
                </domain>""" % (passwd)
        conn.defineXML(xml)
        dom = conn.lookupByName(name)
        dom.setAutostart(1)

    host = Host.objects.get(id=srv_id, user=request.user)
    conn = libvirt_conn(host)

    if type(conn) == dict:
        add_log(host.hostname, conn.values()[0], request.user.id)
        return HttpResponseRedirect('/manage/')
    else:
        kvm_support = test_cpu()
        if not kvm_support:
            errors = []
            errors.append('Your CPU doesn\'t support hardware virtualization')

        all_networks = all_networks()
        all_storages = all_storages()

        try:
            db_all_users = Deligation.objects.filter(admin=request.user)
        except:
            db_all_users = None

        orders = {}
        if db_all_users:
            for db_user in db_all_users:
                try:
                    order = Order.objects.get(user=db_user.id, is_active=0, is_deleted=0)
                    flavor = Flavor.objects.get(id=order.flavor_id)
                    users = User.objects.get(id=db_user.user_id)
                    orders[order.id] = (order.name, users.id, users.username, flavor.vcpu, flavor.ram, flavor.hdd)
                except:
                    pass

        try:
            db_orders = Order.objects.filter(user=request.user, is_active=0, is_deleted=0)
        except:
            db_orders = None

        if db_orders:
            for order in db_orders:
                flavor = Flavor.objects.get(id=order.flavor_id)
                users = User.objects.get(id=order.user_id)
                orders[order.id] = (order.name, users.id, users.username, flavor.vcpu, flavor.ram, flavor.hdd)

        if request.method == 'POST':
            if 'addvds' in request.POST:
                order_id = request.POST.get('order_id', '')
                net = request.POST.get('network', '')
                storage = request.POST.get('storage', '')
                desc = request.POST.get('desc', '')

                order = Order.objects.get(id=order_id)
                user = User.objects.get(id=order.user_id)
                flavor = Flavor.objects.get(id=order.flavor_id)

                from string import letters, digits
                from random import choice

                vds_vname = 'vm-%s' % (order.id)
                vnc_passwd = ''.join([choice(letters + digits) for i in range(12)])

                stg = conn.storagePoolLookupByName(storage)
                add_vol(vds_vname, flavor.hdd)
                vol = vds_vname + '.img'
                vl = stg.storageVolLookupByName(vol)
                image = vl.path()

                add_vm(vds_vname, flavor.ram, flavor.vcpu, image, net, vnc_passwd)

                add_vds = Vds(user=user, flavor=flavor, host_id=srv_id, order=order, name=order.name, vname=vds_vname, vnc_passwd=vnc_passwd, desc=desc, is_active=1)
                add_vds.save()
                appr_order = Order.objects.get(id=order.id)
                appr_order.is_active = True
                appr_order.save()

                if request.user.id == order.user_id:
                    msg = 'Creave virtual instance: %s' % order.name
                    add_log(host.hostname, msg, request.user.id)
                else:
                    adm_msg = 'Creave virtual instance: %s' % order.name
                    add_log(host.hostname, adm_msg, request.user.id)
                    usr_msg = 'Creave virtual instance'
                    add_log(order.name, usr_msg, order.user_id)
                return HttpResponseRedirect('/host/%s/' % srv_id)

        conn.close()

    return render_to_response('newvm.html', locals(), context_instance=RequestContext(request))


def network(request, srv_id):
    """
    Network block
    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/accounts/login')
    if is_user:
        return HttpResponseRedirect('/home')

    host = Host.objects.get(id=srv_id, user=request.user.id)
    conn = libvirt_conn(host)

    if type(conn) == dict:
        add_log(host.hostname, conn.values()[0], request.user.id)
        return HttpResponseRedirect('/manage/')
    else:
        virtnet = {}
        for network in conn.listNetworks():
            net = conn.networkLookupByName(network)
            status = net.isActive()
            virtnet[network] = status
        for network in conn.listDefinedNetworks():
            net = conn.networkLookupByName(network)
            status = net.isActive()
            virtnet[network] = status

        conn.close()

    if len(virtnet) == 0:
        return HttpResponseRedirect('/network/%s/add/' % (srv_id))
    else:
        return HttpResponseRedirect('/network/%s/%s/' % (srv_id, virtnet.keys()[0]))


def network_pool(request, srv_id, pool):
    """
    Networks block

    """

    from libvirt import libvirtError

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')
    if is_user:
        return HttpResponseRedirect('/home')

    def all_networks():
        virtnet = {}
        for network in conn.listNetworks():
            net = conn.networkLookupByName(network)
            status = net.isActive()
            virtnet[network] = status
        for network in conn.listDefinedNetworks():
            net = conn.networkLookupByName(network)
            status = net.isActive()
            virtnet[network] = status
        return virtnet

    def add_new_pool(name, forward, gw, netmask, dhcp):
        xml = """
            <network>
                <name>%s</name>""" % (name)

        if forward == "nat" or "route":
            xml += """<forward mode='%s'/>""" % (forward)

        xml += """<bridge stp='on' delay='0' />
                    <ip address='%s' netmask='%s'>""" % (gw, netmask)

        if dhcp[0] == '1':
            xml += """<dhcp>
                        <range start='%s' end='%s' />
                    </dhcp>""" % (dhcp[1], dhcp[2])

        xml += """</ip>
            </network>"""
        conn.networkDefineXML(xml)

    def net_info():
        info = []
        info.append(net.isActive())
        info.append(net.bridgeName())
        return info

    def ipv4_net():
        import virtinst.util as util
        from polls.IPy import IP

        ipv4 = []
        xml_forward = net.XMLDesc(0)
        fw = util.get_xml_path(xml_forward, "/network/forward/@mode")
        forwardDev = util.get_xml_path(xml_forward, "/network/forward/@dev")
        ipv4.append([fw, forwardDev])

        xml_net = net.XMLDesc(0)
        addrStr = util.get_xml_path(xml_net, "/network/ip/@address")
        netmaskStr = util.get_xml_path(xml_net, "/network/ip/@netmask")
        netmask = IP(netmaskStr)
        gateway = IP(addrStr)
        network = IP(gateway.int() & netmask.int())
        ipv4.append(IP(str(network) + "/" + netmaskStr))

        xml_dhcp = net.XMLDesc(0)
        dhcpstart = util.get_xml_path(xml_dhcp, "/network/ip/dhcp/range[1]/@start")
        dhcpend = util.get_xml_path(xml_dhcp, "/network/ip/dhcp/range[1]/@end")
        if not dhcpstart or not dhcpend:
            pass
        else:
            ipv4.append([IP(dhcpstart), IP(dhcpend)])
        return ipv4

    host = Host.objects.get(id=srv_id, user=request.user.id)
    conn = libvirt_conn(host)

    if type(conn) == dict:
        add_log(host.hostname, conn.values()[0], request.user.id)
        return HttpResponseRedirect('/manage/')
    else:
        if pool == 'add':
            if request.method == 'POST':
                if 'addpool' in request.POST:
                    dhcp = []
                    pool_name = request.POST.get('name', '')
                    net_addr = request.POST.get('net_addr', '')
                    forward = request.POST.get('forward', '')
                    dhcp.append(request.POST.get('dhcp', ''))

                    networks = all_networks()

                    import re
                    errors = []
                    name_have_simbol = re.search('[^a-zA-Z0-9\_]+', pool_name)
                    ip_have_simbol = re.search('[^0-9\.\/]+', net_addr)

                    if not pool_name:
                        msg = 'No pool name has been entered'
                        errors.append(msg)
                    elif len(pool_name) > 12:
                        msg = 'The host name must not exceed 20 characters'
                        errors.append(msg)
                    else:
                        if name_have_simbol:
                            msg = 'The pool name must not contain any characters and Russian characters'
                            errors.append(msg)
                    if not net_addr:
                        msg = 'No subnet has been entered'
                        errors.append(msg)
                    elif ip_have_simbol:
                        msg = 'The pool name must not contain any characters'
                        errors.append(msg)
                    if pool_name in networks.keys():
                        msg = 'Pool name already use'
                        errors.append(msg)
                    try:
                        from polls.IPy import IP

                        netmask = IP(net_addr).strNetmask()
                        ipaddr = IP(net_addr)
                        gateway = ipaddr[0].strNormal()[-1]
                        if gateway == '0':
                            gw = ipaddr[1].strNormal()
                            dhcp_start = ipaddr[2].strNormal()
                            end = ipaddr.len() - 2
                            dhcp_end = ipaddr[end].strNormal()
                        else:
                            gw = ipaddr[0].strNormal()
                            dhcp_start = ipaddr[1].strNormal()
                            end = ipaddr.len() - 2
                            dhcp_end = ipaddr[end].strNormal()
                        dhcp.append(dhcp_start)
                        dhcp.append(dhcp_end)
                    except:
                        msg = 'Input subnet pool error'
                        errors.append(msg)
                    if not errors:
                        try:
                            add_new_pool(pool_name, forward, gw, netmask, dhcp)
                            net = conn.networkLookupByName(pool_name)
                            net.create()
                            net.setAutostart(1)
                            msg = 'Create network pool: %s' % pool_name
                            add_log(host.hostname, msg, request.user.id)
                            return HttpResponseRedirect('/network/%s/%s/' % (srv_id, pool_name))
                        except libvirtError as error_msg:
                            errors.append(error_msg.message)
                            add_log(host.hostname, error_msg.message, request.user.id)
        else:
            net = conn.networkLookupByName(pool)

            info = net_info()
            networks = all_networks()
            if info[0] == True:
                ipv4_net = ipv4_net()

            if request.method == 'POST':
                if 'start' in request.POST:
                    try:
                        net.create()
                        msg = 'Start network pool: %s' % pool
                        add_log(host.hostname, msg, request.user.id)
                        return HttpResponseRedirect('/network/%s/%s' % (srv_id, pool))
                    except libvirtError as error_msg:
                        add_log(host.hostname, error_msg.message, request.user.id)
                if 'stop' in request.POST:
                    try:
                        net.destroy()
                        msg = 'Stop network pool: %s' % pool
                        add_log(host.hostname, msg, request.user.id)
                    except libvirtError as error_msg:
                        add_log(host.hostname, error_msg.message, request.user.id)
                    return HttpResponseRedirect('/network/%s/%s' % (srv_id, pool))
                if 'delete' in request.POST:
                    try:
                        net.undefine()
                        msg = 'Delete network pool: %s' % pool
                        add_log(host.hostname, msg, request.user.id)
                    except libvirtError as error_msg:
                        add_log(host.hostname, error_msg.message, request.user.id)
                    return HttpResponseRedirect('/network/%s/' % srv_id)

        conn.close()

    return render_to_response('network.html', locals(), context_instance=RequestContext(request))


def storage(request, srv_id):
    """
    Storages block

    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')
    if is_user:
        return HttpResponseRedirect('/home')

    host = Host.objects.get(id=srv_id, user=request.user)
    conn = libvirt_conn(host)

    if type(conn) == dict:
        add_log(host.hostname, conn.values()[0], request.user.id)
        return HttpResponseRedirect('/manage/')
    else:
        storages = {}
        for storage in conn.listStoragePools():
            stg = conn.storagePoolLookupByName(storage)
            status = stg.isActive()
            storages[storage] = status
        for storage in conn.listDefinedStoragePools():
            stg = conn.storagePoolLookupByName(storage)
            status = stg.isActive()
            storages[storage] = status

        conn.close()

    if len(storages) == 0:
        return HttpResponseRedirect('/storage/%s/add/' % (srv_id))
    else:
        return HttpResponseRedirect('/storage/%s/%s/' % (srv_id, storages.keys()[0]))


def storage_pool(request, srv_id, pool):
    """
    Storages block

    """

    from libvirt import libvirtError

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')
    if is_user:
        return HttpResponseRedirect('/home')

    def add_new_pool(type_pool, name, source, target):
        xml = """
                <pool type='%s'>
                <name>%s</name>""" % (type_pool, name)

        if pool_type == 'logical':
            xml += """
                  <source>
                    <device path='%s'/>
                    <name>%s</name>
                    <format type='lvm2'/>
                  </source>""" % (source, name)

        if pool_type == 'logical':
            target = '/dev/' + name

        xml += """
                  <target>
                       <path>%s</path>
                  </target>
                </pool>""" % (target)
        conn.storagePoolDefineXML(xml, 0)

    def add_vol(name, size):
        size = int(size) * 1073741824
        xml = """
            <volume>
                <name>%s.img</name>
                <capacity>%s</capacity>
                <allocation>0</allocation>
                <target>
                    <format type='qcow2'/>
                </target>
            </volume>""" % (name, size)
        stg.createXML(xml, 0)

    def clone_vol(img, new_img):
        vol = stg.storageVolLookupByName(img)
        xml = """
            <volume>
                <name>%s</name>
                <capacity>0</capacity>
                <allocation>0</allocation>
                <target>
                    <format type='qcow2'/>
                </target>
            </volume>""" % (new_img)
        stg.createXMLFrom(xml, vol, 0)

    def stg_info():
        import virtinst.util as util

        if stg.info()[3] == 0:
            percent = 0
        else:
            percent = (stg.info()[2] * 100) / stg.info()[1]
        info = stg.info()
        info.append(int(percent))
        info.append(stg.isActive())
        xml = stg.XMLDesc(0)
        info.append(util.get_xml_path(xml, "/pool/@type"))
        info.append(util.get_xml_path(xml, "/pool/target/path"))
        info.append(util.get_xml_path(xml, "/pool/source/device/@path"))
        info.append(util.get_xml_path(xml, "/pool/source/format/@type"))
        return info

    def stg_vol():
        import virtinst.util as util

        volinfo = {}
        for name in stg.listVolumes():
            vol = stg.storageVolLookupByName(name)
            xml = vol.XMLDesc(0)
            size = vol.info()[1]
            format = util.get_xml_path(xml, "/volume/target/format/@type")
            volinfo[name] = size, format
        return volinfo

    def all_storages():
        storages = {}
        for storage in conn.listStoragePools():
            stg = conn.storagePoolLookupByName(storage)
            status = stg.isActive()
            storages[storage] = status
        for storage in conn.listDefinedStoragePools():
            stg = conn.storagePoolLookupByName(storage)
            status = stg.isActive()
            storages[storage] = status
        return storages

    host = Host.objects.get(id=srv_id, user=request.user.id)
    conn = libvirt_conn(host)

    if type(conn) == dict:
        add_log(host.hostname, conn.values()[0], request.user.id)
        return HttpResponseRedirect('/manage/')
    else:
        if pool == 'add':
            if request.method == 'POST':
                if 'addpool' in request.POST:
                    pool_name = request.POST.get('name', '')
                    pool_type = request.POST.get('type', '')
                    pool_target = request.POST.get('target', '')
                    pool_source = request.POST.get('source', '')

                    import re
                    errors = []
                    name_have_simbol = re.search('[^a-zA-Z0-9\_]+', pool_name)
                    path_have_simbol = re.search('[^a-zA-Z0-9\/]+', pool_source)

                    storages = all_storages()

                    if name_have_simbol or path_have_simbol:
                        msg = 'The host name must not contain any characters'
                        errors.append(msg)
                    if not pool_name:
                        msg = 'No pool name has been entered'
                        errors.append(msg)
                    elif len(pool_name) > 12:
                        msg = 'The host name must not exceed 12'
                        errors.append(msg)
                    if pool_type == 'logical':
                        if not pool_source:
                            msg = 'No device has been entered'
                            errors.append(msg)
                    if pool_type == 'dir':
                        if not pool_target:
                            msg = 'No path has been entered'
                            errors.append(msg)
                    if pool_name in storages.keys():
                        msg = 'Pool name already use'
                        errors.append(msg)
                    if not errors:
                        try:
                            add_new_pool(pool_type, pool_name, pool_source, pool_target)
                            stg = conn.storagePoolLookupByName(pool_name)
                            if pool_type == 'logical':
                                stg.build(0)
                            stg.create(0)
                            stg.setAutostart(1)
                            msg = 'Create storage pool: %s' % pool_name
                            add_log(host.hostname, msg, request.user.id)
                            return HttpResponseRedirect('/storage/%s/%s/' % (srv_id, pool_name))
                        except libvirtError as error_msg:
                            errors.append(error_msg.message)
                            add_log(host.hostname, error_msg.message, request.user.id)
        else:
            form_hdd_size = [10, 20, 40, 80, 160, 320]
            stg = conn.storagePoolLookupByName(pool)

            info = stg_info()
            storages = all_storages()
            # refresh storage if acitve
            if info[5] == True:
                stg.refresh(0)
                volumes_info = stg_vol()

            if request.method == 'POST':
                if 'start' in request.POST:
                    try:
                        stg.create(0)
                        msg = 'Start storage pool: %s' % pool
                        add_log(host.hostname, msg, request.user.id)
                    except libvirtError as error_msg:
                        add_log(host.hostname, error_msg.message, request.user.id)
                    return HttpResponseRedirect('/storage/%s/%s' % (srv_id, pool))
                if 'stop' in request.POST:
                    try:
                        stg.destroy()
                        msg = 'Stop storage pool: %s' % pool
                        add_log(host.hostname, msg, request.user.id)
                    except libvirtError as error_msg:
                        add_log(host.hostname, error_msg.message, request.user.id)
                    return HttpResponseRedirect('/storage/%s/%s' % (srv_id, pool))
                if 'delete' in request.POST:
                    try:
                        stg.undefine()
                        msg = 'Delete storage pool: %s' % pool
                        add_log(host.hostname, msg, request.user.id)
                    except libvirtError as error_msg:
                        add_log(host.hostname, error_msg.message, request.user.id)
                    return HttpResponseRedirect('/storage/%s/' % srv_id)
                if 'addimg' in request.POST:
                    name = request.POST.get('name', '')
                    size = request.POST.get('size', '')
                    img_name = name + '.img'

                    import re
                    errors = []
                    name_have_simbol = re.search('[^a-zA-Z0-9\_\-]+', name)
                    if img_name in stg.listVolumes():
                        msg = 'Volume name already use'
                        errors.append(msg)
                    if not name:
                        msg = 'No name has been entered'
                        errors.append(msg)
                    elif len(name) > 20:
                        msg = 'The host name must not exceed 20'
                        errors.append(msg)
                    else:
                        if name_have_simbol:
                            msg = 'The host name must not contain any characters'
                            errors.append(msg)
                    if not errors:
                        add_vol(name, size)
                        msg = 'Add image: %s' % img_name
                        add_log(host.hostname, msg, request.user.id)
                        return HttpResponseRedirect('/storage/%s/%s' % (srv_id, pool))
                if 'delimg' in request.POST:
                    img = request.POST.get('img', '')
                    try:
                        vol = stg.storageVolLookupByName(img)
                        vol.delete(0)
                        msg = 'Delete image: %s' % img
                        add_log(host.hostname, msg, request.user.id)
                    except libvirtError as error_msg:
                        add_log(host.hostname, error_msg.message, request.user.id)
                    return HttpResponseRedirect('/storage/%s/%s' % (srv_id, pool))
                if 'clone' in request.POST:
                    img = request.POST.get('img', '')
                    new_img_name = request.POST.get('new_img', '')
                    new_img = new_img_name + '.img'
                    if info[6] == 'logical':
                        new_img = new_img_name
                    else:
                        new_img = new_img_name + '.img'
                    import re
                    errors = []
                    name_have_simbol = re.search('[^a-zA-Z0-9\_]+', new_img_name)
                    if new_img in stg.listVolumes():
                        msg = 'Volume name already use'
                        errors.append(msg)
                    if not new_img_name:
                        msg = 'No name has been entered'
                        errors.append(msg)
                    elif len(new_img_name) > 20:
                        msg = 'The host name must not exceed 20 characters'
                        errors.append(msg)
                    else:
                        if name_have_simbol:
                            msg = 'The host name must not contain any characters'
                            errors.append(msg)
                    if not errors:
                        clone_vol(img, new_img)
                        msg = 'Clone volume image: %s => %s' % (img, new_img)
                        add_log(host.hostname, msg, request.user.id)
                        return HttpResponseRedirect('/storage/%s/%s' % (srv_id, pool))

        conn.close()

    return render_to_response('storage.html', locals(), context_instance=RequestContext(request))


def snapshot(request, srv_id):
    """
    Snapshot block

    """

    try:
        is_user = Deligation.objects.get(user=request.user)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')
    if is_user:
        return HttpResponseRedirect('/home')

    def dom_have_snapshots(all_vname):
        vname = []
        for name in all_vname:
            dom = conn.lookupByName(name)
            if dom.snapshotNum(0) != 0:
                vname.append(dom.name())
        return vname

    host = Host.objects.get(id=srv_id, user=request.user)

    try:
        vds = Vds.objects.filter(host=host, is_deleted=0, is_active=1)
    except:
        vds = None

    if vds:
        all_vname = []
        for vm in vds:
            all_vname.append(vm.vname)
    else:
        all_vname = None

    conn = libvirt_conn(host)

    if type(conn) == dict:
        add_log(host.hostname, conn.values()[0], request.user.id)
        return HttpResponseRedirect('/manage/')
    else:
        if all_vname:
            dom_snapshots = dom_have_snapshots(all_vname)
            snapshots = {}
            for domain in dom_snapshots:
                snap_vds = Vds.objects.get(vname=domain)
                snap_user = User.objects.get(id=snap_vds.user_id)
                snap_flavor = Flavor.objects.get(id=snap_vds.flavor_id)
                snapshots[snap_vds.id] = snap_vds.name, snap_vds.vname, snap_user.id, snap_user.username, snap_flavor.name

    return render_to_response('snapshot.html', locals(), context_instance=RequestContext(request))


def snapshot_vds(request, srv_id, vds_id):
    """
    Snapshot block

    """

    from libvirt import libvirtError
    from datetime import datetime

    try:
        is_user = Deligation.objects.get(user=request.user.id)
    except:
        is_user = None

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login')
    if is_user:
        return HttpResponseRedirect('/home')

    def snapshots():
        snapshots = {}
        all_snapshot = dom.snapshotListNames(0)
        for snapshot in all_snapshot:
            snapshots[snapshot] = (datetime.fromtimestamp(int(snapshot)), dom.info()[0])
        return snapshots

    host = Host.objects.get(id=srv_id, user=request.user)
    vds = Vds.objects.get(id=vds_id, host=srv_id)

    conn = libvirt_conn(host)

    if type(conn) == dict:
        add_log(host.hostname, conn.values()[0], request.user.id)
        return HttpResponseRedirect('/manage/')
    else:
        dom = conn.lookupByName(vds.vname)
        snapshots = snapshots()

    if request.method == 'POST':
        if 'revert' in request.POST:
            name = request.POST.get('name', '')
            try:
                snap = dom.snapshotLookupByName(name, 0)
                dom.revertToSnapshot(snap, 0)
                msg = 'Revert snapshot %s to VDS %s' % (name, vds.name)
                add_log(host.hostname, msg, request.user.id)
                messages = []
                messages.append('Revert snapshot %s succesful' % name)
            except libvirtError as error_msg:
                add_log(host.hostname, error_msg.message, request.user.id)
        if 'delete' in request.POST:
            name = request.POST.get('name', '')
            try:
                snap = dom.snapshotLookupByName(name, 0)
                snap.delete(0)
                msg = 'Delete snapshot %s for VDS %s' % (name, vds.name)
                add_log(host.hostname, msg, request.user.id)
                messages = []
                messages.append('Revert snapshot %s succesful' % name)
                return HttpResponseRedirect('/snapshot/%s/%s/' % (srv_id, vds_id))
            except libvirtError as error_msg:
                add_log(host.hostname, error_msg.message, request.user.id)

    return render_to_response('dom_snapshot.html', locals(), context_instance=RequestContext(request))


def page_setup(request):
    return render_to_response('setup.html', locals(), context_instance=RequestContext(request))
