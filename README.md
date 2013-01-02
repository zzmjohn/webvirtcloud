# Applince WebVirtCloud

## 1. Info

WebVirtCloud is a libvirt-based Web interface for managing private and public clouds. It allows you to delegate, create and configure new domains. A VNC viewer a full graphical console to the guest domain. KVM is currently the only hypervisor supported.

### Technology:

The application logic is written in Python & Django. The LIBVIRT Python bindings are used to interacting with the underlying hypervisor.


## 2. Installation

### Fedora 17 and above

Run:

    $ su -c 'yum -y install git Django python-virtinst httpd mod_python mod_wsgi'

### Ubuntu 12.04 and above

Run:

    $ sudo apt-get install git python-django virtinst apache2 libapache2-mod-python libapache2-mod-wsgi

### CentOS 6.2, RedHat 6.2 and above

Run:

    $ su -c 'rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm'
    $ su -c 'yum -y install git python-virtinst httpd mod_python mod_wsgi Django'

## 3. Setup

Run: 
    
    $ git clone git://github.com/retspen/webvirtcloud.git
    $ cd webvirtcloud
    $ ./manage.py syncdb

Enter the user information:

    You just installed Django's auth system, which means you don't have any superusers defined.
    Would you like to create one now? (yes/no): yes (Put: yes)
    Username (Leave blank to use 'admin'): admin (Put: your username or login)
    E-mail address: username@domain.local (Put: your email)
    Password: xxxxxx (Put: your password)
    Password (again): xxxxxx (Put: confirm password)
    Superuser created successfully.

Run app for test:

    $ ./manage.py runserver x.x.x.x:8000 (x.x.x.x - your IP address server)
    
Enter in your browser:
    
    http://x.x.x.x:8000 (x.x.x.x - your IP address server)

## 4. Setup Web (Choose only one method: Virtual Host or WSGI)

###1. Virtual Host 

Add file webvirtmgr.conf in conf.d directory (Ubuntu: "/etc/apache2/conf.d" or RedHat,Fedora,CentOS: "/etc/httpd/conf.d"):

    <VirtualHost *:80>
        ServerAdmin webmaster@dummy-host.example.com
        ServerName dummy-host.example.com

        SetHandler python-program
        PythonHandler django.core.handlers.modpython
        SetEnv DJANGO_SETTINGS_MODULE webvirtmgr.settings
        PythonOption django.root /webvirtcloud
        PythonDebug On
        PythonPath "['/var/www'] + sys.path"
        
        ErrorLog ${APACHE_LOG_DIR}/webvirtcloud-error_log
        CustomLog ${APACHE_LOG_DIR}/webvirtcloud-access_log common
    </VirtualHost>

Copy the folder and change owner (Ubuntu: "www-data:www-data", Fedora, Redhat, CentOS: "apache:apache"):

    $ sudo cp -r webvirtcloud /var/www/
    $ sudo chown -R www-data:www-data /var/www/webvirtcloud/

Reload apache:
    
    # service apache2 reload
    
###2. WSGI

Add file webvirtcloud.conf in conf.d directory (Ubuntu: "/etc/apache2/conf.d" or RedHat,Fedora,CentOS: "/etc/httpd/conf.d"):

    WSGIScriptAlias / /var/www/webvirtcloud/wsgi/django.wsgi
    Alias /static /var/www/webvirtcloud/static/
    Alias /media /var/www/webvirtcloud/media/
    <Directory /var/www/webvirtcloud/wsgi>
      Order allow,deny
      Allow from all
    </Directory>


Support: support@webvirtmgr.net
