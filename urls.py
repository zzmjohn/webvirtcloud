from django.conf.urls.defaults import patterns, include, url
from webvirtcloud import settings

urlpatterns = patterns('',
    url(r'^$', 'polls.views.index', name='index'),
    url(r'^home/$', 'polls.views.home', name='home'),

    url(r'^login/$', 'django.contrib.auth.views.login', {'template_name': 'login.html'}),
    url(r'^logout/$', 'django.contrib.auth.views.logout', {'template_name': 'logout.html'}),
    url(r'^profile/$', 'polls.views.profile', name='profile'),

    url(r'^servers/$', 'polls.views.servers', name='servers'),
    url(r'^vds/(\d+)/$', 'polls.views.vds', name='vds'),
    url(r'^support/$', 'polls.views.support', name='support'),
    url(r'^vnc/(\d+)/$', 'polls.views.vnc', name='vnc'),
    url(r'^host/(\d+)/$', 'polls.views.host', name='host'),
    url(r'^order/$', 'polls.views.order', name='order'),
    url(r'^flavor/$', 'polls.views.flavor', name='flavor'),
    url(r'^manage/$', 'polls.views.manage', name='manage'),

    url(r'^users/$', 'polls.views.users', name='users'),
    url(r'^users/(\d+)/$', 'polls.views.users_profile', name='users_profile'),

    url(r'^newvm/(\d+)/$', 'polls.views.newvm', name='newvm'),

    url(r'^log/$', 'polls.views.log', name='log'),

    url(r'^network/(\d+)/$', 'polls.views.network', name='network'),
    url(r'^network/(\d+)/(\w+)/$', 'polls.views.network_pool', name='network_pool'),

    url(r'^storage/(\d+)/$', 'polls.views.storage', name='storage'),
    url(r'^storage/(\d+)/(\w+)/$', 'polls.views.storage_pool', name='storage_pool'),
    url(r'^storage/(\d+)/(\w+)/$', 'polls.views.storage_pool', name='storage_pool'),

    url(r'^snapshot/(\d+)/$', 'polls.views.snapshot', name='snapshot'),
    url(r'^snapshot/(\d+)/(\d+)/$', 'polls.views.snapshot_vds', name='snapshot_vds'),

    url(r'^setup/$', 'polls.views.page_setup', name='page_setup'),

    url(r'^static/(?P<path>.*)$', 'django.views.static.serve', {'document_root': settings.STATIC_ROOT, 'show_indexes': True}),
)
