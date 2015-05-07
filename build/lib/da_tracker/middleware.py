
from django.conf import settings
try:
    import json
except:
    from django.utils import simplejson as json
from django.utils.importlib import import_module

import time
import base64
import re
try:
    import urllib2
except ImportError:
    import urllib as urllib2
try:
    import Queue
except ImportError:
    import queue as Queue
import threading
import traceback


from logging import getLogger
logger = getLogger('django.analytics')


IP_FIELDS = ('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR')

def _setting(key, defval):
    return getattr(settings, 'DJANGO_ANALYTICS_' + key, defval)

def _get_class(path):
    i = path.rfind('.')
    module, cls = path[:i], path[i+1:]
    mod = import_module(module)
    return getattr(mod, cls)


class ReporterThread(threading.Thread):

    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            url = self.queue.get()
            try:
                urllib2.urlopen(url)
            except:
                logger.exception('Django Analytics middleware - problem getting %s', url)
            self.queue.task_done()


class UserProxy(object):

    def is_logged_in(self, request):
        return hasattr(request, 'user') and request.user.is_authenticated()

    def get_id(self, request):
        return request.user.id

    def get_username(self, request):
        return request.user.username

    def get_full_name(self, request):
        return request.user.get_full_name()

    def get_email(self, request):
        return request.user.email

    def get_tags(self, request):
        ret = ['staff'] if request.user.is_staff else []
        if _setting('TAG_USER_GROUPS', False):
            ret += request.user.groups.values_list('name', flat=True)
        return ret

    def get_date_joined(self, request):
        return request.user.date_joined


class TrackerMiddleware(object):

    def __init__(self):
        cls = _setting('USER_PROXY', None)
        self.userproxy = _get_class(cls)() if cls else UserProxy()
        self.queue = Queue.Queue()
        t = ReporterThread(self.queue)
        t.setDaemon(True)
        t.start()

    def process_request(self, request):
        t1 = time.time()
        data = self._get_data(request) # ts gets initialized here
        data['oh'] += int((time.time() - t1) * 1000)
        self._enable_sql_info_collection(request)
        return None

    def process_view(self, request, view_func, view_args, view_kwargs):
        t1 = time.time()
        data = self._get_data(request)
        data['vn'] = view_func.__module__ + '.' + view_func.__name__ if view_func.__module__ else view_func.__name__
        data['oh'] += int((time.time() - t1) * 1000)
        return None

    def process_response(self, request, response):
        t1 = time.time()
        try:
            source = self._get_source(request, response)
            if self.userproxy.is_logged_in(request):
                data = self._get_data(request)
                data['dn'] = request.get_host() # TBD strip away port number?
                data['rm'] = 'U' if request.method == 'PUT' else request.method[0]
                data['rp'] = request.get_full_path()
                data['ua'] = request.META.get('HTTP_USER_AGENT', '')
                for name in IP_FIELDS:
                    ip = request.META.get(name, '')
                    if ip and ip.lower() != 'unknown':
                        break
                ip = ip.split(',')[0].strip()
                data['ip'] = ip
                if request.is_secure():
                    data['rs'] = 1
                if request.is_ajax():
                    data['ra'] = 1
                self._get_sql_info(data)
                data['ui'] = self.userproxy.get_id(request)
                data['uu'] = self.userproxy.get_username(request)
                data['ue'] = self.userproxy.get_email(request)
                data['un'] = self.userproxy.get_full_name(request)
                data['ut'] = ','.join(self.userproxy.get_tags(request))
                date_joined = self.userproxy.get_date_joined(request)
                if date_joined:
                    data['uj'] = time.mktime(date_joined.timetuple())
                logger.debug('Django Analytics user data: id=%s; username=%s; email=%s; name=%s; tags=%s; joined=%s',
                             data['ui'], data['uu'], data['ue'], data['un'], data['ut'], date_joined)
                data['te'] = time.time()
                data['sc'] = response.status_code
                data['ct'] = response.get('Content-Type', None)
                data['vi'] = self._get_visit_id(request, response)
                data['oh'] += int((time.time() - t1) * 1000)
                encoded = '%s,%s' % (self._enc(data), source)
                url = 'https://%s/c.js?d=%s'  % (_setting('SERVER', 'trk2.djangoanalytics.com'), encoded)
                if len(url) <= 2000 and self._client_side_tracking(request, response):
                    pos = self._insertion_point(response.content)
                    if pos != -1:
                        tag = '<script type="text/javascript" async="async" src="%s"></script>\n' % url
                        response.content = response.content[:pos] + tag + response.content[pos:]
                    else:
                        self._enqueue(url)
                else:
                    self._enqueue(url)
        except:
            logger.exception('Exception in Django Analytics middleware')
        return response

    def process_exception(self, request, exception):
        t1 = time.time()
        if self.userproxy.is_logged_in(request):
            data = self._get_data(request)
            data['ex'] = traceback.format_exc()
            data['oh'] += int((time.time() - t1) * 1000)

    def _insertion_point(self, html):
        pos = html.rfind('</body', -500)
        if pos == -1:
            pos = html.rfind('</BODY', -500)
        return pos

    def _enqueue(self, url):
        self.queue.put(url.replace('c.js', 's.js', 1))

    def _get_visit_id(self, request, response):
        prefix = _setting('COOKIE_PREFIX', 'dac')
        name1 = prefix + '1'
        name2 = prefix + '2'
        if name1 in request.COOKIES and name2 in request.COOKIES:
            value = request.COOKIES[name1]
        else:
            value = str(int(round(time.time() / 120)))
        response.set_cookie(name1, value, max_age=None, domain=settings.SESSION_COOKIE_DOMAIN)
        response.set_cookie(name2, value, max_age=_setting('VISIT_TIMEOUT', 60) * 60, domain=settings.SESSION_COOKIE_DOMAIN)
        return value

    def _get_source(self, request, response):
        name = _setting('COOKIE_PREFIX', 'dac') + '3'
        value = request.COOKIES.get(name, None)
        if value:
            if self.userproxy.is_logged_in(request) and len(value) > 1:
                response.set_cookie(name, '0', max_age=3650 * 24 * 60 * 60, domain=settings.SESSION_COOKIE_DOMAIN)
                return value
        else:
            value = self._enc(dict(lp=request.get_full_path(), rf=request.META.get('HTTP_REFERER', '')))
            response.set_cookie(name, value, max_age=90 * 24 * 60 * 60, domain=settings.SESSION_COOKIE_DOMAIN)
        return ''

    def _client_side_tracking(self, request, response):
        if response.status_code != 200 or request.is_ajax():
            return False
        ct = response.get('Content-Type', '').lower()
        return ct.startswith('text/html') or ct.startswith('text/xhtml')

    def _get_data(self, request):
        key = 'django_analytics_data'
        if hasattr(request, key):
            return getattr(request, key)
        data = dict(qc=0, qt=0, qs=0, ts=time.time(), oh=0)
        setattr(request, key, data)
        return data

    def _enc(self, data):
        return base64.urlsafe_b64encode(json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))

    def _enable_sql_info_collection(self, request):
        # Enable debug cursors
        if settings.DEBUG == False and self.userproxy.is_logged_in(request):
            try:
                from django.db import connections
                for connection in connections.all():
                    connection.use_debug_cursor = True
            except:
                pass
        # Cancel out any queries that occurred in previous middlewares
        data = self._get_data(request)
        self._get_sql_info(data)
        for key in ('qc', 'qt', 'qs'):
            data[key] = data[key] * -1

    def _get_sql_info(self, data):
        try:
            from django.db import connections
            for connection in connections.all():
                self._aggregate_sql_info(connection, data)
        except:
            from django.db import connection
            self._aggregate_sql_info(connection, data)

    def _aggregate_sql_info(self, connection, data):
        slow_query_time = _setting('SLOW_QUERY_TIME', 500)
        data['qc'] += len(connection.queries)
        for query in connection.queries:
            query_time = query.get('time')
            if query_time is None:
                query_time = query.get('duration', 0)
            else:
                query_time = int(round(float(query_time) * 1000))
            data['qt'] += query_time
            if query_time >= slow_query_time:
                data['qs'] += 1
