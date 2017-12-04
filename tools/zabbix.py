#!/usr/bin/env python
#ecoding:utf-8

##zabbix api验证配置文件

import json, sys, urllib2

reload(sys)
sys.setdefaultencoding('utf8')

class Efun_zabbix():

    __zabbix_server = 'zabbix url'
    __zabbix_user = 'zabbix user'
    __zabbix_passwd = 'zabbix password'


    @classmethod
    def login(cls, username=__zabbix_user, password=__zabbix_passwd):
        user_info = {'user':username,'password':password}
        obj = {"jsonrpc":"2.0","method":'user.login',"params":user_info,"id":0}
        json_obj = json.dumps(obj)
        content = cls.postRequest(json_obj)
        return content['result']

    @classmethod
    def postRequest(cls, json_obj):
        header = {'Content-Type':'application/json-rpc','User-Agent':'python/zabbix_api'}
        url = '%sapi_jsonrpc.php' % cls.__zabbix_server
        request = urllib2.Request(url, json_obj, header)
        result = urllib2.urlopen(request)
        content = json.loads(result.read())
        return content

    @classmethod
    def get_json_obj(cls, method, params):
        get_obj = {"jsonrpc":"2.0","method":method,"params":params,"auth":cls.login(),"id":1}
        return cls.postRequest(json.dumps(get_obj))

#整合获取数据方法。用于做调用处理
class zabbix_function(Efun_zabbix):

    @classmethod
    #filter为过滤字符串
    def get_hostgroup(cls, params=None):
        if not params:
            params = {"output":"extend"}
        method = 'hostgroup.get'
        return cls.get_json_obj(method, params)['result']

    @classmethod
    def get_trigger(cls, hostids=[], params=None):
        if not params:
            params = {"output":"extend", "hostids": hostids}
        method = 'trigger.get'

        return cls.get_json_obj(method, params)['result']

    @classmethod
    def get_application(cls, params=None):
        if not params:
            params = {"output":"extend"}
        method = 'application.get'
        return cls.get_json_obj(method, params)['result']


    @classmethod
    def get_host(cls, params=None):
        if not params:
            params = {"output":"extend"}
        method = 'host.get'
        return cls.get_json_obj(method, params)['result']

    @classmethod
    def get_item(cls, params=None):
        if not params:
            params = {"output":"extend"}
        method = 'item.get'
        return cls.get_json_obj(method, params)['result']

    @classmethod
    def get_action(cls, params=None):
        if not params:
            params = {"output":"extend"}
        method = 'action.get'
        return cls.get_json_obj(method, params)['result']

    @classmethod
    def get_all(cls, params, method):
        return cls.get_json_obj(method, params)['result']


