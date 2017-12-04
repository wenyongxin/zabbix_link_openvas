#!/usr/bin/env python
#ecoding:utf-8

#用途：zabbix与openvas结合。自动化扫描以及自动化生成excel报告,可实现全程无人值守
#编写人：温永鑫
#职位: 运维监控&运维开发主管
#编写日期：2017-12-4


from openvas_lib import *
from tools.zabbix import zabbix_function
import re, os, pickle, urllib, urllib2, json, time, Queue, sys
from xml.etree import ElementTree
from tools.writer_excel import efun_writer_excel


save_openvas_report_dir = r"/root/openvas_scripts"
title = ["名称", "漏洞评分", "描述(英)", "描述(中)", "解决方案(英)", "解决方案(中)", "总结(英)", "总结(中)" ]
now_day = time.strftime('%Y-%m-%d', time.localtime(time.time()))

#存放总数据文件地址
tmp_path = r"/tmp/openvas_pkl"

#保存所有切片ip的临时文件名称
cut_ip_file = os.path.join(tmp_path, "cut_ip_file.pkl")
#保存所有ip与reportid的对应关系表
ip_report_dicts = os.path.join(tmp_path, "ip_report_dicts.pkl")

cut_num = 8
q = Queue.Queue()

class efun_get_infos(zabbix_function):

    @classmethod
    def get_host_ips(cls):
        this_hosts = []
        params = {"output":["hostid","name"], "selectInterfaces":["ip","useip"], "filter":{"useip":1}, "selectMacros":"extend"}
        for i in cls.get_host(params):
            to_str = json.dumps(i)
            if "{$OPENVAS}" not in to_str:
                this_hosts.append(json.loads(to_str))
        return this_hosts

    @classmethod
    def ip_find_name(cls, ip):
        params = {"output":"extend", "filter":{"ip":ip}, "selectHosts":["hostid","name"]}
        method = "hostinterface.get"
        return cls.get_all(params, method)[0]['hosts'][0]['name']

    #获取带测试标识的用户名字
    @classmethod
    def get_test_users(cls):
        users = []
        params = {"output":"extend", "search":{"alias":u"测试"}}
        method = "user.get"
        for i in cls.get_all(params, method):
            users.append(i['alias'])
        return users


#重构zabbix新的用户连接实例
class efun_connect_zabbix(zabbix_function):

    new_zabbix_users = ""
    new_zabbix_password = "VoeHy5bq0{xs"

    #新的用户登录实例化
    @classmethod
    def new_login(cls):
        return cls.login(username=cls.new_zabbix_users, password=cls.new_zabbix_password)

    #新的角色获取数据方式
    @classmethod
    def new_get_json_obj(cls, method, params):
        get_obj = {"jsonrpc":"2.0","method":method,"params":params,"auth":cls.new_login(),"id":1}
        return cls.postRequest(json.dumps(get_obj))

    #返回当前用户中主机列表信息
    @classmethod
    def return_this_hosts(cls):
        params = {"output":["hostid","name"], "selectInterfaces":["ip","useip"], "filter":{"useip":1}}
        method = "host.get"
        return cls.new_get_json_obj(method, params)['result']




#转换工具
class efun_tools():

    #正则匹配内网IP地址并进行反选
    @classmethod
    def filter_outside_ip(cls, result):
        try:
            this_ip = result['interfaces'][0]['ip']
        except:
            this_ip = result['interfaces'][1]['ip']

        if not re.match(r'10\.\d+\.\d+\.\d+', this_ip) and "J_交换" not in result['name'] and u"Q_七龙珠" not in result['name'] and u"G_高达" not in result['name'] and "ESXI" not in result['name']:
            return this_ip.encode('utf-8')
        else:
            return False

    #正则匹配ip地址
    @classmethod
    def find_ip(cls, string):
        return re.findall(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])', string)[0]

    #切割IP的份数
    @classmethod
    def cut_ip_list(cls, ip_list):
        if ip_list:
            return [ip_list[i:i + cut_num] for i in range(0, len(ip_list), cut_num)]


    #保存pickle文件
    @classmethod
    def save_pickle(cls, filename, data):
        with open(filename, 'wb') as f:
            pickle.dump(data,f)

    #读取pickle文件
    @classmethod
    def read_pickle(cls, filename):
        with open(filename,'r+') as f:
            data = pickle.load(f)
            return data

    #解析文件名字获取reportid
    @classmethod
    def get_reportid(cls,filename):
        return '-'.join(filename.strip('.xml').split('-')[1:])


    #保存openvas的扫描报告 xml格式
    @classmethod
    def writer_xml(cls, report, name):
        filename = os.path.join(save_openvas_report_dir,'report', "%s.xml" %name)


    #有道翻译api
    @classmethod
    def to_chinese(cls, english):
        try:
            if english:
                url = 'http://fanyi.youdao.com/openapi.do?keyfrom=imyours1991&key=708486460&type=data&doctype=json&version=1.1'
                res = json.loads(urllib2.urlopen(url, urllib.urlencode({'q': english})).read())
                if res['errorCode'] == 0:
                    return res['translation'][0]
                else:
                    return False
            else:
                return False
        except:
            return False


    #判断翻译是否成功。如果不成功则等待30秒重新翻译
    @classmethod
    def is_translate_ok(cls, english):
        while True:
            result = cls.to_chinese(english)
            if result and errors != 5:
                return result
            else:
                errors = errors + 1
                print u"等待重试....."
                time.sleep(30)



#定义openva扫描
class efun_openvas():

    __host = "58.229.184.19"
    __user = "admin"
    __password = "admin"
    __port = 9390
    __timeout = 300

    #openavs的连接
    @classmethod
    def conn_openvas(cls):
        return VulnscanManager(cls.__host, cls.__user, cls.__password, cls.__port, cls.__timeout)

    #提交扫描任务
    @classmethod
    def send_scan_object(cls, ip):
        scan_id, target_id = cls.conn_openvas().launch_scan(target = ip, profile = "Full and very deep")
        if scan_id and target_id:
            print "%s 提交ok" %ip
            return scan_id,target_id

    #调用openvas中说有任务
    @classmethod
    def get_all_task(cls):
        return cls.conn_openvas().get_all_scans

    #通过scan_id获取其进度
    @classmethod
    def get_this_progress(cls, scan_id):
        return cls.conn_openvas().get_progress(scan_id)

    #保存扫描报告
    @classmethod
    def get_report(cls, name, scanid):
        report_id = cls.conn_openvas().get_report_id(scanid)
        report = cls.conn_openvas().get_report_xml(report_id)
        this_ip = efun_tools.find_ip(name)
        filename = os.path.join(save_openvas_report_dir,'report', "%s.xml" %this_ip)
        fout = open(filename, "wb")
        fout.write(ElementTree.tostring(report.find("report"), encoding='utf-8', method='xml'))
        fout.close()
        return this_ip

    #删除任务
    @classmethod
    def del_scan_job(cls, scanid):
        try:
            cls.conn_openvas().delete_scan(scanid)
            return True
        except:
            return False


    #生成所有的xml格式的报告
    @classmethod
    def get_all_report_xml(cls):
        for name,scanid in cls.get_all_task().items():
            info = cls.get_report(name, scanid)
            print "%s is ok" %info


    #删除所有的队列
    @classmethod
    def delete_all(cls):
        for name,scanid in cls.get_all_task().items():
            cls.del_scan_job(scanid)
            print u"%s 已经删除" %name


    #读取report中的内容
    @classmethod
    def filter_report_info(cls, report_name):
        try:
            results = report_parser(os.path.join(save_openvas_report_dir, 'report', report_name))
            for x in results:

                if x.threat == "High":
                    name = efun_get_infos.ip_find_name(x.host)
                    score = x.nvt.cvss_base
                    describe = x.nvt.name.replace('\n', '')
                    info = { b.split("=")[0]:b.split("=")[1] for b in x.nvt.tags[0].split('|') }
                    solution = info['solution']
                    summary = info['summary']

                    describe_cn = efun_tools.is_translate_ok(describe)
                    solution_cn = efun_tools.is_translate_ok(solution)
                    summary_cn = efun_tools.is_translate_ok(summary)

                    line_d = [name, score, describe, describe_cn, solution, solution_cn, summary, summary_cn]
                    print line_d
                    q.put(line_d)

            print "%s 生成完毕" %report_name
        except:pass


    #获取当前正在扫描的任务数量
    @classmethod
    def get_running_num(cls):
        try:
            return len(cls.conn_openvas().get_running_scans().keys())
        except:
            return False

all_ip_infos = {}

#通过api方式采集所有的IP地址。并进行列表分割
def First():
    #判断目录是否存在
    if not os.path.exists(tmp_path):
        os.mkdir(tmp_path)
        print u"%s 创建成功" %tmp_path


    all_ips = []
    for i in efun_get_infos.get_host_ips():
        this_ip = efun_tools.filter_outside_ip(i)

        if this_ip:
            all_ip_infos[this_ip] = i['hostid']
            all_ips.append(efun_tools.filter_outside_ip(i))

    efun_tools.save_pickle(ip_report_dicts, {})
    efun_tools.save_pickle(cut_ip_file, efun_tools.cut_ip_list(all_ips))


#读取pickle文件，并读取第0位置的信息
def Second():
    if not os.path.isfile(cut_ip_file):
        First()
        print u"%s 已经生成" % cut_ip_file
    else:
        num = efun_openvas.get_running_num()
        if num and num > 5:
            print u"扫描任务过多:%s 稍等" %num
        else:
            scan_trigger_ip = {}
            data = efun_tools.read_pickle(cut_ip_file)
            if data:
                plan = float(len(efun_tools.read_pickle(ip_report_dicts).keys()))
                print u"完成量: %.2f%%  剩余ip个数: %s" %(float(plan/(plan + float(len(data)) * cut_num) * 100), (len(data) * cut_num))
                for scan_ip in data[-1]:

                    scan_id,target_id = efun_openvas.send_scan_object(scan_ip)
                    scan_trigger_ip.update({scan_ip: {"scanid":scan_id, "gargetid":target_id, "plan":0}})

                data.pop()
                efun_tools.save_pickle(cut_ip_file, data)

                #1 读取内存
                mem_report_info = efun_tools.read_pickle(ip_report_dicts)
                mem_report_info.update(scan_trigger_ip)
                efun_tools.save_pickle(ip_report_dicts, mem_report_info)
                print u"%s 文件更新完毕" %ip_report_dicts
            else:
                print u"所有的ip提交完毕"

#生成excel文件
def efun_report_excel(user, excel):


    writer_data = []
    efun_connect_zabbix.new_zabbix_users = user
    for h in efun_connect_zabbix.return_this_hosts():
        this_ip = efun_tools.filter_outside_ip(h)
        report_name = "%s.xml" %this_ip
        efun_openvas.filter_report_info(report_name)

    while True:
        if q.empty():
            break
        else:
            writer_data.append(q.get())


    excel.mkdir_worksheet(user.split('_')[-1])
    excel.writer_title(title)
    excel.writer_info(writer_data)
    #设置指定宽范围
    excel.change_width([23], len(title))





def main():
    #用于传递参数
    try:
        #开始任务，创建临时的ip列表文件
        if sys.argv[1] == "start":
            First()
        #生成xml格式的report文件
        elif sys.argv[1] == "report":
            efun_openvas.get_all_report_xml()
        #生成excel文件
        elif sys.argv[1] == "excel":
            filename = u"监控组-月度漏洞扫描-%s.xlsx" %now_day
            filepath = os.path.join(save_openvas_report_dir,'report', filename)
            excel = efun_writer_excel(filepath)
            excel.mkdir_file()
            for user in efun_get_infos.get_test_users():
                efun_report_excel(user, excel)
            excel.close_file()
        #删除所有扫描任务
        elif sys.argv[1] == "delete":
            efun_openvas.delete_all()
            for filename in os.listdir(os.path.join(save_openvas_report_dir, 'report')):
                try:
                    os.remove(os.path.join(save_openvas_report_dir, 'report', filename))
                except:pass
                print u"%s 已经删除" %filename

            for config_file in os.listdir(tmp_path):
                os.remove(os.path.join(tmp_path, config_file))
                print u"%s 已经删除" %config_file
                
    #用于任务计划
    except BaseException,e:
        print e
        print u"----------- 开始扫描 ---------------------"
        print "%s" %time.ctime()
        try:
            efun_openvas.conn_openvas()
            Second()
            print u"----------- 扫描结束 ---------------------"
        except BaseException,e:
            print u"------------- openvas 异常稍等 ---------------"



if __name__=="__main__":
    main()
