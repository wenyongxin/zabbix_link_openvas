用途：
openvas与zabbix结合自动化漏洞扫描工具。
真正实现无人值守，告别减少人为的错误与复查的工作。



用法：
开始扫描
```bash
python openvas_scan_new.py start
```

自动提交任务
```bash
root@ubuntu:~/openvas_scripts# crontab -l
*/5 * * * * python /root/openvas_scripts/openvas_scan_new.py >> /tmp/openvas_pkl/efun_openvas_progress.log
```

生成报告
```bash
python openvas_scan_new.py report
```

生成excel
```bash
python openvas_scan_new.py excel
```


删除历史记录
```bash
python openvas_scan_new.py delete
```
