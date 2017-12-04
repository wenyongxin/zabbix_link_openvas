##开始扫描
```bash
python openvas_scan_new.py start
```

##自动提交任务
```bash
root@ubuntu:~/openvas_scripts# crontab -l
*/5 * * * * python /root/openvas_scripts/openvas_scan_new.py >> /tmp/openvas_pkl/efun_openvas_progress.log
```


##生成报告
```bash
python openvas_scan_new.py report
```
![](/uploads/201712/attach_14fd1635b2f47bd6.png)


##生成excel
```bash
python openvas_scan_new.py excel
```
生成在当前执行脚本的目录

![](/uploads/201712/attach_14fd1a0e0d9e4e5e.png)



##删除历史记录
```bash
python openvas_scan_new.py delete
```
![](/uploads/201712/attach_14fd19017a93d013.png)

####openvas队列信息
![](/uploads/201712/attach_14fd1906221977bb.png)
####报告存放目录信息
![](/uploads/201712/attach_14fd1908265e40ec.png)
