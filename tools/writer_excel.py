#!/usr/bin/env python
#ecoding:utf-8


import xlsxwriter


workerbook,worksheet = "",""


class efun_writer_excel():

    def __init__(self, filename):
        self.filename = filename

    #创建文件
    def mkdir_file(self):
        global workerbook
        workerbook = xlsxwriter.Workbook(self.filename)


    #创建工作表
    def mkdir_worksheet(self, name):
        global worksheet
        worksheet = workerbook.add_worksheet(name)

    #标题样式
    def title_style(self):
        format = workerbook.add_format()
        #背景颜色
        format.set_bg_color("#dddddd")
        #文字加粗
        format.set_bold(True)
        #左右居中
        format.set_align("center")
        #上下居中
        format.set_align('vcenter')
        #填充外框线
        format.set_border(1)
        return format

    #文本内容的格式化
    def text(self):
        format = workerbook.add_format()
        format.set_border(1)
        #文本超出范围自动换行
        format.set_text_wrap()
        format.set_align("center")
        format.set_align('vcenter')
        return format


    #写入标题
    def writer_title(self, title):
        worksheet.write_row("A1", title, self.title_style())


    #写入文件内容
    def writer_info(self, datas):
        for n,data in enumerate(datas):
            worksheet.write_row("A%s" %(n+2), data, self.text())


    #设置宽度
    def change_width(self, list, excel_range=None):
        for n,column in enumerate(list):
            if excel_range:
                worksheet.set_column(0, excel_range, column)
            else:
                worksheet.set_column(n, n, column)


    #关闭excel
    def close_file(self):
        workerbook.close()
