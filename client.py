import tkinter.filedialog
import tkinter.messagebox
import tkinter as tk
import threading
import hashlib
import socket
import pprint
import time
import sys
import os
import ssl

import utils

class Login_win:                   ####  界面初始化

    def show(self):
        self.win.mainloop()
        

    def destroy(self):
        self.win.destroy()
        

    def __init__(self):
        self.win = tk.Tk()              #创建窗口
        self.user = tk.StringVar()
        self.pwd = tk.StringVar()

        self.win.geometry("320x240")
        self.win.title("登录")
        self.win.resizable(width=False, height=False)

        self.label1 = tk.Label(self.win)
        self.label1.place(relx=0.055, rely=0.1, height=31, width=89)
        self.label1.configure(text='账号')

        self.entry_user = tk.Entry(self.win)
        self.entry_user.place(relx=0.28, rely=0.11, height=26, relwidth=0.554)
        self.entry_user.configure(textvariable=self.user)

        self.label2 = tk.Label(self.win)
        self.label2.place(relx=0.055, rely=0.27, height=31, width=89)
        self.label2.configure(text='密码')

        self.entry_pwd = tk.Entry(self.win)
        self.entry_pwd.place(relx=0.28, rely=0.28, height=26, relwidth=0.554)
        self.entry_pwd.configure(show="*")
        self.entry_pwd.configure(textvariable=self.pwd)

        self.btn_login = tk.Button(self.win)
        self.btn_login.place(relx=0.13, rely=0.6, height=32, width=88)
        self.btn_login.configure(text='登录')

        self.btn_reg = tk.Button(self.win)
        self.btn_reg.place(relx=0.6, rely=0.6, height=32, width=88)
        self.btn_reg.configure(text='注册')



class Main_win:             ######聊天室界面初始化
    closed_fun = None

    def show(self):
        self.win.mainloop()


    def destroy(self):
        try:
            self.closed_fun()
        except:
            pass
        self.win.destroy()


    def __init__(self):
        self.win = tk.Tk()
        self.win.protocol('WM_DELETE_WINDOW', self.destroy)   #protocol就是一个创建销毁窗口的方法
        self.win.geometry("480x320")
        self.win.title("聊天室")
        self.win.resizable(width=False,height=False)

        self.msg = tk.StringVar()
        self.name = tk.StringVar()

        self.user_list = tk.Listbox(self.win)
        self.user_list.place(relx=0.75, rely=0.15, relheight=0.72, relwidth=0.23)

        self.label1 = tk.Label(self.win)
        self.label1.place(relx=0.76, rely=0.075, height=21, width=101)
        self.label1.configure(text='在线用户列表')

        self.history = tk.Text(self.win)
        self.history.place(relx=0.02, rely=0.24, relheight=0.63, relwidth=0.696)
        self.history.configure(state='disabled')

        self.entry_msg = tk.Entry(self.win)
        self.entry_msg.place(relx=0.02, rely=0.9, height=24, relwidth=0.59)
        self.entry_msg.configure(textvariable=self.msg)

        self.btn_send = tk.Button(self.win)
        self.btn_send.place(relx=0.62, rely=0.89, height=28, width=45)
        self.btn_send.configure(text='发送')

        self.btn_file = tk.Button(self.win)
        self.btn_file.place(relx=0.752, rely=0.89, height=28, width=108)
        self.btn_file.configure(text='发送文件')
        self.btn_file.configure(state='disabled')

        self.label2 = tk.Label(self.win)
        self.label2.place(relx=0.24, rely=0.0, height=57, width=140)
        self.label2.configure(textvariable=self.name)


login_win = None
main_win = None
my_socket = None
user_name = ''
current_session = ''
users = {}


server_ip = "127.0.0.1"
server_port = "8888"


def close_socket():
    utils.send(my_socket, {'cmd': 'close'})
    my_socket.shutdown(2)
    my_socket.close()


def on_btn_login_clicked():
    
    global my_socket, user_name, login_win, main_win
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        ########################获取socket对象##############################################3
    my_socket.settimeout(5)                                              #最大等待时间
    if login_win.user.get() != '' and login_win.pwd != '':               #登录用户名密码不为空
        my_socket.connect((server_ip, int(server_port)))                 #进行连接
        utils.send(my_socket, {'cmd': 'login', 'user': login_win.user.get(), 
                               'pwd': hashlib.sha1(login_win.pwd.get().encode('utf-8')).hexdigest()})   #发送用户名和密码 同时进行hash加密
        server_response = utils.recv(my_socket)                          #接收服务端的信息
        if server_response['response'] == 'ok':
            user_name = login_win.user.get()                             #用户名
            login_win.destroy()                                          #关闭登录界面
            main_win = Main_win()                                        #打开聊天室界面
            main_win.closed_fun = on_closed
            main_win.name.set('Hi!\n%s' % user_name)                     
            main_win.btn_send.configure(command=on_btn_send_clicked)     #信息发送
            main_win.user_list.bind('<<ListboxSelect>>', on_session_select)
            utils.send(my_socket, {'cmd': 'get_users'})
            utils.send(my_socket, {'cmd': 'get_history', 'peer': ''})
            t = threading.Thread(target=recv_async, args=())              #同时开启多个线程
            t.setDaemon(True)
            t.start()
            main_win.show()
        elif server_response['response'] == 'fail':
            tkinter.messagebox.showerror('警告', '登录失败：' + server_response['reason'])
            close_socket()
    else:
        tkinter.messagebox.showerror('警告', '账号和密码不能为空！')


def on_btn_reg_clicked():                        ###注册按钮###
    global my_socket, login_win
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.settimeout(5)
    if login_win.user.get() != '' and login_win.pwd.get() != '':
        my_socket.connect((server_ip, int(server_port)))
        utils.send(my_socket, {'cmd': 'register', 'user': login_win.user.get(), 'pwd': hashlib.sha1(login_win.pwd.get().encode('utf-8')).hexdigest()})
        server_response = utils.recv(my_socket)
        if server_response['response'] == 'ok':
            tkinter.messagebox.showinfo('注意', '注册成功！')
        elif server_response['response'] == 'fail':
            tkinter.messagebox.showerror('警告', '注册失败：' + server_response['reason'])
    else:
        tkinter.messagebox.showerror('警告', '账号和密码不能为空！')
    close_socket()


def recv_async():
    global my_socket, users, main_win, current_session, file_transfer_pending, filename_short, filename
    while True:
        data = utils.recv(my_socket)
        if data['type'] == 'get_users':
            users = {}
            for user in [''] + data['data']:
                users[user] = False
            refresh_user_list()
        elif data['type'] == 'get_history':
            if data['peer'] == current_session:
                main_win.history['state'] = 'normal'
                main_win.history.delete('1.0', 'end')
                main_win.history['state'] = 'disabled'
                for entry in data['data']:
                    append_history(entry[0], entry[1], entry[2])
        elif data['type'] == 'peer_joined':
            users[data['peer']] = False
            refresh_user_list()
        
        elif data['type'] == 'peer_left':
            if data['peer'] in users.keys():
                del users[data['peer']]
            if data['peer'] == current_session:
                current_session = ''
                main_win.btn_file.configure(state='disabled')
                main_win.name.set('%s -> global' % user_name)
                users[''] = False
                utils.send(my_socket, {'cmd': 'get_history', 'peer': ''})
            refresh_user_list()

        elif data['type'] == 'msg':
            if data['peer'] == current_session:
                append_history(data['peer'], time.strftime('%m月%d日%H:%M', time.localtime(time.time())), data['msg'])
            else:
                users[data['peer']] = True
                refresh_user_list()

        elif data['type'] == 'broadcast':       #公共聊天
            if current_session == '':
                append_history(data['peer'], time.strftime('%m月%d日%H:%M', time.localtime(time.time())), data['msg'])
            else:
                users[''] = True
                refresh_user_list()

def refresh_user_list():
    main_win.user_list.delete(0, 'end')
    for user in users.keys():
        name = '世界聊天室' if user == '' else user
        if users[user]:
            name += ' (*)'
        main_win.user_list.insert('end', name)


def append_history(sender, time, msg):
    main_win.history['state'] = 'normal'
    main_win.history.insert('end', '%s - %s\n' % (sender, time))
    main_win.history.insert('end', msg + '\n\n', 'text')
    main_win.history.see('end')
    main_win.history['state'] = 'disabled'


def on_btn_send_clicked():            #发送信息按钮实现
    global my_socket, user_name, current_session, main_win
    if main_win.msg.get() != '':
        utils.send(my_socket, {'cmd': 'chat', 'peer': current_session, 'msg': main_win.msg.get()})
        append_history(user_name, time.strftime('%m月%d日%H:%M', time.localtime(time.time())), main_win.msg.get())
        main_win.msg.set('')
    else:
        tkinter.messagebox.showinfo('警告', '消息不能为空！')


def on_session_select(event):
    global current_session, main_win, user_name, users, file_transfer_pending
    w = event.widget
    changed = False
    if len(w.curselection()) != 0:
        index = int(w.curselection()[0])
        if index != 0:
            if current_session != w.get(index).rstrip(' (*)'):
                changed = True
                current_session = w.get(index).rstrip(' (*)')
                if not file_transfer_pending:
                    main_win.btn_file.configure(state='normal')
                main_win.name.set('%s -> %s' % (user_name, current_session))
                users[current_session] = False
                refresh_user_list()
        elif index == 0:
            if current_session != '':
                changed = True
                current_session = ''
                main_win.btn_file.configure(state='disabled')
                main_win.name.set('%s -> global' % user_name)
                users[''] = False
                refresh_user_list()
        if changed:
            utils.send(my_socket, {'cmd': 'get_history', 'peer': current_session})


def on_closed():
    close_socket()


def get_file_md5(file_path):
    md5obj = hashlib.md5()
    maxbuf = 8192
    f = open(file_path, 'rb')
    while True:
        buf = f.read(maxbuf)
        if not buf:
            break
        md5obj.update(buf)
    f.close()
    hash = md5obj.hexdigest()
    return str(hash).upper()


if __name__ == '__main__':
 
    login_win = Login_win()
    login_win.btn_login.configure(command=on_btn_login_clicked)
    login_win.btn_reg.configure(command=on_btn_reg_clicked)
    login_win.show()
