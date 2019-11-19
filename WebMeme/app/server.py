from flask import Flask, request
from flask import render_template
from binascii import hexlify
from socket import inet_aton, socket, AF_INET, SOCK_STREAM
import ctypes
import json

import struct
import sys
app = Flask(__name__)
ip_blacklist = [{'data': '192.168.1.1', 'text': '测试路由器地址(此规则不会生效)'}]
data_blacklist = [{'data': '?? ?? ?? ??', 'text': '拦截全部流量(此规则不会生效)'}]

HOST = 'localhost'
PORT = 5099
BUFSIZ = 255
ADDR = (HOST, PORT)


def push_backlist_data(data, data_len, block_ip, push_type):
    if push_type == 1:
        data = "huoji"
        data_len = len(data)
    c = socket(AF_INET, SOCK_STREAM)
    c.connect(ADDR)
    packet = struct.pack("IL255s",
                         data_len,
                         int(block_ip),
                         data.encode('gbk'),
                         )
    c.send(packet)
    c.close()


def Ip2Int(ipaddr):
    int_ip = struct.unpack('!I', inet_aton(ipaddr))[0]
    print('IP:' + str(int_ip))
    return int_ip


@app.route('/')
def index():
    context = ip_blacklist
    context_type = {
        'table_type1': "IP地址",
        'table_type2': "备注"
    }
    return render_template('index.html', main=context, type=context_type)


@app.route('/api', methods=["POST", "GET"])
def api():
    if request.method == 'POST':
        data = request.form.get("data")
        page = request.form.get("page")
        push = request.form.get("push")
        push_data = request.form.get("push_data")
        if data:
            # push_backlist_data(data, len(data))
            return json.dumps({"status": "success"})
        if page:
            json_return = {"status": "Error"}
            if int(page) == 1:
                json_return = {
                    "status": "success",
                    "page": "ip_list",
                    "table_1": "IP地址",
                    "table_2": "备注",
                    "data": ip_blacklist
                }
            if int(page) == 2:
                json_return = {
                    "status": "success",
                    "page": "data_list",
                    "table_1": "特征码",
                    "table_2": "备注",
                    "data": data_blacklist
                }
            return json.dumps(json_return)
        if push and push_data:
            json_return = {"status": "Error"}
            processdata = push_data.split("@")
            if int(push) == 1:
                ip_blacklist.append({
                    "data": processdata[0],
                    "text": processdata[1]
                })
            else:
                data_blacklist.append({
                    "data": processdata[0],
                    "text": processdata[1]
                })
            blockip = 0
            if int(push) == 1:
                blockip = Ip2Int(processdata[0])
            print("type " + push + " blockip: " + str(blockip))
            push_backlist_data(
                processdata[0],
                len(processdata[0]),
                blockip,
                int(push)
            )
            return json.dumps(json_return)
    return "API"


if __name__ == '__main__':
    app.run(debug=True)
