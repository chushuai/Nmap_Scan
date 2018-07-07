# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from pymongo import MongoClient
from werkzeug.utils import secure_filename
import re
import subprocess
import os


def fuzzer_search(fuzzer_input):
    fuzzer_ip_list = ['product', 'ip', 'extrainfo',
                      'port',  'name', 'cpe', 'version', 'time_man']
    out_list = []
    for fuzzer_data in fuzzer_ip_list:
        rexExp = re.compile('.*' + fuzzer_input + '.*', re.IGNORECASE)
        res = mon.toybox.ip_list.find({fuzzer_data: rexExp})

        for rs in res:
            if rs not in out_list:
                out_list.append(rs)

    fuzzer_nse_list = ['vuln.ms17-010.hack']

    for fuzzer_data in fuzzer_nse_list:
        rexExp = re.compile('.*' + fuzzer_input + '.*', re.IGNORECASE)
        res = mon.toybox.nse_list.find({fuzzer_data: rexExp})

        for rs in res:
            if rs not in out_list:
                out_list.append(rs)

    return out_list


app = Flask(__name__)
mon = MongoClient('mongodb://' + 'root' + ':' + 'example' + '@127.0.0.1')


@app.route("/add_task", methods=['GET', 'POST'])
def scan():
    # alpine mode
    # command = [
    #    'python2.7', '/scan_code/muti_nmap_mongo.py']

    # debug mode
    command = [
        'python2.7', '/home/playerke/Nmap_Scan/scan_code/muti_nmap_mongo.py']
    if request.method == 'POST':
        search_host = request.form.get('search_host')
        search_port = request.form.get('search_port')
        search_threads = request.form.get('search_threads')

        scan_mode_list = request.form.get('scan_mode_list')
        ping_list = request.form.get('ping_list')
        speed_list = request.form.get('speed_list')
        other_listf = request.form.get('other_list-f')
        other_list6 = request.form.get('other_list-6')
    if search_host != '':
        command.append('-i')
        command.append(search_host)
    if search_port != '':
        command.append('-p')
        command.append(search_port)
    if search_threads != '':
        command.append('-t')
        command.append(search_threads)
    if search_host != '':
        command.append('-a')
        temp2 = [scan_mode_list, ping_list,
                 speed_list, other_listf, other_list6]
        temp = ''
        for x in temp2:
            if x != None:
                temp += x+' '
        # temp = "\'" + temp + "\'"
        command.append(temp)
    show_text = ''
    for x in command:
        show_text += x + ' '
    try:
        process = subprocess.Popen(command, stderr=subprocess.PIPE)
    except:
        show_text = 'Error in subprocess'
    return render_template('add_scan.html', command=command, show_text=show_text)


@app.route("/scan", methods=['GET', 'POST'])
def single_scan():
    scan_mode_list = [
        {
            'id': '1',
            'arg': '-sT',
            'name': 'TCP Connect Scan',
            'text': u'利用TCP協定，建立完整的3向交握連線後在進行掃描，雖然準確率比較高，但易留下紀錄。'
        },
        {
            'id': '2',
            'arg': '-sS',
            'name': 'SYN Stealth Scan',
            'text': u'半開放掃描，若對方有開啟TCP端口就會回應封包，不會留下紀錄。'
        },
        {
            'id': '3',
            'arg': '-sA',
            'name': 'ACK Scan ',
            'text': u'探測目標是否有防火牆阻擋。'
        },
        {
            'id': '4',
            'arg': '-sM',
            'name': 'Mainmon Scan',
            'text': u'判斷那些端口是開啟狀態。'
        },
        {
            'id': '5',
            'arg': '-sF',
            'name': 'FIN Scan',
            'text': u'正常連線型態，隱密性較高。'
        },
        {
            'id': '6',
            'arg': '-sN',
            'name': 'NULL Scan',
            'text': u'類似-sF，但對Windows無作用。'
        },
        {
            'id': '7',
            'arg': '-sX',
            'name': 'XMas Tree Scan',
            'text': u'利用送出三個控制封包探測目標主機，對Windows無作用。'
        },
        {
            'id': '8',
            'arg': '-sU',
            'name': 'UDP Scan',
            'text': u'探測目標是否提供UDP服務。'
        },
        {
            'id': '9',
            'arg': '-sO',
            'name': 'IP Protocol Scan',
            'text': u'偵測目標系統哪些IP協定。'
        },
        {
            'id': '10',
            'arg': '-sP',
            'name': 'Ping Sweep',
            'text': u'單純Ping掃描。'
        }

    ]
    ping_list = [
        {
            'id': '1',
            'arg': '-P0',
            'name': 'Don\'t Ping',
            'text': u'執行掃描前，不目標主機。'
        },
        {
            'id': '2',
            'arg': '-PI',
            'name': 'ICMP Echo',
            'text': u'查詢目標是否正在運行。'
        },
        {
            'id': '3',
            'arg': '-PE',
            'name': 'Use ICMP Ping Host',
            'text': u'利用ICMP封包Ping目標。'
        },
        {
            'id': '4',
            'arg': '-PR',
            'name': 'ARP Ping',
            'text': u'只能使用同區段的區域網路。'
        },
        {
            'id': '5',
            'arg': '-PS',
            'name': 'TCP SYN Ping',
            'text': u'發出TCP SYN封包，需指定端口，預設端口80。'
        },
        {
            'id': '6',
            'arg': '-PA',
            'name': 'TCP ACK Ping',
            'text': u'發出TCP ACK封包，需指定端口，預設端口80。'
        },
        {
            'id': '7',
            'arg': '-PU',
            'name': 'UDP Ping',
            'text': u'發出空的UDP封包，需指定端口，預設端口31338。'
        }
    ]
    speed_list = [
        {
            'id': '1',
            'arg': '-T0',
            'name': 'Paranoid',
            'text': u'每五秒鐘發送一個封包。'
        },
        {
            'id': '2',
            'arg': '-T1',
            'name': 'Sneaky',
            'text': u'每十五秒鐘發送一個封包。'
        },
        {
            'id': '3',
            'arg': '-T2',
            'name': 'Polite',
            'text': u'每0.4秒鐘發送一個封包。'
        },
        {
            'id': '4',
            'arg': '-T3',
            'name': 'Normal',
            'text': u'預設及不指定速度的掃描。'
        },
        {
            'id': '5',
            'arg': '-T4',
            'name': 'Aggressive',
            'text': u'每十毫秒鐘發送一個封包。'
        },
        {
            'id': '6',
            'arg': '-T5',
            'name': 'Insane',
            'text': u'每五毫秒鐘發送一個封包。'
        }
    ]
    other_list = [
        {
            'id': '1',
            'arg': '-f',
            'name': 'Fragmentation',
            'text': u'發送碎片封包，資料長度為8byte，增加封包過濾器、防火牆與IDS的檢查難度。'
        },
        {
            'id': '2',
            'arg': '-6',
            'name': 'IPv6',
            'text': u'支援掃描IPv6TAT。'
        },
    ]
    task_list = mon.toybox.task_list.find()
    return render_template('single_scan.html', scan_mode_list=scan_mode_list, ping_list=ping_list, speed_list=speed_list, other_list=other_list, task_list=task_list)


@app.route("/add_tasklist", methods=['GET', 'POST'])
def mutiscan():
    # alpine mode
    # command = [
    #    'python2.7', '/scan_code/muti_nmap_mongo.py']

    # debug mode
    command = [
        'python2.7', '/home/playerke/Nmap_Scan/scan_code/muti_nmap_mongo.py']
    if request.method == 'POST':
        test =  request.form.get('test')     
        search_port = request.form.get('search_port')
        search_threads = request.form.get('search_threads')

        scan_mode_list = request.form.get('scan_mode_list')
        ping_list = request.form.get('ping_list')
        speed_list = request.form.get('speed_list')
        other_listf = request.form.get('other_list-f')
        other_list6 = request.form.get('other_list-6')

    iph = '/home/playerke/Nmap_Scan/upload_list/' + test
    command.append('-l')
    command.append(iph)
    if search_port != '':
        command.append('-p')
        command.append(search_port)
    if search_threads != '':
        command.append('-t')
        command.append(search_threads)

    command.append('-a')
    temp2 = [scan_mode_list, ping_list,
             speed_list, other_listf, other_list6]
    temp = ''
    for x in temp2:
        if x != None:
            temp += x+' '
        # temp = "\'" + temp + "\'"
    command.append(temp)
    show_text = ''
    for x in command:
        show_text += x + ' '
    try:
        process = subprocess.Popen(command, stderr=subprocess.PIPE)
    except:
        show_text = 'Error in subprocess'
    return render_template('add_scanlist.html', command=command, show_text=show_text)


UPLOAD_FOLDER = 'upload_list'
ALLOWED_EXTENSIONS = set(['txt'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route("/mutiscan", methods=['GET', 'POST'])
def muti_scan(): 
    test = ''      
    if request.method == 'POST':
        file = request.files['input_list']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            test = filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    
    scan_mode_list = [
        {
            'id': '1',
            'arg': '-sT',
            'name': 'TCP Connect Scan',
            'text': u'利用TCP協定，建立完整的3向交握連線後在進行掃描，雖然準確率比較高，但易留下紀錄。'
        },
        {
            'id': '2',
            'arg': '-sS',
            'name': 'SYN Stealth Scan',
            'text': u'半開放掃描，若對方有開啟TCP端口就會回應封包，不會留下紀錄。'
        },
        {
            'id': '3',
            'arg': '-sA',
            'name': 'ACK Scan ',
            'text': u'探測目標是否有防火牆阻擋。'
        },
        {
            'id': '4',
            'arg': '-sM',
            'name': 'Mainmon Scan',
            'text': u'判斷那些端口是開啟狀態。'
        },
        {
            'id': '5',
            'arg': '-sF',
            'name': 'FIN Scan',
            'text': u'正常連線型態，隱密性較高。'
        },
        {
            'id': '6',
            'arg': '-sN',
            'name': 'NULL Scan',
            'text': u'類似-sF，但對Windows無作用。'
        },
        {
            'id': '7',
            'arg': '-sX',
            'name': 'XMas Tree Scan',
            'text': u'利用送出三個控制封包探測目標主機，對Windows無作用。'
        },
        {
            'id': '8',
            'arg': '-sU',
            'name': 'UDP Scan',
            'text': u'探測目標是否提供UDP服務。'
        },
        {
            'id': '9',
            'arg': '-sO',
            'name': 'IP Protocol Scan',
            'text': u'偵測目標系統哪些IP協定。'
        },
        {
            'id': '10',
            'arg': '-sP',
            'name': 'Ping Sweep',
            'text': u'單純Ping掃描。'
        }

    ]
    ping_list = [
        {
            'id': '1',
            'arg': '-P0',
            'name': 'Don\'t Ping',
            'text': u'執行掃描前，不目標主機。'
        },
        {
            'id': '2',
            'arg': '-PI',
            'name': 'ICMP Echo',
            'text': u'查詢目標是否正在運行。'
        },
        {
            'id': '3',
            'arg': '-PE',
            'name': 'Use ICMP Ping Host',
            'text': u'利用ICMP封包Ping目標。'
        },
        {
            'id': '4',
            'arg': '-PR',
            'name': 'ARP Ping',
            'text': u'只能使用同區段的區域網路。'
        },
        {
            'id': '5',
            'arg': '-PS',
            'name': 'TCP SYN Ping',
            'text': u'發出TCP SYN封包，需指定端口，預設端口80。'
        },
        {
            'id': '6',
            'arg': '-PA',
            'name': 'TCP ACK Ping',
            'text': u'發出TCP ACK封包，需指定端口，預設端口80。'
        },
        {
            'id': '7',
            'arg': '-PU',
            'name': 'UDP Ping',
            'text': u'發出空的UDP封包，需指定端口，預設端口31338。'
        }
    ]
    speed_list = [
        {
            'id': '1',
            'arg': '-T0',
            'name': 'Paranoid',
            'text': u'每五秒鐘發送一個封包。'
        },
        {
            'id': '2',
            'arg': '-T1',
            'name': 'Sneaky',
            'text': u'每十五秒鐘發送一個封包。'
        },
        {
            'id': '3',
            'arg': '-T2',
            'name': 'Polite',
            'text': u'每0.4秒鐘發送一個封包。'
        },
        {
            'id': '4',
            'arg': '-T3',
            'name': 'Normal',
            'text': u'預設及不指定速度的掃描。'
        },
        {
            'id': '5',
            'arg': '-T4',
            'name': 'Aggressive',
            'text': u'每十毫秒鐘發送一個封包。'
        },
        {
            'id': '6',
            'arg': '-T5',
            'name': 'Insane',
            'text': u'每五毫秒鐘發送一個封包。'
        }
    ]
    other_list = [
        {
            'id': '1',
            'arg': '-f',
            'name': 'Fragmentation',
            'text': u'發送碎片封包，資料長度為8byte，增加封包過濾器、防火牆與IDS的檢查難度。'
        },
        {
            'id': '2',
            'arg': '-6',
            'name': 'IPv6',
            'text': u'支援掃描IPv6TAT。'
        },
    ]
    task_list = mon.toybox.task_list.find()
    return render_template('muti_scan.html', test=test, scan_mode_list=scan_mode_list, ping_list=ping_list, speed_list=speed_list, other_list=other_list, task_list=task_list)


@app.route("/overview", methods=['GET', 'POST'])
def overview():
    scan_list = {}
    target_list = []
    nse_list = {}
    search_filter = ''
    if request.method == 'POST':
        search_filter = request.form['search_filter']
    # ip form
    for x in fuzzer_search(search_filter):
        try:
            if x['ip'] not in target_list:
                target_list.append(x['ip'])
                scan_list.update({x['ip']: {}})
                nse_list.update({x['ip']: {}})
        except KeyError:
            if x['_id'] not in target_list:
                target_list.append(x['_id'])
                scan_list.update({x['_id']: {}})
                nse_list.update({x['_id']: {}})

    # port form
    for x in target_list:
        for y in mon.toybox.ip_list.find({'ip': x}):
            scan_list[x].update(
                {y['port']: y, 'time_man': y['time_man'], 'time_pc': y['time_pc']})

    # nse form
    for x in target_list:
        for y in mon.toybox.nse_list.find({'_id': x}):
            nse_list[x].update(y)

    return render_template('list.html', nse_list=nse_list, target_list=target_list, scan_list=scan_list, search_filter=search_filter)


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5200, debug=True)
