#!/usr/bin/python3
#-*- coding:utf-8 -*-
import os
import re
import sys
import subprocess
import textwrap
from collections import OrderedDict
ip='^(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){3}'
net='^(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){2}\.0\/(24|16|8)$'
ip_range='^(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){3}-(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])(\.(2[0-4][0-9]|25[0-5]|1[0-9][0-9]|[1-9]?[0-9])){3}$'
interface='enp0s3'
ccd_dir='/media/root/etc/openvpn/ccd'
vpn_netnum='2'
os.chdir(ccd_dir)
iptab_dir='/media/root/tmp'
os.system('iptables -t nat -L -n|grep MASQUERADE > %s/iptables_list' % iptab_dir)
def print_dst(func):
    def deco(args,ip_ex):
        list_ser=OrderedDict()
        opip=open('%s/iptables_list' % iptab_dir)
        ss=opip.readlines()
        opip.close()
        a,r=func(args,ip_ex)
        if args=='show':
            return a,r 
        else:
            for v in a.keys():
                w=a[v].split()
                filen=len(ss)
                for i in range(filen):
                    if re.search('%s '% w[1],ss[i]):
                        iptb=ss[i].strip()
                        i=iptb.split()[3:][0]
                        if v in list_ser.keys():
                            if i in list_ser[v]:
                                pass
                            else:
                                list_ser.setdefault(v,[]).append(i)  
                        else:
                            list_ser.setdefault(v,[]).append(i)  
                        i=iptb.split()[3:][-1]
                        list_ser.setdefault(v,[]).append(i)
            return list_ser
    return deco
@print_dst
def show(args,ip_ex):
    a=OrderedDict()
    r=[]
    sortdir=sorted(os.listdir('.'))
    for f in sortdir:
        fobj=open(f,'r')
        for i in fobj:
            r.append(f)
            if re.match('ifconfig-push 172\.%s\.%s\.\d+ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d+\n' % (ip_ex,vpn_netnum),i):
                a[f]=i
    r.sort(key=lambda x: len(x))
    r=len(r[-1])
    return a,r
def getip(ip_ex,arg2):
    l=[]
    for f in os.listdir('.'):
        fobj=open(f,'r')
        for i in fobj.readlines():
            if re.match('ifconfig-push 172\.%s\.%s\.\d+ \d{1,3}\.\d{1,3}\.\d{1,3}\.\d+\n' % (ip_ex,vpn_netnum),i):
                if ip_ex == int(i.split('.')[-6]):
                    w=re.split(' |\.',i)[1:4]
                    i=re.split(' |\.',i)[4]
                    l.append(int(i))
                    fobj.close()
    llen=len(l)
    if llen == 0:
        t='172.%s.%s.1' % (ip_ex,vpn_netnum)  if arg2=='srcip' else '172.%s.%s.2' % (ip_ex,vpn_netnum)
        return t
    else:
        a=sorted(l)[-1]
        src=int(a)+4
        route=int(a)+5
        t=src if  arg2 =='srcip' else route
        w.append(str(t))
        return '.'.join(w)
def edit_iptab(src_ip,ruleip,interface,mode='A'):
    os.environ['src_ip']=str(src_ip)
    os.environ['ruleip']=str(ruleip)
    os.environ['interface']=str(interface)
    os.environ['mode']=str(mode)
    if re.match(ip_range,ruleip):
        os.system('iptables -t nat  -$mode POSTROUTING -s $src_ip -m iprange --dst-range  $ruleip  -o $interface -j MASQUERADE')
    elif re.match(net,ruleip):
        os.system('iptables -t nat  -$mode POSTROUTING -s $src_ip -d  $ruleip  -o $interface -j MASQUERADE')
    elif re.match(ip,ruleip):
        os.system('iptables -t nat  -$mode POSTROUTING -s $src_ip -d  $ruleip  -o $interface -j MASQUERADE')
    else:
        print ('ip err!')
def getrule(src_ip,interface):
    ruleip=input('enter want add rule : ').split()
    sum=len(ruleip)
    for i in range(sum):
        ruleip=ruleip[i]
        edit_iptab(src_ip,ruleip,interface,'A')
def auto():
    while True:
        adduser=input('enter want add user : ').strip()    
        if re.match('^\w+$',adduser):
            if os.path.exists(adduser):
                print ("%s is exists!" % adduser)
                break
            else:
                ip_ex=int(input('enter is network 17 / 18 /...: '))
                opfl=open(adduser,'w')
                src_ip=getip(ip_ex,'srcip')
                src_iproute=getip(ip_ex,'iproute')
                opfl.write('ifconfig-push %s %s\n' % (src_ip,src_iproute))
                opfl.close()
                getrule(src_ip,interface)
                break
        else:
            print ('user add format err!')
class Nav():
    import textwrap
    @staticmethod
    def print_nav():
        '''
        导航提示类
        '''
        msg = """\n\033[1;32m###    weclome  vpnadd  ### \033[0m
        1) Enter \033[32mP/p\033[0m Display rule
        2) Enter \033[32mS/s\033[0m Search auth
        3) Enter \033[32mA/a\033[0m Auto add
        4) Enter \033[32mD/d\033[0m Delect auth and user
        5) Enter \033[32mI/i\033[0m Add auth for user
        0) Enter \033[32mQ/q\033[0m Exit
                """
        print (textwrap.dedent(msg))
    @staticmethod
    def search_nav():
        msg = """\n\033[1;32m### select   ### \033[0m
        1) for user  
        2) for ip
              """
        print (textwrap.dedent(msg))
    def search(self,ip_ex,mode,user='nouser',se_ip='noip'):
        if ip_ex == 'all':
            ip_ex='.*'
        if user != 'nouser':
            all_d=show(mode,ip_ex)
            if user in all_d.keys():
                print (user,all_d[user])
            else:
                print ('%s not exist !' % user)
        elif se_ip != 'noip':
            global ok_status
            ok_status='init'
            all_d=show(mode,ip_ex)
            for k,v in all_d.items():
                if se_ip in v:
                    ok_status='yes'
                    print (k)        
            if ok_status != 'yes':
                print ('for %s  not found in iptab' % se_ip )
        else:
            a,r=show(mode,ip_ex)
            for e in a.keys():
                c=a[e].split()
                print ('%-*s %-15s %s' % (r+2,e,c[1],c[-1]))
    def del_user(self,user):
        try:
            os.path.exists(user)
            fobj=open(user)
            s=fobj.readlines()
            fobj.close()
            del_ip=re.split(' ',' '.join(s))[1]
            os.remove(user)
            os.environ['del_ip']=str(del_ip)
            del_list=subprocess.getoutput('cat %s/iptables_list|grep $del_ip' % iptab_dir).split('\n')
            lend=len(del_list)
            for i in range(lend):
                del_iptab=del_list[i].split()[-1]
                edit_iptab(del_ip,del_iptab,interface,'D')
        except Exception as e:
           print (Exception,':',e)
    def add_user_iptab(self,user):
        try:
            os.path.exists(user)
            fobj=open(user)
            s=fobj.readlines()
            fobj.close()
            src_ip=re.split(' ',' '.join(s))[1]
            ruleip=input('ruleip: ')
            rule_list=ruleip.split()
            lend=len(ruleip)
            for i in range(lend):
                ruleip=rule_list[i]
                edit_iptab(src_ip,ruleip,interface,'A')
        except Exception as e:
            print (Exception,': %s user not exists!',e)
def main():
    '''
    主程序
    '''
    nav=Nav()
    nav.print_nav()
    try:
        while True:
            try:
                option=input("\033[1;32mOpt or ID>:\033[0m ").strip()
            except EOFError:
                nav.print_nav()
                continue
            except KeyboardInterrupt:
                sys.exit(0)
            if option in ['P','p','1']:                    
                ip_ex=input('Enter net(18 / 19 /..or all):')
                nav.search(ip_ex,'show') 
            elif option in ['S','s','2']:
                nav.search_nav()
                op=input('select search: ').strip()
                if op == '1':
                    user=input('search user: ')
                    nav.search('all','addrule',user,'noip')
                if op == '2':
                    se_ip=input('search ip: ')
                    nav.search('all','andrule','nouser',se_ip)
            elif option in ['A','a','3']:
                auto()
            elif option in ['D','d','4']:
                user=input('what del user: ')
                nav.del_user(user)
            elif option in ['I','i','5']:
                user=input('user: ')
                nav.add_user_iptab(user)
            elif option in ['Q','q','0','exit']:
                sys.exit(0)
            else :
                nav.print_nav()
                continue
                #return
    except IndexError as e:
        sys.exit(0)
    finally:
        pass
        #os.system('iptables-save > %s/iptables$(date +%Y%m%d-%H:%M:%S)' % '/iptabbak' ) 
if __name__=='__main__':
    main()
