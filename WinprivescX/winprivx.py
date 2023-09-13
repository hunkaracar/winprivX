import os
import sys
import subprocess
from colorama import init, Fore, Back, Style
import time
import datetime
import requests
import multiprocessing



"""
Windows most important CMD command(for Privilege Escalation)

=> systeminfo

=> ver

=> hostname

=> whoami

=> whoami /groups

=> whoami /priv

=> net user

=> net localgroup administrators

=> net user Administrator

=> wmic useraccount

=> ipconfig /all

=> arp -a

=> netstat -ano

=> route print

=> tasklist /v or tasklist 

=> findstr /si password *.txt

=> findstr /si password *.ini

=> findstr /si password *.xml

=> sc query windefend

=> cmdkey /list

#=>icacls "C:\"

=> icacls "C:\" /T

=> icacls C:\path\to\directory /T /C | findstr /i "(OI)(CI)(M)

=> wmic qfe list

"""



def booting_codeUI():

    try:

        text = "\n\nPrivilege escalation process begins for Windows\n"
        print(Fore.RED + text + Fore.RESET)

        print(f"""
    █████████████████████████████████████████████
    █▄─█▀▀▀█─▄█▄─▄█▄─▀█▄─▄█▄─▄▄─█▄─▄▄▀█▄─▄█▄─█─▄█
    ██─█─█─█─███─███─█▄▀─███─▄▄▄██─▄─▄██─███▄▀▄██
    ▀▀▄▄▄▀▄▄▄▀▀▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▀▀▀▄▄▀▄▄▀▄▄▄▀▀▀▄▀▀▀

        Developer: \\\\\\\\Hunkar Acar/////
        Date:{datetime.datetime.now()}
        Program:Winprivx
        Purpose:Windows Privelege 0f Escalation
     
        """)

        time.sleep(5)
        print(Fore.YELLOW +"__>General System features<__" + Fore.RESET)
        print(Fore.YELLOW + "---------------------------------------------------------------------------------------------------\n" + Fore.YELLOW)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)



def systeminfo():

    try:

        text = "\n\n--------------->>>[+]Systeminfo"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)
        command = os.system("systeminfo")
        return command


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE+f"Return Error Code => {e}\n"+Fore.RESET)




def ver():

    try:

        text = "\n\n\n-------------->>>[+]KernelInfo"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)
        output_command = subprocess.call(['ver'], shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def ver_test():

    try:

        output_command = subprocess.call(['ver'], shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def kernel_exploit_detect_exploitDB(value):

    try:

        print(Fore.RED+  "\n-------------->>>Exploit-DB\n" + Fore.RESET)
        time.sleep(2)
        base_url = "https://www.exploit-db.com/search"
        params = {
            "q":value,
            "action":"search",
            "submit":"Search",
            "description":"1",
            "author":"1",
            "platform":"0",
            "type":"0",
            "port":"0",
            "osvdb":"0",
            "cve":"0"
        }

        response = requests.get(base_url,params=params)

        if response.status_code == 200:
            return response.text,response.url

        else:
            print(Fore.YELLOW + "\nNo results found in exploit-db!!!!!\n\n" + Fore.RESET)
            time.sleep(2)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)




def kernel_exploit_search_engine():

    print(Fore.RED + "------------>>>Vulnerability Search For Windows" + Fore.RESET)
    time.sleep(2)
    print(Fore.MAGENTA + "\n____>Open search engines you can Vulnerability to for kernel exploits and other exploits<____\n" + Fore.RESET)


    print("https://www.exploit-db.com/")
    print("https://www.rapid7.com/")
    print("https://github.com/SecWiki/windows-kernel-exploits")
    print("https://www.cvedetails.com/")
    print("https://book.hacktricks.xyz/welcome/readme")
    print("https://pentestmonkey.net/\n")

    print(Fore.GREEN + "______>It will be useful for you to look at these urls.<_____" + Fore.RESET)
    time.sleep(7)



def hostname():

    try:

        text = "\n\n\n-------------->>>[+]HostName\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)
        output_command = subprocess.call(['hostname'],shell=True)
        #print(type(output_command)) Return Class <'int'>
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)



def whoami():

    try:

        text = "\n\n\n------------->>>[+]Whoami\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)
        output_command = subprocess.call(['whoami'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def whoami_groups():

    try:

        text = "\n\n\n-------------->[+]whoami /groups\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)
        output_command = subprocess.call(['whoami','/groups'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def whoami_privs():


    try:

        text = "\n\n\n-------------->[+]whoami /priv\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)
        output_command = subprocess.call(['whoami', '/priv'], shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def net_user():

    try:

        text = "\n\n\n-------------->>>[+]net user (Shows users on Windows)\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)
        output_command = subprocess.call(['net', 'user'], shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def net_localgroup_administrators():

    try:

        text = "\n\n\n-------------->>>[+]net localgroup administrators\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)
        output_command = subprocess.call(['net', 'localgroup','administrators'], shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def root_user_detect():

    try:

        text = "\n\n\n-------------->>>[+]Root User Detect\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)

        output_command = subprocess.call('net user Administrator',shell=True)
        #command_output = output_command.stdout
        #print(type(output_command)) => <Class 'int'>

        if output_command == 0:
            print(Fore.GREEN + "\n---->>[!] Root user detected! ===> (Administrator)<<----\n" + Fore.RESET)

        else:
            print(Fore.RED + "\n[-] No root user detected.Could be - NT-Authority System -\n" + Fore.RESET)


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)




def wmic_useraccount():

    try:

        text = "\n\n\n--------------->>>[+]UserAccount(details)\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)

        output_command = subprocess.call(['wmic','useraccount'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def ip_config_all():

    try:

        text = "\n\n\n--------------->>>[+]Ipconfig(details)\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)

        output_command = subprocess.call(['ipconfig','/all'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def arp_a():

    try:

        text = "\n\n\n--------------->>>[+]Arp Table Information\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)

        output_command = subprocess.call(['arp','-a'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def netstat_ano():

    try:

        text = "\n\n\n--------------->>>[+]Active Connections\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)

        output_command = subprocess.call(['netstat','-ano'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def route_print():

    try:

        text = "\n\n\n--------------->>>[+]Router Information\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)

        output_command = subprocess.call(['route','print'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def tasklist():

    try:

        text = "\n\n\n--------------->>>[+]Tasklist\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(2)

        output_command = subprocess.call(['tasklist'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)



def find_txtPass_file():

    try:

        text = "\n\n\n--------------->>>[+]Password TXT File\n\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(3)

        #subprocess.call(['cd', 'C:'])
        output_command = subprocess.call(['findstr','/si','password','C:\*.txt'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def find_iniPass_file():

    try:

        text = "\n\n\n--------------->>>[+]Password INI(ini) File\n\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(3)

        #subprocess.call(['cd','C:'])
        output_command = subprocess.call(['findstr','/si','password','C:\*.ini'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def find_xmlPass_file():

    try:

        text = "\n\n\n--------------->>>[+]Password XML File\n\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(3)

        #subprocess.call(['cd', 'C:'])
        output_command = subprocess.call(['findstr','/si','password','C:\*.xml'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)



def find_id_rsa_file():

    try:

        text = "\n\n\n--------------->>>[+]Search id_rsa File for SSH KEY\n\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(3)

        # subprocess.call(['cd', 'C:'])
        output_command = subprocess.call(['findstr', '/si', 'id_rsa', 'C:\*.pub'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)





def sc_query_windefend():

    try:

        text = "\n\n\n--------------->>>[+]Windows Defender Active/Passive\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(3)

        output_command = subprocess.call(['sc','query','windefend'],shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)



def icacls_T():
    

    try:

        text = "\n\n\n--------------->>>[+]Access and Accessibility Permissions\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(3)

        output_command = subprocess.call(['icacls', 'C:','/T'], shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)



def wmic_qfe_list():


    try:

        text = "\n\n\n--------------->>>[+]Update List\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(3)

        output_command = subprocess.call(['wmic', 'qfe', 'list'], shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def icacls_findstr():

    try:

        text = "\n\n\n--------------->>>[+]Files with Specific Propertiess\n"
        print(Fore.RED + text + Fore.RESET)
        time.sleep(3)

        output_command = subprocess.call(['icacls', 'C:', '/T','/C','|','findstr','/i','(OI)','(CI)','(M)'], shell=True)
        return output_command


    except subprocess.CalledProcessError as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)


    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)


    except Exception as e:
        print(Fore.BLUE + f"Return Error Code => {e}\n" + Fore.RESET)




def scan_complete():

    try:
        print(Fore.YELLOW + "\n\n\t--------------------------------------------------------------------------------------------------------\n" + Fore.RESET)
        print(Fore.YELLOW + "\n\n\t<<<< Analyze the results well >>>>\n\n" + Fore.RESET)
        print(Fore.YELLOW + "\t-------------------#SCAN COMPLETED------------------###\n\n" + Fore.RESET)
        time.sleep(2)

    except KeyboardInterrupt:
        print(Fore.RED + "\n\n\tProgram::Terminated\n\n" + Fore.RESET)
        sys.exit(1)



booting_codeUI()
systeminfo()
ver()
kernel_exploit_detect_exploitDB(ver_test())
kernel_exploit_search_engine()
hostname()
whoami()
whoami_groups()
whoami_privs()
net_user()
net_localgroup_administrators()
root_user_detect()
wmic_useraccount()
ip_config_all()
arp_a()
netstat_ano()
route_print()
tasklist()
find_txtPass_file()
find_iniPass_file()
#find_xmlPass_file()
find_id_rsa_file()
sc_query_windefend()
icacls_T()
wmic_qfe_list()
icacls_findstr()
scan_complete()