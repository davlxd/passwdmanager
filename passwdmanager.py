#! /usr/bin/python3

# passwdmanager.py --- 
# 
# Filename: passwdmanager.py
# Description: Generate, keep, prompt to update password
# Author: lxd
# Maintainer: 
# Created: Wed Feb  1 15:46:06 2012 (+0800)
# Version: 1.0
# Last-Updated: 
#           By: 
#     Update #: 0
# URL: 
# Keywords: 
# Compatibility: Python 3.1
# 
#

# Depends: PyCrypto-2.5
# 


# Commentary: 
# 
# 
# 
# 

# Change Log:
# 
# 
# 
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street, Fifth
# Floor, Boston, MA 02110-1301, USA.
# 
# 

# Code:

import sys
import os
import platform
import time
import datetime
import math
import getpass
import binascii
import subprocess
import Crypto
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

PROGRAM="PasswdManager"
VERSION=1.0
PYTHON_VERSION=sys.version[:5]
CRYPTO_VERSION=Crypto.__version__
LICENSE="""License under GNU GPL version 3 <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law."""
AUTHOR="lxd <i@lxd.me>"

CIPHERTEXT_WIDTH=68
START_OF_CIPHERTEXT="# START OF CIPHERTEXT"
END_OF_CIPHERTEXT="# END OF CIPHERTEXT"


outter_inputs = { '?' : ['Print this', lambda:print_help(outter_inputs)],
                  'ex': ['Export unencryted password info in base64', \
                             lambda:do_export()],
                  'q' : ['Exit this script', lambda:die()],
                  'n' : ['Creat new entry', lambda:create_new_entry()],
                  'u' : ['Update main passwd', \
                             lambda:prompt_update_main_passwd()]
                  }


# Data structure

LISTS = [[] for x in range(9)]
LOG_LEN = 5
logged_user_host = LISTS[0]
logged_timestamp = LISTS[1]
passwd_altered = LISTS[2]

HISTORY_LEN = 4
main_passwd = LISTS[3]
updated_timestamp = LISTS[4]
entry_name = LISTS[5]
entry_username = LISTS[6]
entry_passwd = LISTS[7]
entry_updated_timestamp = LISTS[8]

DEFAULT_PASSWD_LEN = 15



def print_lists(): print(LISTS)

def now():
    return math.trunc(time.time())

def update_logs():
    if len(logged_user_host) >= LOG_LEN:    
        logged_user_host.pop(0)
        logged_timestamp.pop(0)
        passwd_altered.pop(0)
    
    logged_user_host.append('{0}@{1}'.
                            format(getpass.getuser(), platform.node()))
    logged_timestamp.append(now())
    passwd_altered.append(False)

def set_to_altered():
    passwd_altered[len(passwd_altered)-1] = True

def update_main_passwd(p):
    if len(main_passwd) >= HISTORY_LEN:
        main_passwd.pop(0)
        updated_timestamp.pop(0)
    main_passwd.append(p)
    updated_timestamp.append(now())
    update_ciphertext()

def die(c=0):
    update_ciphertext()
    print('\nBye~')
    sys.exit(c)

def get_user_input(msg='', f=input):
    try:
        user_input = f(msg + '>> ')
    except (KeyboardInterrupt, EOFError):
        die()
    return user_input
    
def txt_parenthesized(t):
    if len(t) == 0:
        return False
    return t[0] == '(' and t[-1] == ')'

def type_convertible(s, t):
    try:
        i = t(s)
    except ValueError as ex:
        return False
    else:
        return True

def int_convertible(s):
    return type_convertible(s, int)

def literal_bool_convertible(s):
    return s == 'True' or s == 'False'

def literal_bool(s):
    assert literal_bool_convertible(s)
    if s == 'True':
        return True
    else:
        return False

def split_by_level1(s, sep):
    """Split string by sep but escape sep within parenthesis"""
    stack = []
    l = []
    e = ''
    skip = False
    
    for c in s:
        if c == sep and not skip:
            l.append(e)
            e = ''
            continue
        if c == '(':
            skip = True
            stack.append('#')
        elif c == ')':
            if len(stack) == 1:
                skip = False
            stack.pop()
        e += c

    if e:
        l.append(e)
    return l
    
def txt_2_list(t, l):
    """Convert list-formated string to real list"""
    if txt_parenthesized(t):
        t = t[1:-1]
    assert len(l) == 0
    
    l0 = split_by_level1(t, ',')
    for e in l0:
        if txt_parenthesized(e):
            ll = []
            l.append(txt_2_list(e, ll))
        elif int_convertible(e):
            l.append(int(e))
        elif literal_bool_convertible(e):
            l.append(literal_bool(e))
        else:
            l.append(e)
    return l

def list_2_txt(l):
    if type(l) is not list:
        return str(l)
    else:
        txt = '('
        for e in l:
            txt += list_2_txt(e) + ','
        return txt + ')' if txt[-1] == '(' else txt[:-1] + ')'

def extract_lists():
    txt = ''
    for l in LISTS:
        txt += list_2_txt(l)
    return txt

def extract_txt(t):
    assert len(t) > 1
    tls = t[1:-1].split(')(')

    for tl, l in zip(tls, LISTS):
        txt_2_list('('+tl+')', l)


def calc_main_passwd(passwd_txt):
    obj = SHA256.new()
    obj.update(passwd_txt.encode())
    d = obj.digest()
    return binascii.b2a_base64(d).decode()[:32]

def encrypt(txt, rawpasswd):
    k = calc_main_passwd(rawpasswd)
    aes = AES.new(k, AES.MODE_CFB)
    ct = aes.encrypt(txt.encode())
    return binascii.b2a_base64(ct).decode()[:-1] # remove trailing `\n'


def decrypt(b64s, rawpasswd):
    k = calc_main_passwd(rawpasswd)
    try:
        ct = binascii.a2b_base64(b64s.encode())
        aes = AES.new(k, AES.MODE_CFB)
        txt = aes.decrypt(ct)
        txts = txt.decode()
    except UnicodeDecodeError:
        return False
    else:
        return txts

def load_ciphertext():
    with open(sys.argv[0], 'r') as f:
        ct = ""
        In = False
        for l in f:
            l = l.rstrip('\n')
        
            if l == START_OF_CIPHERTEXT:
                In = True
            elif l == END_OF_CIPHERTEXT:
                break
            elif In:
                ct += l.lstrip('#')
    return ct

def unload_ciphertext(ct):
    ctlist = [ct[i:i+CIPHERTEXT_WIDTH]
              for i in range(0, len(ct), CIPHERTEXT_WIDTH)]
    pre = post = s = ''
    
    with open(sys.argv[0], 'r+') as f:
        for l in f:
            s += l
            if l.rstrip('\n') == START_OF_CIPHERTEXT:
                pre = s
                s = ''
            elif l.rstrip('\n') == END_OF_CIPHERTEXT:
                s = ''
        post = END_OF_CIPHERTEXT + '\n' + s

    with open(sys.argv[0], 'w') as f:
        f.write(pre)
        for l in ctlist:
            f.write('#' + l + '\n')
        f.write(post)

def update_ciphertext():
    assert len(main_passwd) > 0
    unload_ciphertext(encrypt(extract_lists(), main_passwd[-1]))
    

def prompt_update_main_passwd():
    passwd = get_user_input('Input new main password', getpass.getpass)
    passwd1 = get_user_input('Again as uaual', getpass.getpass)
    if passwd != passwd1:
        s = get_user_input('\nNot match, press \'c\' to cancel')
        if s == 'c' or s == 'C':
            return False
        else:
            prompt_update_main_passwd()
    else:
        update_main_passwd(passwd)
        return True




def print_help(dic):
    print('List of possible commands:\n')
    for x in dic:
            print(x, dic[x][0], sep='\t')
    print()


def print_entries_multilines():
    d = datetime.timedelta(seconds=(now()-updated_timestamp[-1])) #duration
    print('\nEntries (main password updated', str(d), 'ago):')
    
    # Here is why I like python ...
    for i, (n, un, ts) in enumerate(zip(entry_name,
                                        entry_username,
                                        entry_updated_timestamp)):
        d = datetime.timedelta(seconds=(now()-ts[-1]))
        print(str(i), n, un, str(d), sep='    ')
    print()

def print_entries_singleline():
    print('\nEntries: ', end='')
    for i, n in enumerate(entry_name):
        print(str(i), '.', n, sep='', end='  ')
    print()

def print_entry_detail(i, showidx=-1):
    print(str(i)+'.', entry_name[i], entry_username[i], ' ', end='')
    l = entry_passwd[i]
    for i, p in enumerate(l):
        pp = p if i == showidx else p[:3]+'...'
        print('[', str(i), ']', '.', pp, sep='', end='  ')
    print()

def generate_passwd(pphrase, plen):
    #TODO
    sha = SHA256.new()
    sha.update(pphrase.encode())
    d = sha.digest()
    return binascii.b2a_base64(d).decode()[:plen]#random []
    #Password must contain at least one of letters, numbers, and symbols.

def do_export():
    while True:
        s = get_user_input('Where to put ? ('+os.getcwd()+')')
        if s == '' or s != '' and os.path.exists(s):
            break
        print('Invalid')
    p = s if s != '' else os.getcwd()

    fname = 'pass.data'
    s = get_user_input('Filename ? ('+fname+')')
    f = s if s != '' else fname

    lt = extract_lists()
    t = binascii.b2a_base64(lt.encode()).decode()

    try:
        with open(os.path.join(p, f), 'w') as fp:
            fp.write(t)
    except IOError as ioe:
        print(ioe)
        return False
        
    print('Done')
    return True


def create_new_entry():
    print('Creat a new entry, directly hit Enter to cancel')
    
    en = get_user_input('Input entry name')
    if en == '': return False

    un = get_user_input('Input username')
    if un == '': return False

    pp = get_user_input('Input passphrase')
    if pp == '': return False

    pls = get_user_input('Input password length (default%d)' %
                        DEFAULT_PASSWD_LEN)
    if pls == '' or not int_convertible(pls):
        pl = DEFAULT_PASSWD_LEN
    elif int_convertible(pls) and int(pls) <= 0:
        pl = DEFAULT_PASSWD_LEN
    else:
        pl = int(pls)

    passwd = generate_passwd(pp, pl)
    entry_name.append(en)
    entry_username.append(un)
    entry_passwd.append([passwd])
    entry_updated_timestamp.append([now()])

    print('New entry %s created' % en)
    return True

def remove_entry(i):
    s = get_user_input('Are you sure to remove entry '+entry_name[i]+'?(Yn)')
    if s == 'Y' or s == 'y':
        entry_username.pop(i)
        entry_passwd.pop(i)
        entry_updated_timestamp.pop(i)
        name = entry_name.pop(i)
        
        print('Entry', name, 'removed')
        return True
    else:
        print('Abort')
        return False

def extend_outter_inputs():
    d = {}
    for i, name in enumerate(entry_name):
        d[str(i)] = ['Operate on entry \''+name+'\'', lambda:innner_loop(i)]
        d['d'+str(i)] = ['Remove entry \''+name+'\'', lambda:remove_entry(i)]

    for x in outter_inputs: # merge
        d[x] = outter_inputs[x]
    
    d['?'][1] = lambda:print_help(d) # update

    return d

def update_entry_passwd(i):
    en = get_user_input('Input new entry name ('+entry_name[i]+')')
    if en != '': entry_name[i] = en

    un = get_user_input('Input username ('+entry_username[i]+')')
    if un != '': entry_username[i] = un

    pp = get_user_input('Input passphrase')
    if pp == '':
        print('Abort')
        print_entries_singleline()
        print_entry_detail(i)
        return False

    pls = get_user_input('Input password length (default%d)' %
                        DEFAULT_PASSWD_LEN)
    if pls == '' or not int_convertible(pls):
        pl = DEFAULT_PASSWD_LEN
    elif int_convertible(pls) and int(pls) <= 0:
        pl = DEFAULT_PASSWD_LEN
    else:
        pl = int(pls)

    passwd = generate_passwd(pp, pl)

    if len(entry_passwd[i]) >= HISTORY_LEN:
        entry_passwd[i].pop(0)
        entry_updated_timestamp[i].pop(0)
        
    entry_passwd[i].append(passwd)
    entry_updated_timestamp[i].append(now())

    print('Done')
    
    print_entries_singleline()
    print_entry_detail(i)
    
    return True

# --Implementation of 'yank passwd to X's clipboard'
def xsel_installed():
    program = 'xsel'
    for path in os.environ['PATH'].split(':'):
        fullpath = os.path.join(path, program)
        if os.path.exists(fullpath) and not os.path.isdir(fullpath):
            return True
    return False

def get_xsel_version():
    assert xsel_installed()
    return subprocess.getoutput('xsel --version').split()[2]

def cp2_clipboard(s):
    if not xsel_installed():
        print('Copied to clipboard failed, xsel not found.')
        return None
    try:
        if type(s) is str:
            b = s.encode()
        p0 = subprocess.Popen('xsel', stdin=subprocess.PIPE)
        p0.communicate(b)
        p1 = subprocess.Popen(['xsel', '--clipboard'], stdin=subprocess.PIPE)
        p1.communicate(b)
    except OSError:
        print('Copied to clipboard failed.')
# --

def do_yank(p):
    cp2_clipboard(p)
    return True

def do_show(entry_idx, passwd_idx):
    print_entries_singleline()
    print_entry_detail(entry_idx, passwd_idx)
    return True

def extend_inner_inputs(i): # extend from scratch
    d = {}
    pl = entry_passwd[i]
    
    d['?'] = ['Print this', lambda:print_help(d)]
    d['m'] = ['Return to main menu', lambda:'return']
    d['u'] = ['Update password info', lambda:update_entry_passwd(i)]
    d['y'] = ['Yank newest password', lambda:do_yank(pl[-1])]
    d['s'] = ['Show newest password', lambda:do_show(i, len(pl)-1)]
    for k, p in enumerate(pl):
        s = str(k)
        d['y'+s] = ['Yank '+s+'th password', lambda: not do_yank(p)]
        d['s'+s] = ['Show '+s+'th password', lambda: not do_show(i, k)]
        print(d)

    return d


def innner_loop(i):
    print_entries_singleline()
    print_entry_detail(i)
    while True:
        s = get_user_input()
        dic = extend_inner_inputs(i)
        if s not in dic:
            print('Invalid input \'', s , '\' ', sep='')
            print_entries_singleline()
            print_entry_detail(i)
            continue
        rv = dic[s][1]() # lambda execute...
        if rv == 'return': return None # TODO: (dirty)


def outter_loop():
    while True:
        print_entries_multilines()
        s = get_user_input()
        dic = extend_outter_inputs()
        if s not in dic:
            print('Invalid input \'', s , '\' ', sep='')
            continue
        dic[s][1]()


def first_time_use():
    print("No CipherText found, maybe it's your first time start this "\
              "script or pretend to do so, anyway create your main pasword")
    rv = prompt_update_main_passwd()
    if not rv:
        die(1)
        
    update_logs()
    set_to_altered()

def security_guard():
    ct = load_ciphertext() # `ct': CipherText
    if not ct:
        first_time_use()
    else:
        decrypted = False
        while not decrypted:
            passwd = get_user_input('Input main passwd:',getpass.getpass)
            decrypted = decrypt(ct, passwd)
        extract_txt(decrypted)
        update_logs()
        
    update_ciphertext()
    outter_loop()


if __name__ == '__main__':
    XSEL_VERSION=get_xsel_version() if xsel_installed() else 'not installed'
    print("\n{} {} (Python {}, Crypto {}, XSel {})\n{}\nAuthor: {}, {}\n".
          format(PROGRAM, VERSION, PYTHON_VERSION, CRYPTO_VERSION,
                 XSEL_VERSION, LICENSE, AUTHOR, 'Input \'?\' for help'))
    security_guard()


# Attention! Do not touch following lines, ciphertext lies here
# START OF CIPHERTEXT
#UW3lx+6dHcxdWY63nK5GJIfNk9iGuR7CebhCCXbQ5ByTpoFCRBxSb3cGFeVFs2KWH0LT
#UK5IICiH4HXAZXLun7eVCZUWcNDN/xY8DmqbNmz/9IX6CISikfxhkrbDsvFWKB5n4IVi
#f/wytmlKT+3JxPjJrxDkyopIF6zee4bq0sIbQJoR0nyZL397KcukZdXOPtRpjXAdFBP3
#G7w6XmTZeeQ1YG12qFzqJ4KB92rwjqB5+XsfNZBC4h8tBMi3BuYZChfp07CuRFZfe6gy
#0OVcGCXqWgm8IcyX+306N8zuakOvr59YjCJYXmgbZTutHRAW6Xgd7BKUHZUPiJ8F4YXG
#F9hQM7RH+VpUBB7AxTHHZ4l/bf2G9h2un/3qA4CGUoo6QrfMMP3Ku9M1oghCRs1vWHU7
#r0T/j5pkcpZ3KU0=
# END OF CIPHERTEXT

# 
# passwdmanager.py ends here


