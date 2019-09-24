'''
Keys4All Thunderbird-Addon
Designed and developed by
Fraunhofer Institute for Secure Information Technology SIT
<https://www.sit.fraunhofer.de>
(C) Copyright FhG SIT, 2018

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 '''


import ssl
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, Tls
from ldap3.utils.conv import escape_bytes

LDAP_SERVER = "ldap.example.de:389"
LDAP_SERVER_TLS = "ldap.example.de:636"
LDAP_SEARCH_BASE = 'dc=keys4all-test,dc=org'


def list():
    server = Server(LDAP_SERVER_TLS, use_ssl=True)
    conn = Connection(server)
    conn.bind()
    search_filter = '(&(objectclass=inetOrgPerson)(mail=*))'
    attrs = ['uid;string']
    conn.search(LDAP_SEARCH_BASE, search_filter, attributes=attrs)
    entry_size = len(conn.entries)
    print("Entries: "+str(entry_size))
    if  entry_size > 0:
        for x in range(0, entry_size) :
            print(conn.entries[x])
    else:
        print("")

    conn.unbind()



def create_entry(email, auth_user, auth_pw, cert_path=""):
        if len(cert_path) != 0:
            der_cert = open(cert_path, "rb").read()

        # email to: cn, dc, dc
        emailSplit1 = email.split('@')
        username = emailSplit1[0]
        emailSplit2 = emailSplit1[1].split('.')
        dc0 = emailSplit2[0]
        dc1 = emailSplit2[1]

        # Open connection
        server = Server(LDAP_SERVER_TLS, use_ssl=True, get_info=ALL)
        conn = Connection(server, user=auth_user, password=auth_pw)
        conn.bind()

        # Create entry
        if len(cert_path) != 0:
            rc = conn.add('uid='+email+',ou=certificates,'+LDAP_SEARCH_BASE, 'inetOrgPerson', {'cn': username, 'uid':email, 'mail': email, 'sn': username, 'userCertificate;binary': der_cert})
        else:
            rc = conn.add('uid='+email+',ou=certificates,'+LDAP_SEARCH_BASE, 'inetOrgPerson', {'cn': username, 'uid':email, 'mail': email, 'sn': username})
        print(conn.result)
        print("rc: "+str(rc))



def get_cert(email):
    server = Server(LDAP_SERVER)
    conn = Connection(server)
    conn.bind()
    #print(conn)
    search_filter = '(&(objectclass=inetOrgPerson)(mail='+email+'))'
    attrs = ['userCertificate;binary']
    conn.search(LDAP_SEARCH_BASE, search_filter, attributes=attrs)
    if len(conn.entries) > 0:
        print("Found entry")
        print(conn.entries[0])
        return conn.entries[0].userCertificate
    else:
        print("No entry")
        return None

    conn.unbind()

def get_cert_tls(email, cert_path):
    #tls = Tls(local_certificate_file = 'cert.pem', validate = ssl.CERT_REQUIRED, version = ssl.PROTOCOL_TLS)
    tls = Tls(local_certificate_file = cert_path, validate = ssl.CERT_REQUIRED)
    server = Server(LDAP_SERVER_TLS, use_ssl=True, tls=tls)
    conn = Connection(server)
    conn.bind()

    search_filter = '(&(objectclass=inetOrgPerson)(mail='+email+'))'
    attrs = ['userCertificate;binary']
    conn.search(LDAP_SEARCH_BASE, search_filter, attributes=attrs)
    if len(conn.entries) > 0:
        print("Found entry")
        print(conn.entries[0])
        return conn.entries[0].userCertificate
    else:
        print("No entry")
        return None

    conn.unbind()

def update_cert(email, auth_user, auth_pw, cert_path=""):
        der_cert = open(cert_path, "rb").read()

        # email to: cn, dc, dc
        emailSplit1 = email.split('@')
        username = emailSplit1[0]
        emailSplit2 = emailSplit1[1].split('.')
        dc0 = emailSplit2[0]
        dc1 = emailSplit2[1]

        # Open connection
        tls = Tls(validate = ssl.CERT_NONE)
        server = Server(LDAP_SERVER_TLS,get_info=ALL,use_ssl=True, tls=tls)
        conn = Connection(server, user=auth_user, password=auth_pw)
        conn.bind()

        # check if certificate exists at server
        if get_cert(email) != None:
            print("cert found")
            rc = conn.modify("uid="+email+",ou=certificates,"+LDAP_SEARCH_BASE, {"userCertificate;binary": [(MODIFY_REPLACE, der_cert)]})
            print(conn.result)
        else:
            print("cert not found")
            rc = conn.modify("uid="+email+",ou=certificates,"+LDAP_SEARCH_BASE, {"userCertificate;binary": [(MODIFY_ADD, der_cert)]})
            print(conn.result)



def delete_cert(email, auth_user, auth_pw):
        # Open connection
        tls = Tls(validate = ssl.CERT_NONE)
        server = Server(LDAP_SERVER_TLS,get_info=ALL,use_ssl=True)
        conn = Connection(server, user=auth_user, password=auth_pw)
        conn.bind()

        # check if certificate exists at server
        if get_cert(email) != None:
            print("cert found")
            rc = conn.modify("uid="+email+",ou=certificates,"+LDAP_SEARCH_BASE, {"userCertificate;binary": [(MODIFY_DELETE, [])]})
            print(conn.result)
        else:
            print("cert not found")
