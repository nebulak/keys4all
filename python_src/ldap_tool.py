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

import argparse
import ldap

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-a', '--action', type=str, help='Action', required=True
    )
    parser.add_argument(
        '-e', '--email', type=str, help='Email', required=True
    )
    parser.add_argument(
        '-u', '--user', type=str, help='User for authentication', required=False, default=None
    )
    parser.add_argument(
        '-p', '--pw', type=str, help='Password for authentication', required=False, default=None
    )
    parser.add_argument(
        '-c', '--cert_path', type=str, help='Path to encoded certificate', required=False, default=""
    )

    args = parser.parse_args()

    return args.action, args.email, args.user, args.pw, args.cert_path


def main():
    action, email, user, pw, cert_path = get_args()

    if action == 'get_cert':
        ldap.get_cert_tls(email, cert_path)
    elif action == 'update_cert':
        ldap.update_cert(email, user, pw, cert_path)
    elif action == 'create_entry':
        ldap.create_entry(email, user, pw, cert_path)
    elif action == 'delete_cert':
        ldap.delete_cert(email, user, pw)
    else:
        print('Action unknown')

main()
