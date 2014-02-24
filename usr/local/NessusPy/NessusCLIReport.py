#!/usr/bin/env python 

import argparse
import NessusAnalysis

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This program will parse through already conducted scan result files and give you a nicer report')

    parser.add_argument('-xml', required=True, 
                        help='Indicate the XML file/location you would like to parse')
    parser.add_argument('-sevplus', choices='01234', 
                        help='Minimum severity level of severity to report [choose from 0,1,2,3, or 4] . Defaults to 1', default=None)
    parser.add_argument('-seveq', default=None, 
                        choices='01234', help='Only report severity level signified [choose from 0,1,2,3, or 4].')
    parser.add_argument('-noshowports', action='store_false', 
                        help='Show the ports of the hosts that are open. Typically this is not shown.', default=True)
    parser.add_argument('-noshowvulns', action='store_false', 
                        help='Dont show the vulns of the hosts. Useful for just grabbing the basic host data.', default=True)
    parser.add_argument('-hostip', 
                        help='Indicate a particular host from the xml file that you would like to filter to', default=None)
    parser.add_argument('-hostdns', 
                        help='Indicate a particular host from the xml file that you would like to filter to', default=None)
    parser.add_argument('-osmatch', 
                        help='String match on a particular word in the operating system type', default = None)
    parser.add_argument('-csv', action='store_true', default=False,
                        help='Print output of just hosts in csv format',)
    parser.add_argument('-port', default=None,
                        help='Only show vulnerabilities that match this port',)

    user_args = parser.parse_args()

    results = NessusAnalysis.NessusXMLParser(user_args.xml,
                                             troll_check=True)
    results.FilterHostAttrs(hostIP = user_args.hostip, 
                            fqdn = user_args.hostdns,
                            os_string = user_args.osmatch)
    results.FilterVulnAttrs(severityeq = user_args.seveq,
                            severitygte = user_args.sevplus,
                            porteq = user_args.port)
    results.parse()

    if user_args.csv: results.csv_print_hosts()
    else:
        results.pretty_print(show_ports = user_args.noshowports,
                             show_vulns = user_args.noshowvulns)

    

