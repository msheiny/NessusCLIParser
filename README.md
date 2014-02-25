a Nessus XMLv2 Command-line parser written in Python. Has functionality to 
also lookup usernames by MAC address through an already existing external 
mysql inventory database.


ToDo
-------------

* Have to upload a sanitized XML for all the tests to pass.
* Missing mysql credential file which shouldn't be applicable to anyone but me.

Running
-------------

NessusCLIReport.py is the entry point. It takes command line arguments for filtering down to just the hosts and vulnerabilities you want to see. An xml file location or folder location (full of XMLs) is required. 

Currently can filter by:

* Vulnerability severity level
* host IP
* host dns name
* operating system string (like 'windows', 'linux')

Output options:

* Succint CSV with just the host information
* optional all open port information
* Vulnerabity break-down


```
msheiny@nessus:~/> /usr/local/bin/NessusCLIReport.py -h
usage: NessusCLIReport.py [-h] -xml XML [-sevplus {0,1,2,3,4}]
                          [-seveq {0,1,2,3,4}] [-noshowports] [-noshowvulns]
                          [-hostip HOSTIP] [-hostdns HOSTDNS]
                          [-osmatch OSMATCH] [-csv] [-port PORT]

This program will parse through already conducted scan result files and give
you a nicer report

optional arguments:
  -h, --help            show this help message and exit
  -xml XML              Indicate the XML file/location you would like to parse
  -sevplus {0,1,2,3,4}  Minimum severity level of severity to report [choose
                        from 0,1,2,3, or 4] . Defaults to 1
  -seveq {0,1,2,3,4}    Only report severity level signified [choose from
                        0,1,2,3, or 4].
  -noshowports          Show the ports of the hosts that are open. Typically
                        this is not shown.
  -noshowvulns          Dont show the vulns of the hosts. Useful for just
                        grabbing the basic host data.
  -hostip HOSTIP        Indicate a particular host from the xml file that you
                        would like to filter to
  -hostdns HOSTDNS      Indicate a particular host from the xml file that you
                        would like to filter to
  -osmatch OSMATCH      String match on a particular word in the operating
                        system type
  -csv                  Print output of just hosts in csv format
  -port PORT            Only show vulnerabilities that match this port
```
