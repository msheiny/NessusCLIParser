#!/usr/bin/env python 
import os
from bs4 import BeautifulSoup
from TrollDB import TrollDB


class HostObject(object):
  """
    Class definition for Host objects. 
    Each extracted Nessus ReportHost is converted to this.
  """

  def __init__(self, SoupObject, troll_user_check=False, sqlalchemy=None):
    """ 
      At minimum, need to provide a host object of the ReportHost 
    """

    strfilter = "SoupObject.HostProperties.find('tag',attrs={{'name':'{0}'}}).string"
    self.IP = self.set_or_none(SoupObject, strfilter.format('host-ip'))
    self.fqdn = self.set_or_none(SoupObject, strfilter.format('host-fqdn'))
    self.os = self.set_or_none(SoupObject, 
                               strfilter.format('operating-system'))
    self.mac = self.set_or_none(SoupObject, strfilter.format('mac-address'))
    self.owner = "N/A"

    try:
      if troll_user_check and self.mac:
        self.owner = sqlalchemy.UserForMac(self.mac)
    except (ImportError, UserWarning): 
      pass
    self.vulns = []
    self.ports = []
    
  def set_or_none(self, SoupObject, SoupSearch):
    try: return eval(SoupSearch).replace('\n',' | ')
    except (AttributeError): return "N/A"

  def insert_report_item(self, SoupObject):
    """ 
      Set a vulnerability for a host object. Just need the matching 
      soup object.
    """

    if ( SoupObject['pluginFamily'] == "Port scanners" 
        and SoupObject['severity'] == "0"):
        port_dict = {'port':SoupObject['port'],
                          'protocol':SoupObject['protocol'],
                          'svc':SoupObject['svc_name']}
        try:
          for ports in self.ports:
            if ports == port_dict: 
              raise ValueError('{0} duplicate'.format(ports))
          self.ports.append(port_dict)
        except ValueError:
          pass

    else:
        stag = "SoupObject['{0}']"
        sfind = "SoupObject.find('{0}').string"
        self.vulns.append({'port': self.set_or_none(SoupObject, 
                          stag.format('port')),
                      'protocol':self.set_or_none(SoupObject, 
                          stag.format('protocol')),
                      'svc':self.set_or_none(SoupObject, 
                          stag.format('svc_name')),
                      'severity':self.set_or_none(SoupObject, 
                          stag.format('severity')),
                      'pluginFamily':self.set_or_none(SoupObject, 
                          stag.format('pluginFamily')),
                      'synopsis':self.set_or_none(SoupObject, 
                          sfind.format('synopsis')),
                      'solution':self.set_or_none(SoupObject, 
                          sfind.format('solution')),
                      'risk_factor':self.set_or_none(SoupObject, 
                          sfind.format('risk_factor')),
                      'osvdb':self.set_or_none(SoupObject, 
                          sfind.format('osvdb'))})

class NessusXMLParser(object):
  """Class for parsing Nessus XML v2 files"""

  def __init__(self, xml, troll_check=True):
      """ 
        Provide me with the location to an xml file or the location of
        a folder filed with xml files
      """

      self.troll_user_check = troll_check
      self.result_storage = []
      self.FilterHostAttrs()
      self.FilterVulnAttrs()

      try:
          open(xml)
          self.xml = [xml]
      except IOError:
          self.xml = [os.path.join(xml,file) for file in os.listdir(xml)]

      # SQLAlchemy class
      self.troll_link = TrollDB()
      
  def ValidateXML(self, SoupObject):
      """ 
        Very basic validation logic. Might want to expand later. 
      """
      if ( not SoupObject.NessusClientData_v2 ): 
          raise TypeError

  def FilterHostAttrs(self,
             hostIP=None, 
             fqdn=None, 
             os_string=None, 
             mac=None):
    """ Setup and mark which attributes we will filter the host on """

    filteredlocals = {}
    attrs = ['hostIP', 'fqdn', 'os_string', 'mac']
    for name in attrs:
        if eval(name): filteredlocals[name] = eval(name)
    self.FilterHost = filteredlocals

  def FilterVulnAttrs(self,
             family=None, 
             severityeq=None,
             severitygte=None,
             porteq=None):
    """ 
      Setup and determine which vulnerabilities we will be filtering later for 
    """

    if severityeq and severitygte:
        raise Warning('Cannot have severityeq and severitygt set at once')
    if severityeq: severityeq = int(severityeq)
    if severitygte: severitygte = int(severitygte)
    if porteq: porteq = int(porteq)
    filteredlocals = {}
    attrs = ['family', 'severityeq', 'severitygte', 'porteq']

    for name in attrs:
      if eval(name): filteredlocals[name] = eval(name)
    self.FilterVulns = filteredlocals


  def XMLEqualorRaise(self, SoupObj, key, keyfilter, value, SoupSearch):
    """ 
      Comparison logic for comparing strings. Raise ValueError when no
      match
    """
    if key == keyfilter:
        xml_value = eval(SoupSearch)
        if not xml_value:
          raise ValueError('Filtering for {0} which is blank.'.format(
                           key))
        elif xml_value.string.lower() != value.lower(): 
          raise ValueError('Value {0} != {1}'.format(
                             xml_value.string.lower(), value.lower()))

  def XMLEqualIntorRaise(self, SoupObj, key, keyfilter, value, SoupSearch):
    """ 
      Comparison logic for comparing integers. Raise ValueError when no
      match
    """
    if key == keyfilter:
        if int(eval(SoupSearch)) != value: 
            raise ValueError('Value {0} != {1}'.format(
                             int(eval(SoupSearch)), value))

  def XMLGTEorRaise(self, SoupObj, key, keyfilter, value, SoupSearch):
    """ 
      Comparison logic for comparing integers greater than or equal to. 
      Raise ValueError when no match
    """
    if key == keyfilter:
        if int(eval(SoupSearch)) < value: 
            raise ValueError('Value {0} != {1}'.format(
                             int(eval(SoupSearch)), value))

  def XMLTagInorRaise(self, SoupObj, key, keyfilter, value, SoupSearch):
    """ 
      Comparison logic for seeing if string is in XML value.
      Raise ValueError if no match
    """
    if key == keyfilter:
        if not eval(SoupSearch): 
          raise ValueError('Value not provided for {0}'.format(keyfilter))
        elif value.lower() not in eval(SoupSearch).string.lower():
            raise ValueError('Value {0} not in {1}'.format(
                value.lower(), eval(SoupSearch).string.lower()))

  def FilterThisHost(self, SoupObj):
    """ 
      Call this to perform filter of a host. Requires soup object ReportHost
    """
    filterstr = "SoupObj.HostProperties.find('tag',attrs={{'name':'{0}'}})"
    if not self.FilterHost: return False
    try:
        for key, value in self.FilterHost.iteritems():
            self.XMLEqualorRaise(SoupObj, key, 'hostIP',
                                 value, filterstr.format('host-ip'))
            self.XMLTagInorRaise(SoupObj, key, 'fqdn',
                                 value, filterstr.format('host-fqdn'))
            self.XMLTagInorRaise(SoupObj, key, 'os_string', value, 
                            filterstr.format('operating-system'))
    except ValueError:
      return True
    else: return False


  def FilterThisVuln(self, SoupObj):
    """
      Call to filter out a particular vulnerability. Send me in a 
    """
    filterstr = "SoupObj['{0}']"
    if not self.FilterVulns: return False
    try:
        for key, value in self.FilterVulns.iteritems():
            self.XMLEqualorRaise(SoupObj, key, 'family', value, 
                                 filterstr.format('pluginFamily'))
            self.XMLEqualIntorRaise(SoupObj, key, 'severityeq', value, 
                                 filterstr.format('severity'))
            self.XMLEqualIntorRaise(SoupObj, key, 'porteq', value, 
                                 filterstr.format('port'))
            self.XMLGTEorRaise(SoupObj, key, 'severitygte', value, 
                                 filterstr.format('severity'))
    except ValueError: return True
    else: return False


  def parse(self):
    """ The main parse method. Need to call me before getting output. """
    self.result_storage = []

    for xml_file in self.xml:
        # read in nesss xml file,  turn into soup obj, and validate
        xml_obj=open(xml_file,'ro')
        xml_parser = BeautifulSoup(xml_obj,'xml')
        self.ValidateXML(xml_parser)

        # iterate through hosts found in report
        for target in xml_parser.find_all('ReportHost'):

          # skip hosts that are caught in the filter
          if self.FilterThisHost(target) == True: continue

          # turn host into a host object
          target_obj = HostObject(target, self.troll_user_check, 
                                  self.troll_link)
          
          # iterate over vulnerabilities of that host
          for vuln in target.find_all('ReportItem'):

              # filter out open ports and insert into HostObject 
              if ( vuln['pluginFamily'] == "Port scanners" 
                  and vuln['severity'] == "0"):
                target_obj.insert_report_item(vuln)

              # if the vulnerability is not filtered, feed into Hostobj
              elif self.FilterThisVuln(vuln) == False:
                target_obj.insert_report_item(vuln)
          # if any vulnerabilities exist in that host, append that to
          # a list of host objects
          if target_obj.vulns: 
              self.result_storage.append(target_obj)

        # demantle parser object, close xml file to free memory
        xml_parser.decompose()
        xml_obj.close()

    # close out the link to the inventory system lookup DB
    self.troll_link.Close()

  def pretty_print(self, show_vulns=True, show_ports=True):
    """ 
      Output affected hosts, including their filtered vulnerabilities. 
      Not very parser friendly though.
    """

    print "Your vuln filters: {0}".format(str(self.FilterVulns))
    print "Your host filters: {0}".format(str(self.FilterHost))

    if not self.result_storage:
      print "No hosts found."
    else:
      print "Hosts found: {0}\n\n".format(len(self.result_storage))

    for host in self.result_storage:
      print "=+"*40
      print ">Host {0}\n>IP {1}\n>OS {2}\n>Mac {3}\n>Owner {4}\n\n".format(
                                                           host.fqdn,
                                                           host.IP,
                                                           host.os,
                                                           host.mac,
                                                           host.owner)
      if show_ports:
        for port in host.ports:
          print " - ".join([port['port'], port['protocol'], port['svc']])
      if show_vulns:
        for vuln in host.vulns:
          print "\t"+"-"*20
          for val, key in vuln.iteritems():
            print "\t{0} - {1}".format(val, key)

  def csv_print_hosts(self):
    """ 
        Ouput affected hosts in CSV format.
    """
    print ",".join(['Host','IP','OS','Mac','Owner'])
    for host in self.result_storage:
      try:
          print ",".join([host.fqdn,host.IP,host.os,host.mac,host.owner])
      except TypeError:
          print "{0} - ERROR".format(host.IP)
