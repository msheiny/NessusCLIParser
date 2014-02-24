#!/usr/bin/env python2
#
#
# Some unit tests to be run against a sample Nessus XML file 
#   ./tests/example.xml 

import unittest
import os
import sys
from bs4 import BeautifulSoup
sys.path.append('./usr/local/NessusPy')
import NessusAnalysis

tests_folder = os.path.join(os.path.dirname(os.path.realpath(__file__)), 
                           'tests/')

class test_NessusXMLParser(unittest.TestCase):
    
    @classmethod
    def setUpClass(self):
        example_file = os.path.join(tests_folder,'example.xml')
        self.parser = NessusAnalysis.NessusXMLParser(example_file,  
                                                     troll_check=False)
        example_txt = """<ReportHost name="10.10.10.2"><HostProperties>
<tag name="HOST_END">Fri Sep  6 15:20:08 2013</tag>
<tag name="patch-summary-total-cves"">4</tag>
<tag name="mac-address">00:04:76:21:32:c9</tag>
<tag name="traceroute-hop-0">10.10.10.2</tag>
<tag name="host-ip">10.10.10.2</tag>
<tag name="host-fqdn">PPT1.PRIVATE.EDU</tag>
<tag name="HOST_START">Fri Sep  6 15:17:49 2013</tag>
</HostProperties></ReportHost> """
        self.ex_soup = BeautifulSoup(example_txt,'xml') 

        for severity_lvl in ['1','2','3','4']:
            exec("self.soup_vuln{0} = BeautifulSoup(open(os.path.join(tests_folder,'example_vuln{0}.xml')),'xml')".format(severity_lvl))

    @classmethod
    def tearDown(self):
        self.parser.FilterHostAttrs()
        self.parser.FilterVulnAttrs()

    def test_TrollQuery(self):
        """ Test the link to troll. Ensure that Mike Sheinbergs system matches 'msheiny' in the Troll database """
        try:
            mysql_credentials = './refsys-root/usr/local/NessusPy/mysql.txt'
            example_file = os.path.join(tests_folder,'msheiny.xml')

            open(mysql_credentials,'ro').close()
            open(example_file,'ro').close()
                        
            self.parser = NessusAnalysis.NessusXMLParser(example_file,
                                                         troll_check=True)
            self.parser.parse()

            msheinySystem = self.parser.result_storage[0]
            self.assertEquals(msheinySystem.owner,'msheiny')

        except IOError as e:
            print ("Some troll relatd files were missing:\n{0}".format(e))

    def testFilterWrongHostIP(self):
        """ Unit test for negative match FilterThisHost class method"""
        self.parser.FilterHostAttrs(hostIP='10.10.10.3')
        self.assertTrue(self.parser.FilterThisHost(
                        self.ex_soup))

    def testFilterSameHostIP(self):
        """ Unit test for matching FilterThisHost class method"""
        self.parser.FilterHostAttrs(hostIP='10.10.10.2')
        self.assertFalse(self.parser.FilterThisHost(
                        self.ex_soup))

    def testFilterSameFQDN(self):
        """ Unit test for matching FilterThisHost class method domain 
            names"""
        self.parser.FilterHostAttrs(fqdn='ppt1.private.edu')
        self.assertFalse(self.parser.FilterThisHost(
                        self.ex_soup))

    def testFilterWrongFQDN(self):
        self.parser.FilterHostAttrs(fqdn='whatever.com')
        self.assertTrue(self.parser.FilterThisHost(
                        self.ex_soup))

    def testVulnerabilityEqAllowed(self):
        self.parser.FilterVulnAttrs(severityeq=3)
        test = self.soup_vuln3.find('ReportItem')
        self.assertFalse(self.parser.FilterThisVuln(test))

    def testVulnerabilityEqBlocked(self):
        self.parser.FilterVulnAttrs(severityeq=3)
        test = self.soup_vuln2.find('ReportItem')
        self.assertTrue(self.parser.FilterThisVuln(test))

    def testVulnerabilityEqPlus4Allowed(self):
        self.parser.FilterVulnAttrs(severitygte=3)
        test = self.soup_vuln4.find('ReportItem')
        self.assertFalse(self.parser.FilterThisVuln(test))

    def testVulnerabilityEqPlus4Blocked(self):
        self.parser.FilterVulnAttrs(severitygte=3)
        test = self.soup_vuln2.find('ReportItem')
        self.assertTrue(self.parser.FilterThisVuln(test))

    def testFound_Any_Vuln_hosts(self):
        self.parser.parse()
        self.assertTrue(self.parser.result_storage)

    def testPortFilter(self):
        sheiny_file = os.path.join(tests_folder,'msheiny.xml')
        sheiny_parse = NessusAnalysis.NessusXMLParser(sheiny_file,
                                                         troll_check=True)
        sheiny_parse.FilterVulnAttrs(porteq=22)
        sheiny_parse.parse()
        self.assertEquals(len(sheiny_parse.result_storage), 1 )

        self.parser.FilterVulnAttrs(porteq=3389)
        self.parser.parse()
        self.assertEquals(len(self.parser.result_storage), 77 )

    def testFound_326_Vuln_hosts(self):
        self.parser.parse()
        self.assertEquals(len(self.parser.result_storage), 326)

    def testFound_3_Level4s(self):
        self.parser.FilterVulnAttrs(severityeq=4)
        self.parser.parse()
        self.assertEquals(len(self.parser.result_storage), 3)

if __name__ == '__main__':
    unittest.main()
