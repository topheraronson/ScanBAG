using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.ComponentModel;

namespace WpfApp1
{
    class QuickSeverity
    {
        private int iSeverity;
        private string sPluginID;
        public string PluginID
        {
            get
            {
                return sPluginID;
            }
        }
        public int Severity
        {
            get
            {
                return iSeverity;
            }
        }
        public QuickSeverity(string PluginID, int Severity)
        {
            sPluginID = PluginID;
            iSeverity = Severity;
        }
        public override bool Equals(object obj)
        {
            if (obj == null) return false;

            QuickSeverity objAsQS = obj as QuickSeverity;
            if (objAsQS == null) return false;

            return (this.PluginID.Equals(objAsQS.PluginID) && this.Severity == objAsQS.Severity);
        }
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }
    class LiveHost
    {
        string sNetworkName;
        string sHostName;
        int iTCP;
        int iUDP;
        int iMaxIssue;
        List<QuickSeverity> lIssues;
        public List<string> PortsDiscovered;

        public LiveHost(string Net, string HostIP)
        {
            sNetworkName = Net;
            sHostName = HostIP;
            iTCP = 0;
            iUDP = 0;
            iMaxIssue = 1;
            lIssues = new List<QuickSeverity>(0);
            PortsDiscovered = new List<string>(0);
        }
        public int MaxIssue
        {
            get
            {
                return iMaxIssue;
            }
        }
        public void DeleteFalsePositives(string PluginID)
        {
            lIssues.RemoveAll(x => x.PluginID.Equals(PluginID));
            if (lIssues.Count > 0)
                iMaxIssue = (from x in lIssues select x.Severity).Max();
            else
                iMaxIssue = 1;

        }
        public void AddIssues(List<QuickSeverity> IssuesTOAdd)
        {
            foreach (QuickSeverity ish in IssuesTOAdd)
                if(!lIssues.Contains(ish))
                    this.AddIssue(ish.PluginID,ish.Severity.ToString());
        }
            public void AddIssue(string PluginID, string Severity)
        {
            switch(Severity)
            {
                case "2":
                    lIssues.Add(new QuickSeverity(PluginID, 2));
                    if (iMaxIssue < 2)
                        iMaxIssue = 2;
                    break;
                case "3":
                    lIssues.Add(new QuickSeverity(PluginID, 3));
                    if (iMaxIssue < 3)
                        iMaxIssue = 3;
                    break;
                case "4":
                    lIssues.Add(new QuickSeverity(PluginID, 4));
                    if (iMaxIssue < 4)
                        iMaxIssue = 4;
                    break;
                case "5":
                    lIssues.Add(new QuickSeverity(PluginID, 5));
                    if (iMaxIssue < 5)
                        iMaxIssue = 5;
                    break;
            }
        }
        public string Network
        {
            get { return sNetworkName; }
        }
        public List<QuickSeverity> Issues
        {
            get { return lIssues; }
        }
        public string Host
        {
            get { return sHostName; }
        }
        public int TCPPortCount
        {
            get { return iTCP; }
        }
        public int UDPPortCount
        {
            get { return iUDP; }
        }
        public void AddTCP()
        {
            iTCP++;
        }
        public void AddTCP(int x)
        {
            iTCP = iTCP + x;
        }
        public void AddUDP()
        {
            iUDP++;
        }
        public void AddUDP(int x)
        {
            iUDP = iUDP + x;
        }
        public override bool Equals(object obj)
        {
            if (obj == null) return false;

            LiveHost objAsLH = obj as LiveHost;
            if (objAsLH == null) return false;

            return (this.Host.Equals(objAsLH.Host) && this.Network.Equals(objAsLH.Network));
        }
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }
    }
    class NessusFinding
    {
        private string sPluginID;
        private string sCVE;
        private string sCVSS;
        private string sRisk;
        private string sHost;
        private string sProtocol;
        private string sPort;
        private string sFindingName;
        private string sSynopsis;
        private string sDescription;
        private string sSolution;
        private string sSeeAlso;
        private string sPluginOutput;
        private string sCVSSVector;
        private string sVulnPubDate;
        private string sNetworkName;

        public NessusFinding(string Network, string PluginID, string CVE, string CVSSScore, string Risk, string Host, string Protocol, string Port, string FindingName, string Synopsis, string Description, string Solution, string SeeAlso, string PluginOutput, string CVSSVector, string VulnPubDate)
        {
            sNetworkName = Network?.Trim() ?? "default";

            switch (Risk.Trim()) { 
                case "Critical":
                    sRisk = "5 - Critical";
                    break;
                case "High":
                    sRisk = "4 - High";
                    break;
                case "Medium":
                    sRisk = "3 - Medium";
                    break;
                case "Low":
                    sRisk = "2 - Low";
                    break;
                case "None":
                    sRisk = "1 - Info";
                    break;
                default:
                    throw new Exception("The risk is not standard. Value is: " + Risk.Trim());
            }
            sPluginID = PluginID.Trim();
            sDescription = Description.Trim();
            sHost = Host.Trim();
            sProtocol = Protocol.Trim();
            sPort = Port.Trim();
            sFindingName = FindingName.Trim();

            sSynopsis = Synopsis?.Trim() ?? "";
            sCVE = CVE?.Trim() ?? "";
            sCVSS = CVSSScore?.Trim() ?? "";
            sSolution = Solution?.Trim() ?? "";
            sSeeAlso = SeeAlso?.Trim() ?? "";
            sPluginOutput = PluginOutput?.Trim() ?? "";
            sCVSSVector = CVSSVector?.Trim() ?? "";
            sVulnPubDate = VulnPubDate?.Trim() ?? "";
        }
        public bool FalsePositive
        {
            get; set;
        }
        public string NetworkName
        {
            get { return sNetworkName; }
        }
        public string PluginID
        {
            get { return sPluginID; }
        }
        public string CVE
        {
            get { return sCVE; }
        }
        public string CVSS
        {
            get { return sCVSS; }
        }
        public string Risk
        {
            get { return sRisk; }
        }
        public string Host
        {
            get { return sHost; }
        }
        public string Protocol
        {
            get { return sProtocol; }
        }
        public string Port
        {
            get { return sPort; }
        }
        public string FindingName
        {
            get { return sFindingName; }
        }
        public string Synopsis
        {
            get { return sSynopsis; }
        }
        public string Description
        {
            get { return sDescription; }
        }
        public string Solution
        {
            get { return sSolution; }
        }
        public string SeeAlso
        {
            get { return sSeeAlso; }
        }
        public string PluginOutput
        {
            get { return sPluginOutput; }
        }
        public string CVSSVector
        {
            get { return sCVSSVector; }
        }
        public string VulnPubDate
        {
            get { return sVulnPubDate; }
        }
    }
    class NetworkIssue : INotifyPropertyChanged
    {
        private string sPluginID;
        private string sCVSS;
        private string sRisk;
        private string sFindingName;
        private string sNetworkName;
        private bool bFalsePositive;

        public event PropertyChangedEventHandler PropertyChanged;

        private void NotifyPropertyChanged(String propertyName = "")
        {
            if(propertyName.Equals("FalsePositive"))
            {
                
            }
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }


        public NetworkIssue(string Network, string PluginID, string CVSSScore, string Risk, string FindingName, bool FalsePos)
        {
            sNetworkName = Network?.Trim() ?? "default";
            sRisk = Risk.Trim();
            sPluginID = PluginID.Trim();
            sFindingName = FindingName.Trim();
            sCVSS = CVSSScore?.Trim() ?? "";
            bFalsePositive = FalsePos;
        }
        public bool FalsePositive
        {
            get { return bFalsePositive; }
            set
            {
                bFalsePositive = value;
                NotifyPropertyChanged("FalsePositve");
            }
        }
        public string NetworkName
        {
            get { return sNetworkName; }
        }
        public string PluginID
        {
            get { return sPluginID; }
        }
        
        public string CVSS
        {
            get { return sCVSS; }
        }
        public string Risk
        {
            get { return sRisk; }
        }
        public string FindingName
        {
            get { return sFindingName; }
        }
    }

    class LoadNessusScanFiles
    {
        public List<NessusFinding> PreparedIndividualFindingsList = new List<NessusFinding>(0);
        public List<LiveHost> LiveHosts = new List<LiveHost>(0);
        public List<BugReport> BugReportList = new List<BugReport>(0);

        public List<NetworkIssue> Go(List<ScanFile> FilesToLoad)
        {
            List<NetworkIssue> NetworkIssueList = new List<NetworkIssue>(0);

            foreach (ScanFile sf in FilesToLoad)
            {
                XDocument xmlScanFile = XDocument.Load(sf.ScanFileWholePathName);
                // Query the data and write out a subset of contacts
                IEnumerable<string> ScannedHosts = from scan in xmlScanFile.Root.Descendants("ReportHost") select scan.Attribute("name").Value;

                foreach (string host in ScannedHosts)
                {
                    Console.WriteLine("Host Name: {0}", host);
                    IEnumerable<IEnumerable<XElement>> HostFindings = from HostResult in xmlScanFile.Root.Descendants("ReportHost") where HostResult.Attribute("name").Value == host select HostResult.Elements("ReportItem");
                    
                    int TCPCOunt = (from TCPPorts in HostFindings.ElementAt(0)
                                    where (string)TCPPorts.Attribute("protocol").Value.Trim() == "tcp"
                                    && (string)TCPPorts.Attribute("port").Value.Trim() != "0"
                                    && TCPPorts.Attribute("port").Value.Trim() != ""
                                    select TCPPorts).Count();
                    int UDPCOunt = (from UDPPorts in HostFindings.ElementAt(0)
                                    where (string)UDPPorts.Attribute("protocol") == "udp"
                                    && (string)UDPPorts.Attribute("port") != "0"
                                    && UDPPorts.Attribute("port").Value.Trim() != ""
                                    select UDPPorts).Count();

                    LiveHost lh = null; ;
                    if (TCPCOunt > 0 || UDPCOunt > 0)
                        if (TCPCOunt < 65535 && UDPCOunt < 65535)
                        {
                            lh = new LiveHost(sf.ScanFileNetworkName, host);
                        }
                    foreach (XElement finding in HostFindings.ElementAt(0))
                    {
                        string a = sf.ScanFileNetworkName;
                        string b = finding.Attribute("pluginID").Value;
                        string c = finding.Element("cve")?.Value;
                        string d = finding.Element("cvss_base_score")?.Value;
                        string e = finding.Element("risk_factor").Value;
                        string f = host;
                        string g = finding.Attribute("protocol").Value;
                        string h = finding.Attribute("port").Value;
                        string i = finding.Attribute("pluginName").Value;
                        string j = finding.Element("synopsis")?.Value;
                        string k = finding.Element("description").Value;
                        string l = finding.Element("solution")?.Value;
                        string m = finding.Element("see_also")?.Value;
                        string n = finding.Element("plugin_output")?.Value;
                        string o = finding.Element("cvss_vector")?.Value;
                        string p = finding.Element("vuln_publication_date")?.Value;
                        NessusFinding nf = new NessusFinding(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p);
                        nf.FalsePositive = false;
                        PreparedIndividualFindingsList.Add(nf);
                        if (lh != null)
                        {
                            if(!h.Equals("0"))
                            { 
                                if(!lh.PortsDiscovered.Contains(String.Format("{0}:{1}",g, h)))
                                    lh.PortsDiscovered.Add(String.Format("{0}:{1}",g,h));
                            }
                            if (nf.Risk.Equals("1 - Info") || !nf.CVSS.Equals(""))
                                lh.AddIssue(b, nf.Risk.Substring(0, 1));
                        }
                    }
                    if (lh != null)
                    {
                        if (!LiveHosts.Contains(lh))
                            LiveHosts.Add(lh);
                        else
                            LiveHosts[LiveHosts.IndexOf(lh)].AddIssues(lh.Issues); 
                    }
                }
            }
            //HERE
            foreach (LiveHost zz in LiveHosts)
            {
                foreach (string pp in zz.PortsDiscovered)
                {
                    Console.WriteLine("{0} - {1} - {2}", zz.Network, zz.Host, pp);
                }
            }
            foreach (NessusFinding nf in PreparedIndividualFindingsList)
            {
                if (nf.Risk.Equals("1 - Info"))
                    continue;
                if (nf.CVSS.Equals(""))
                    continue;
                if (nf.FalsePositive)
                    continue;

                int MatchingIndex = NetworkIssueList.FindIndex(x => x.PluginID.Equals(nf.PluginID) && x.CVSS.Equals(nf.CVSS) && x.NetworkName.Equals(nf.NetworkName));
                if (MatchingIndex == -1)
                {
                    //Add a new network issue
                    NetworkIssueList.Add(new NetworkIssue(nf.NetworkName, nf.PluginID, nf.CVSS, nf.Risk, nf.FindingName,nf.FalsePositive));
                }
            }
            return NetworkIssueList;
        }
        public List<BugReport> GenerateBugs()
        {
            //List<BugReport> BugList = new List<BugReport>(0);
            foreach (NessusFinding nf in PreparedIndividualFindingsList)
            {
                if (nf.Risk.Equals("1 - Info"))
                    continue;
                if (nf.CVSS.Equals(""))
                    continue;
                if (nf.FalsePositive)
                    continue;

                int MatchingIndex = BugReportList.FindIndex(x => x.PluginID.Equals(nf.PluginID) && x.CVSS_Score.Equals(nf.CVSS));
                if (MatchingIndex == -1)
                {
                    //Add a new bug report for the pluginID
                    BugReportList.Add(new BugReport(nf.FindingName, nf.Risk, nf.CVSS, nf.Synopsis, nf.Description, nf.Solution, nf.Host, nf.Protocol, nf.Port, nf.SeeAlso, nf.CVE, nf.PluginID, nf.PluginOutput, nf.NetworkName,nf.CVSSVector));
                }
                else
                {
                    BugReportList[MatchingIndex].AddInstanceToBugReport(nf.Host, nf.Protocol, nf.Port, nf.CVE, nf.PluginOutput, nf.NetworkName);
                }
            }
            return BugReportList;
        }
    }
}
