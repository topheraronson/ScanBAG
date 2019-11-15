using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WpfApp1
{
    class AffectedHost
    {
        string sport, sip, sproto, snetwork;

        public AffectedHost(string port, string ip, string proto, string net)
        {
            sport = port;
            sip = ip;
            sproto = proto;
            snetwork = net;
        }
        public override bool Equals(object obj)
        {
            if (obj == null) return false;

            AffectedHost objAsAH = obj as AffectedHost;
            if (objAsAH == null) return false;
            
            return (this.Port.Equals(objAsAH.Port) && this.HostIPAddress.Equals(objAsAH.HostIPAddress) && this.Protocol.Equals(objAsAH.Protocol) && this.Network.Equals(objAsAH.Network));
        }
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public string Network
        {
            get
            {
                return snetwork.Trim();
            }
        }

        public string Port
        {
            get
            {
                return sport.Trim();
            }
        }
        public string HostIPAddress
        {
            get
            {
                return sip.Trim();
            }
        }
        public string Protocol
        {
            get
            {
                return sproto.Trim().ToUpper();
            }
        }
    }

    class BugReport
    {
        private string sVulnName, sRisk, sCVSS, sCVSSVector, sSynopsis, sVulnDescr, sSolution, sSeeAlso, sPluginID;
        private List<AffectedHost> AffectedHostList;
        private List<string> PluginOutputList;
        private List<string> CVEList;

        public BugReport(string VulnName, string risk, string CVSS, string Synopsis, string VulnDescr, string Solution, string Host, string Protocol, string Port, string SeeAlso, string CVE, string PluginID, string PluginOutput, string Network, string inCVSS_Vector)
        {
            AffectedHostList = new List<AffectedHost>(0);
            PluginOutputList = new List<string>(0);
            CVEList = new List<string>(0);
            sVulnName = VulnName;
            sRisk = risk;
            sCVSS = CVSS;
            sCVSSVector = inCVSS_Vector;
            sSynopsis = Synopsis;
            sVulnDescr = VulnDescr;
            sSolution = Solution;
            AffectedHostList.Add(new AffectedHost(Port, Host, Protocol, Network));
            sSeeAlso = SeeAlso;
            if(!String.IsNullOrEmpty(CVE.Trim()))
                CVEList.Add(CVE);
            sPluginID = PluginID;
            if (!String.IsNullOrEmpty(PluginOutput.Trim()))
                PluginOutputList.Add(PluginOutput);
        }

        public void AddInstanceToBugReport(string Host, string Protocol, string Port, string CVE, string PluginOutput, string Network)
        {
            AffectedHost x = new AffectedHost(Port, Host, Protocol, Network);
            if (!AffectedHostList.Contains(x))
                AffectedHostList.Add(x);
            if (!CVEList.Contains(CVE) && !String.IsNullOrEmpty(CVE.Trim()))
                CVEList.Add(CVE);
            if (!PluginOutputList.Contains(PluginOutput) && !String.IsNullOrEmpty(PluginOutput.Trim()))
                PluginOutputList.Add(PluginOutput);
        }

        public override bool Equals(object obj)
        {
            if (obj == null) return false;

            BugReport objAsBR = obj as BugReport;
            if (objAsBR == null) return false;

            return (this.CVSS_Score.Equals(objAsBR.CVSS_Score) && this.PluginID.Equals(objAsBR.PluginID));
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public string Title
        {
            get
            {
                return sVulnName;
            }
        }
        public string Severity
        {
            get
            {
                return sRisk;
            }
        }
        public string CVSS_Score
        {
            get
            {
                return sCVSS;
            }
        }
        public string CVSS_Vector
        {
            get
            {
                return sCVSSVector;
            }
        }
        public string Summary
        {
            get
            {
                return sVulnDescr;
            }
        }
        public string Impact
        {
            get
            {
                return sSynopsis;
            }
        }
        public string Recommendation
        {
            get
            {
                return sSolution;
            }
        }
        public string Reference
        {
            get
            {
                return sSeeAlso;
            }
        }
        public List<string> CVEs
        {
            get
            {
                return CVEList;
            }
        }
        public string PluginID
        {
            get
            {
                return sPluginID;
            }
        }
        public List<string> PluginOutput
        {
            get
            {
                return PluginOutputList;
            }
        }
        public List<AffectedHost> HostInfo
        {
            get
            {
                return AffectedHostList;
            }
        }       
    }
}
