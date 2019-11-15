using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
//using Microsoft.Win32;
using System.Windows.Forms;
using System.IO;
using System.Collections.ObjectModel;

namespace WpfApp1
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private ObservableCollection<ScanFile> ScanFileCollection { get; set; }
        private ObservableCollection<NetworkIssue> NetworkIssueCollection { get; set; }
        private ObservableCollection<BugReport> BugReportCollection { get; }
        private LoadNessusScanFiles Loader;
        public MainWindow()
        {
            InitializeComponent();
            ScanFileCollection = new ObservableCollection<ScanFile>();
            NetworkIssueCollection = new ObservableCollection<NetworkIssue>();
            BugReportCollection = new ObservableCollection<BugReport>();
            Loader = new LoadNessusScanFiles();

        }
        private void Button_Generate_Click(object sender, RoutedEventArgs e)
        {
            this.btnGenerate.IsEnabled = false;
            WriteNessusBugs oWNB = new WriteNessusBugs(Loader.BugReportList); //HERE maybe we didn't update the list to match the false positives?
            oWNB.WriteEm(this.tbFile.Text);
            this.btnGenerate.IsEnabled = true;
        }
        private void Button_Browse_SelectFile_Click(object sender, RoutedEventArgs e)
        {
            // Create File
            SaveFileDialog dlg = new SaveFileDialog();
            dlg.DefaultExt = ".docx";
            dlg.InitialDirectory = Environment.CurrentDirectory;
            dlg.AddExtension = true;
            dlg.Filter = "Word (*.docx)|*.docx";
            dlg.ValidateNames = true;
            dlg.Title = "Bug File";
            dlg.RestoreDirectory = true;            

            // Get the selected file name and display in a TextBox 
            if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                // Open document 
                string filename = dlg.FileName;
                tbFile.Text = filename;
            }
            dlg.Dispose();
            this.btnGenerate.IsEnabled = true;
        }
        private void Button_Browse_SelectDirectory_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.InitialDirectory = Environment.CurrentDirectory;
            ofd.DefaultExt = ".nessus";
            ofd.Filter = "Nessus Files (*.nessus)|*.nessus";            
            DialogResult result = ofd.ShowDialog();
            string[] files = new string[0];
            if (result == System.Windows.Forms.DialogResult.OK && !string.IsNullOrWhiteSpace(ofd.FileName))
            {
                tbDirectory.Text = new FileInfo(ofd.FileName).DirectoryName;
                files = Directory.GetFiles(tbDirectory.Text, "*.nessus");
            }            
            ofd.Dispose();

            foreach (string file in files)
            {
                if (ScanFileCollection.Where(sf => sf.ScanFileWholePathName.Equals(file)).Count() == 0)
                {
                    ScanFileCollection.Add(new ScanFile(file));
                    this.dgIncludedScanFiles.ItemsSource = ScanFileCollection;
                    this.btnProcess.IsEnabled = true;
                }
                //dgIncludedScanFiles.Items.Add(new ScanFile(System.IO.Path.GetFileName(file)));
            }
            this.dgIncludedScanFiles.IsEnabled = true;
        }

        private void Button_ProcessFiles_Click(object sender, RoutedEventArgs e)
        {
            this.dgIncludedScanFiles.IsEnabled = false;
            this.tabLoadFiles.IsEnabled = false;
            this.tabReview.IsSelected = true;
            List<ScanFile> filestoload = new List<ScanFile>();
            foreach (ScanFile sf in ScanFileCollection.ToList<ScanFile>())
            {
                //tbDirectory.Text = sf.ScanFileNetworkName + " " + sf.ScanFileName + " " + sf.ScanFileIncluded.ToString();
                if (!sf.ScanFileIncluded)
                {
                    ScanFileCollection.Remove(sf);
                }
                else
                {
                    filestoload.Add(sf);
                }
            }
            List<NetworkIssue> NetworkIssues = Loader.Go(filestoload);
            foreach (NetworkIssue ni in NetworkIssues.OrderBy(x => x.NetworkName).ThenByDescending(x => Decimal.Parse(x.CVSS)))
                NetworkIssueCollection.Add(ni);
            this.dgReviewBugs.ItemsSource = NetworkIssueCollection;
            this.tabReview.IsEnabled = true;
        }

        private void Button_CompleteReview_Click(object sender, RoutedEventArgs e)
        {
            this.tabGenBugs.IsEnabled = true;
            this.tabReview.IsEnabled = false;
            this.tabGenBugs.IsSelected = true;
            this.dgBugs.ItemsSource = null;
            foreach (BugReport x in BugReportCollection)
            {
                BugReportCollection.Remove(x);
            }
            foreach (BugReport br in Loader.GenerateBugs())
            {
                if (!BugReportCollection.Contains(br))
                    BugReportCollection.Add(br);
            }            
            this.dgBugs.ItemsSource = BugReportCollection.OrderByDescending(x => Decimal.Parse(x.CVSS_Score)).ThenBy(x => x.Title);
            GenStats();
        }

        private void GenStats()
        {
            Console.WriteLine("Total Live Hosts: {0}", Loader.LiveHosts.Count());
            Console.WriteLine("Critical Hosts: {0}", Loader.LiveHosts.Where(x => x.MaxIssue == 5).Count());
            Console.WriteLine("High Hosts: {0}", Loader.LiveHosts.Where(x => x.MaxIssue == 4).Count());
            Console.WriteLine("Medium Hosts: {0}", Loader.LiveHosts.Where(x => x.MaxIssue == 3).Count());
            Console.WriteLine("Low Hosts: {0}", Loader.LiveHosts.Where(x => x.MaxIssue == 2).Count());
            Console.WriteLine("Info Hosts: {0}", Loader.LiveHosts.Where(x => x.MaxIssue == 1).Count());

            //Get Networks
            foreach (string Net in Loader.LiveHosts.Select(o => o.Network).Distinct())
            {
                Console.WriteLine("{1} Live Hosts: {0}", Loader.LiveHosts.Where(x => x.Network.Equals(Net)).Count(), Net);
                Console.WriteLine("{1} Critical Hosts: {0}", Loader.LiveHosts.Where(x => x.MaxIssue == 5 && x.Network.Equals(Net)).Count(), Net);
                Console.WriteLine("{1} High Hosts: {0}", Loader.LiveHosts.Where(x => x.MaxIssue == 4 && x.Network.Equals(Net)).Count(), Net);
                Console.WriteLine("{1} Medium Hosts: {0}", Loader.LiveHosts.Where(x => x.MaxIssue == 3 && x.Network.Equals(Net)).Count(), Net);
                Console.WriteLine("{1} Low Hosts: {0}", Loader.LiveHosts.Where(x => x.MaxIssue == 2 && x.Network.Equals(Net)).Count(), Net);
                Console.WriteLine("{1} Info Hosts: {0}", Loader.LiveHosts.Where(x => x.MaxIssue == 1 && x.Network.Equals(Net)).Count(), Net);
            }
        }

        private void FalsePosiviteClicked(object sender, RoutedEventArgs e)
        {
            //this.btnCompleteReview.IsEnabled = true;
            NetworkIssue ni = ((System.Windows.Controls.CheckBox)sender).BindingGroup.Items[0] as NetworkIssue;
            foreach (NessusFinding nf in Loader.PreparedIndividualFindingsList)
            {
                if (ni.PluginID.Equals(nf.PluginID)
                    && ni.NetworkName.Equals(nf.NetworkName)
                    && ni.CVSS.Equals(nf.CVSS))
                    nf.FalsePositive = ni.FalsePositive;
            }
            foreach (LiveHost lh in Loader.LiveHosts.Where(x => x.Network.Equals(ni.NetworkName)))
            {
                Loader.LiveHosts[Loader.LiveHosts.IndexOf(lh)].DeleteFalsePositives(ni.PluginID);
            }
        }
    }
    /*public class PercentageConverter : IValueConverter
    {
        public object Convert(object value,
            Type targetType,
            object parameter,
            System.Globalization.CultureInfo culture)
        {
            return System.Convert.ToDouble(value) *
                   System.Convert.ToDouble(parameter);
        }

        public object ConvertBack(object value,
            Type targetType,
            object parameter,
            System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }*/
    public class ScanFile
    {
        public ScanFile(string File)
        {
            ScanFileWholePathName = File;
            ScanFileName = System.IO.Path.GetFileName(File);
            ScanFileIncluded = true;
            ScanFileNetworkName = "Default";
        }
        public string ScanFileNetworkName { get; set; }
        public string ScanFileName { get; }
        public bool ScanFileIncluded { get; set; }
        public string ScanFileWholePathName { get; set; }
    }
}
