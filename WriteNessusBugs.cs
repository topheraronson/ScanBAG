using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Word = Microsoft.Office.Interop.Word;
using System.IO;
//using System.Windows.Media;
using System.Drawing;

namespace WpfApp1
{
    class WriteNessusBugs
    {
        private List<BugReport> bugs;
        private Word._Application oWord;
        private object oMissing = System.Reflection.Missing.Value;
        //private object oEndOfDoc = "\\endofdoc";
        //private object oStartOfDoc = "\\beginofdoc";
        private Word.Document wdEmptyBugTable;
        private Word.Range oRangeEmptyBugTable;

        public WriteNessusBugs(List<BugReport> bugsToWrite)
        {
            bugs = bugsToWrite.OrderByDescending(x => Decimal.Parse(x.CVSS_Score)).ThenBy(x => x.Title).ToList();
        }
        private string CombineReferenceandCVEs(string Reference, List<string> CVEs)
        {
            StringBuilder sb = new StringBuilder(Reference);            

            if (CVEs.Count > 0)
            {
                if(!String.IsNullOrEmpty(Reference.Trim()))
                    sb.Append("\v\v");
                sb.Append("Associated CVE:\v");
                foreach(string CVE in CVEs)
                {
                    sb.Append(CVE);
                    sb.Append('\v');
                }
            }
            return sb.ToString();
        }
        private string FlattenPluginPOutput(List<string> PluginOuts)
        {
            StringBuilder sb = new StringBuilder();
            if (PluginOuts.Count > 0)
            {
                sb.Append("Plugin Output:");                
                foreach (string plop in PluginOuts)
                {
                    sb.Append('\v');
                    sb.Append(plop);
                    sb.Append('\v');
                }
            }
            string x = sb.ToString().Replace('\n','\v').Replace("\r","");
            //Console.Write(x);
            return sb.ToString();
        }
        private void GetAffectedTable(List<AffectedHost> listAffectedHosts, Word.Range wrdRng)
        {
            //Word._Document oDoc;            
            //oDoc = oWord.Documents.Add(ref oMissing, ref oMissing, ref oMissing, ref oMissing);
            //Word.Range wrdRng = oDoc.Bookmarks.get_Item(ref oEndOfDoc).Range;
            Word.Table oTable;
            oTable = wrdRng.Tables.Add(wrdRng, 1, 4, Word.WdDefaultTableBehavior.wdWord9TableBehavior, Word.WdAutoFitBehavior.wdAutoFitContent);
            oTable.Range.ParagraphFormat.SpaceAfter = 0;
            oTable.Range.ParagraphFormat.SpaceBefore = 0;
            oTable.Cell(1, 1).Range.Text = "Network";
            oTable.Cell(1, 2).Range.Text = "Host";
            oTable.Cell(1, 3).Range.Text = "Port";
            oTable.Cell(1, 4).Range.Text = "Protocol";
            oTable.Rows[1].Range.ParagraphFormat.Alignment = Word.WdParagraphAlignment.wdAlignParagraphCenter;
            oTable.Rows[1].Range.Cells.VerticalAlignment = Word.WdCellVerticalAlignment.wdCellAlignVerticalCenter;
            oTable.Rows[1].Range.Font.Bold = 1;
            oTable.Rows[1].Range.Font.Color = Word.WdColor.wdColorWhite;
            oTable.Rows[1].Range.Shading.BackgroundPatternColor = (Word.WdColor)ColorTranslator.ToOle(Color.FromArgb(0x788BBB2E));
            //oTable.ApplyStyleHeadingRows = true;
            int iRow = 1;

            foreach (AffectedHost af in listAffectedHosts)
            {
                oTable.Rows.Add(ref oMissing);
                iRow++;
                oTable.Rows[iRow].Range.Font.Color = (Word.WdColor)ColorTranslator.ToOle(Color.FromArgb(0x5D6062));
                oTable.Rows[iRow].Range.Shading.BackgroundPatternColor = Word.WdColor.wdColorWhite;
                oTable.Rows[iRow].Range.Font.Bold = 0;
                oTable.Rows[iRow].Range.ParagraphFormat.Alignment = Word.WdParagraphAlignment.wdAlignParagraphLeft;

                oTable.Cell(iRow, 1).Range.Text = af.Network;
                oTable.Cell(iRow, 2).Range.Text = af.HostIPAddress;
                oTable.Cell(iRow, 3).Range.Text = af.Port;
                oTable.Cell(iRow, 4).Range.Text = af.Protocol;
            }

            //return oTable;
            /*Add some text after the table.
            Word.Paragraph oPara4;
            oRng = oDoc.Bookmarks.get_Item(ref oEndOfDoc).Range;
            oPara4 = oDoc.Content.Paragraphs.Add(ref oRng);
            oPara4.Range.InsertParagraphBefore();
            oPara4.Range.Text = "And here's another table:";
            oPara4.Format.SpaceAfter = 24;
            oPara4.Range.InsertParagraphAfter();
            */
        }
        private void ReplaceTagWithContent(Word.Document editDoc, string Tag, string newValue)
        {
            //UTF8Encoding utf8 = new ();
            //newValue = Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(newValue));
            //newValue = newValue.Replace((char)1310, '!');

            Word.Range rangeToEdit = editDoc.Content;
            newValue = newValue.Replace('\n', '\v').Replace("\r", "");
            newValue = newValue.Replace("^", "");
            rangeToEdit.Find.ClearFormatting();
            if (newValue.Length > 255)
            {
                ReplaceTagWithContent(editDoc, Tag, Tag + newValue.Substring(255));
                newValue = newValue.Substring(0, 255);
            }
            bool result = rangeToEdit.Find.Execute(MatchCase: true, FindText: Tag, ReplaceWith: newValue, Replace: Word.WdReplace.wdReplaceOne);
        }
        public bool WriteEm(string FilePath)
        {
            oWord = new Word.Application();
            oWord.Visible = true;
            bool bRet = false;
            wdEmptyBugTable = oWord.Documents.Open(Path.Combine(Environment.CurrentDirectory, "autoNessus.docx"));
            oRangeEmptyBugTable = wdEmptyBugTable.Content;

            Word.Document wdOutputBugFile = oWord.Documents.Add();
            // the table of bugs
            Word.Table oTable;
            oTable = wdOutputBugFile.Tables.Add(wdOutputBugFile.Content, 1, 2, Word.WdDefaultTableBehavior.wdWord9TableBehavior, Word.WdAutoFitBehavior.wdAutoFitContent);
            oTable.Range.ParagraphFormat.SpaceAfter = 0;
            oTable.Range.ParagraphFormat.SpaceBefore = 0;
            oTable.Cell(1, 1).Range.Text = "CVSS";
            oTable.Cell(1, 2).Range.Text = "Title";           
            oTable.Rows[1].Range.ParagraphFormat.Alignment = Word.WdParagraphAlignment.wdAlignParagraphCenter;
            oTable.Rows[1].Range.Cells.VerticalAlignment = Word.WdCellVerticalAlignment.wdCellAlignVerticalCenter;
            oTable.Rows[1].Range.Font.Bold = 1;
            oTable.Rows[1].Range.Font.Color = Word.WdColor.wdColorWhite;
            oTable.Rows[1].Range.Shading.BackgroundPatternColor = (Word.WdColor)ColorTranslator.ToOle(Color.FromArgb(0x788BBB2E));
            //oTable.ApplyStyleHeadingRows = true;
            int iRow = 1;

            foreach (BugReport bug in bugs)
            {
                oTable.Rows.Add(ref oMissing);
                iRow++;
                oTable.Rows[iRow].Range.Font.Color = (Word.WdColor)ColorTranslator.ToOle(Color.FromArgb(0x5D6062));
                oTable.Rows[iRow].Range.Shading.BackgroundPatternColor = Word.WdColor.wdColorWhite;
                oTable.Rows[iRow].Range.Font.Bold = 0;
                oTable.Rows[iRow].Range.ParagraphFormat.Alignment = Word.WdParagraphAlignment.wdAlignParagraphLeft;

                oTable.Cell(iRow, 1).Range.Text = bug.CVSS_Score;
                oTable.Cell(iRow, 2).Range.Text = bug.Title;
            }

            Word.Document editBugDoc = oWord.Documents.Add();

            foreach (BugReport bug in bugs)
            {
                editBugDoc.Content.Delete();
                //oRangeEmptyBugTable.w
                oRangeEmptyBugTable.Copy();
                editBugDoc.Content.Paste(); // Special(DataType: Word.WdPasteOptions.wdKeepSourceFormatting);
                
                //Now we have the bug in a doc to edit so fill it in
                ReplaceTagWithContent(editBugDoc, "|TITLE|", bug.Title);
                ReplaceTagWithContent(editBugDoc, "|ID|", bug.PluginID);
                ReplaceTagWithContent(editBugDoc, "|SEVERITY|", bug.Severity);
                ReplaceTagWithContent(editBugDoc, "|CAT|", "Nessus Vulnerability");
                ReplaceTagWithContent(editBugDoc, "|SCORE|", bug.CVSS_Score);
                ReplaceTagWithContent(editBugDoc, "|VECTOR|", bug.CVSS_Vector);
                ReplaceTagWithContent(editBugDoc, "|SUMMARY|", bug.Summary);
                ReplaceTagWithContent(editBugDoc, "|IMPACT|", bug.Impact);
                ReplaceTagWithContent(editBugDoc, "|REPRO|", "Nessus Scan"); //HERE perhaps the scan details should be in here (date, source IP, scan type)
                ReplaceTagWithContent(editBugDoc, "|REC|", bug.Recommendation);
                ReplaceTagWithContent(editBugDoc, "|REF|", this.CombineReferenceandCVEs(bug.Reference, bug.CVEs));
                ReplaceTagWithContent(editBugDoc, "|NOTES|", this.FlattenPluginPOutput(bug.PluginOutput));

                Word.Range rangeToEdit = editBugDoc.Content;
                rangeToEdit.Tables[1].Tables[1].Range.Font.Color = (Word.WdColor)ColorTranslator.ToOle(Color.FromArgb(0x5D6062));
                rangeToEdit.Tables[1].Tables[1].Range.ParagraphFormat.SpaceAfter = 0;
                rangeToEdit.Tables[1].Tables[1].Range.ParagraphFormat.SpaceBefore = 0;
                rangeToEdit.Find.ClearFormatting();                
                rangeToEdit.Find.Execute(MatchCase: true, FindText: "|AFFECTED|");
                rangeToEdit.Cut();
                this.GetAffectedTable(bug.HostInfo, rangeToEdit);                

                rangeToEdit = editBugDoc.Content;
                rangeToEdit.Copy();
                wdOutputBugFile.Characters.Last.Select();  // Line 1
                oWord.Selection.Collapse();
                oWord.Selection.Paste(); // Special(DataType: Word.WdPasteOptions.wdKeepSourceFormatting);
                wdOutputBugFile.SaveAs2(FilePath);
            }
            editBugDoc.Close(SaveChanges: false);
            wdEmptyBugTable.Close(SaveChanges: false);
            wdOutputBugFile.SaveAs2(FilePath);
            wdOutputBugFile.Close(SaveChanges: true);
            System.Runtime.InteropServices.Marshal.ReleaseComObject(oWord);
            return bRet;
        }
        private bool NopeWriteEm(string FilePath)
        {
            StringBuilder sb = new StringBuilder();
            char delimiter = '|';
            string sBugTable = File.ReadAllText(@"C:\Users\brian-admin\Documents\Casaba\templates\autoNessus.docx");
            String[] tableParts = sBugTable.Split(delimiter);
           
            foreach(BugReport bug in bugs)
            {
                foreach (string part in tableParts)
                {
                    switch (part)
                    {
                        case "TITLE":
                            sb.Append(bug.Title);
                            break;
                        case "ID":
                            sb.Append(bug.PluginID);
                            break;
                        case "SEVERITY":
                            sb.Append(bug.Severity);
                            break;
                        case "CAT":
                            sb.Append("Nessus Vulnerability");
                            break;
                        case "SCORE":
                            sb.Append(bug.CVSS_Score);
                            break;
                        case "VECTOR":
                            sb.Append(bug.CVSS_Vector);
                            break;
                        case "SUMMARY":
                            sb.Append(bug.Summary);
                            break;
                        case "IMPACT":
                            sb.Append(bug.Impact);
                            break;
                        case "REPRO":
                            sb.Append("Nessus Scan");
                            break;
                        case "REC":
                            sb.Append(bug.Recommendation);
                            break;
                        case "REF":
                            sb.Append(bug.Reference);
                            break;
                        case "AFFECTED":
                            sb.Append(bug.HostInfo);
                            break;
                        case "NOTES":
                            sb.Append(bug.PluginOutput);
                            break;
                        default:
                            sb.Append(part);
                            break;
                    }
                }
            }
            return true;
        }
    }
}
