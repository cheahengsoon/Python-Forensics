from __future__ import print_function
import argparse

from datetime import datetime, timedelta
import os
import pytsk3
import pyewf
import pymsiecf
import sys
import unicodecsv as csv

from utility.pytskutil import TSKUtil
if __name__ == "__main__":
parser = argparse.ArgumentParser('getting information from internet history')
   parser.add_argument("EVIDENCE_FILE", help = "Evidence file path")
   parser.add_argument("TYPE", help = "Type of Evidence",choices = ("raw", "ewf"))
   parser.add_argument("-d", help = "Index.dat directory to scan",default = "/USERS")
   args = parser.parse_args()
   
   if os.path.exists(args.EVIDENCE_FILE) and os.path.isfile(args.EVIDENCE_FILE):
      main(args.EVIDENCE_FILE, args.TYPE, args.d)
   else:
      print("[-] Supplied input file {} does not exist or is not a ""file".format(args.EVIDENCE_FILE))
      sys.exit(1)
      def main(evidence, image_type, path):
   tsk_util = TSKUtil(evidence, image_type)
   index_dir = tsk_util.query_directory(path)
   
   if index_dir is not None:
      index_files = tsk_util.recurse_files("index.dat", path = path,logic = "equal")
      
      if index_files is not None:
         print("[+] Identified {} potential index.dat files".format(len(index_files)))
         index_data = []
         
         for hit in index_files:
            index_file = hit[2]
            temp_index = write_file(index_file)
            def write_file(index_file):
   with open(index_file.info.name.name, "w") as outfile:
   outfile.write(index_file.read_random(0, index_file.info.meta.size))
return index_file.info.name.name
if pymsiecf.check_file_signature(temp_index):
   index_dat = pymsiecf.open(temp_index)
   print("[+] Identified {} records in {}".format(
   index_dat.number_of_items, temp_index))

   for i, record in enumerate(index_dat.items):
   try:
      data = record.data
   if data is not None:
      data = data.rstrip("\x00")
   except AttributeError:
   
   if isinstance(record, pymsiecf.redirected):
      index_data.append([
         i, temp_index, "", "", "", "", "",record.location, "", "", record.offset,os.path.join(path, hit[1].lstrip("//"))])
   
   elif isinstance(record, pymsiecf.leak):
      index_data.append([
         i, temp_index, record.filename, "","", "", "", "", "", "", record.offset,os.path.join(path, hit[1].lstrip("//"))])
   continue
   
   index_data.append([
      i, temp_index, record.filename,
      record.type, record.primary_time,
      record.secondary_time,
      record.last_checked_time, record.location,
      record.number_of_hits, data, record.offset,
      os.path.join(path, hit[1].lstrip("//"))
   ])
   else:
      print("[-] {} not a valid index.dat file. Removing "
      "temp file..".format(temp_index))
      os.remove("index.dat")
      continue
      os.remove("index.dat")
      write_output(index_data)
   else:
      print("[-] Index.dat files not found in {} directory".format(path))
   sys.exit(3)
   else:
      print("[-] Directory {} not found".format(win_event))
   sys.exit(2)

   def write_output(data):
   output_name = "Internet_Indexdat_Summary_Report.csv"
   print("[+] Writing {} with {} parsed index.dat files to current "
   "working directory: {}".format(output_name, len(data),os.getcwd()))
   
   with open(output_name, "wb") as outfile:
      writer = csv.writer(outfile)
      writer.writerow(["Index", "File Name", "Record Name",
      "Record Type", "Primary Date", "Secondary Date",
      "Last Checked Date", "Location", "No. of Hits",
      "Record Data", "Record Offset", "File Path"])
      writer.writerows(data)