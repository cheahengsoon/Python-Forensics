from __future__ import print_function
import argparse
import unicodecsv as csv
import os
import pytsk3
import pyewf
import pyevt
import pyevtx
import sys
from utility.pytskutil import TSKUtil
if __name__ == "__main__":
   parser = argparse.ArgumentParser('Information from Event Logs')
   parser.add_argument("EVIDENCE_FILE", help = "Evidence file path")
   parser.add_argument("TYPE", help = "Type of Evidence",choices = ("raw", "ewf"))
   parser.add_argument(
      "LOG_NAME",help = "Event Log Name (SecEvent.Evt, SysEvent.Evt, ""etc.)")
   
   parser.add_argument(
      "-d", help = "Event log directory to scan",default = "/WINDOWS/SYSTEM32/WINEVT")
   
   parser.add_argument(
      "-f", help = "Enable fuzzy search for either evt or"" evtx extension", action = "store_true")
   args = parser.parse_args()
   
   if os.path.exists(args.EVIDENCE_FILE) and \ os.path.isfile(args.EVIDENCE_FILE):
      main(args.EVIDENCE_FILE, args.TYPE, args.LOG_NAME, args.d, args.f)
   else:
      print("[-] Supplied input file {} does not exist or is not a ""file".format(args.EVIDENCE_FILE))
   sys.exit(1)

def main(evidence, image_type, log, win_event, fuzzy):
   tsk_util = TSKUtil(evidence, image_type)
   event_dir = tsk_util.query_directory(win_event)
   
   if event_dir is not None:
      if fuzzy is True:
         event_log = tsk_util.recurse_files(log, path=win_event)
   else:
      event_log = tsk_util.recurse_files(log, path=win_event, logic="equal")
   
   if event_log is not None:
      event_data = []
      for hit in event_log:
         event_file = hit[2]
         temp_evt = write_file(event_file)
         def write_file(event_file):
   with open(event_file.info.name.name, "w") as outfile:
      outfile.write(event_file.read_random(0, event_file.info.meta.size))
   return event_file.info.name.name
      if pyevt.check_file_signature(temp_evt):
         evt_log = pyevt.open(temp_evt)
         print("[+] Identified {} records in {}".format(
            evt_log.number_of_records, temp_evt))
         
         for i, record in enumerate(evt_log.records):
            strings = ""
            for s in record.strings:
               if s is not None:
                  strings += s + "\n"
            event_data.append([
               i, hit[0], record.computer_name,
               record.user_security_identifier,
               record.creation_time, record.written_time,
               record.event_category, record.source_name,
               record.event_identifier, record.event_type,
               strings, "",
               os.path.join(win_event, hit[1].lstrip("//"))
            ])
      elif pyevtx.check_file_signature(temp_evt):
         evtx_log = pyevtx.open(temp_evt)
         print("[+] Identified {} records in {}".format(
            evtx_log.number_of_records, temp_evt))
         for i, record in enumerate(evtx_log.records):
            strings = ""
            for s in record.strings:
			   if s is not None:
               strings += s + "\n"
         event_data.append([
            i, hit[0], record.computer_name,
            record.user_security_identifier, "",
            record.written_time, record.event_level,
            record.source_name, record.event_identifier,
            "", strings, record.xml_string,
            os.path.join(win_event, hit[1].lstrip("//"))
      ])
      else:
         print("[-] {} not a valid event log. Removing temp" file...".format(temp_evt))
         os.remove(temp_evt)
      continue
      write_output(event_data)
   else:
      print("[-] {} Event log not found in {} directory".format(log, win_event))
      sys.exit(3)
else:
   print("[-] Win XP Event Log Directory {} not found".format(win_event))
   sys.exit(2)
   def write_output(data):
   output_name = "parsed_event_logs.csv"
   print("[+] Writing {} to current working directory: {}".format(
      output_name, os.getcwd()))
   
   with open(output_name, "wb") as outfile:
      writer = csv.writer(outfile)
      writer.writerow([
         "Index", "File name", "Computer Name", "SID",
         "Event Create Date", "Event Written Date",
         "Event Category/Level", "Event Source", "Event ID",
         "Event Type", "Data", "XML Data", "File Path"
      ])
      writer.writerows(data)

      