'''
NAME: Caitlin Harris
PROGRAM: lab3_source.py
SUMMARY:  Dynamic Heuristic Analysis Tool for Detection of Unknown Malware

'''

import pefile
import sys
import os


#array: holds lines of the log file
logFile = []

#open file, loop through contents and save lines into the array
with open("log.txt") as f:
	for line in f:
		logFile.append(line)


#count modifies (if 3 or more have been modified)
count1 = [s for s in logFile if "Modify" in s]

#count renames (if 3 or more have been renamed)
count2 = [s for s in logFile if "Rename" in s]

#count creates and deletes (if 1 or more file was created and then deleted)
count3 = [s for s in logFile if "Create" in s]

count4 = [s for s in logFile if "Delete" in s]

count5 = 0
for i in range(0, len(count3)):
	for k in range(0, len(count4)):
		line1 = count3[i]
		line2 = count4[k]
		if line1[12:] == line2[12:]:
			count5 += 1

if (count1 >= 3) and (count2 >= 3):
	if count5 >= 1:
		print("malware detected --> HEUR:Trojan-")
		print("Ransom.DocxEncrpt.Generic")	

