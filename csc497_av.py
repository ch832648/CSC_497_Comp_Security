import pefile
import sys
import os

'''
NAME: Caitlin Harris
PROGRAM: csc497_av.py
SUMMARY: Heuristic Malware Dectection System
'''

#user input directory to search
direct = sys.argv[1]

#master for loop: loops through all the files found in directory
for mal_file in os.listdir(direct):
	#arrays: memory addresses, memory offsets, function names
	#variables: rules broken
	memAdd = []
	memOffset = []
	funcNames = []
	rules = 0
	memAddRules = 0
	memOffsetRules=0
	funcNamesRules = 0

	#save file into pe
	pe = pefile.PE(direct+ "/" + mal_file)
	#if the file is valid
	if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):	
		#loop through file contents
    		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			#add memory address to array
			memAdd.append(hex(exp.address + pe.OPTIONAL_HEADER.ImageBase))
			#add function names to array
			funcNames.append(exp.name)

	#sort memory addresses and function names
	memAdd.sort()	
	funcNames.sort()
	
	#print malware file name
	print("Malware Analysis for file: %s: " % (mal_file))

	#loop through offsets, get differences	
	for i in range(1, len(memAdd)):
		memOffset.append(hex(int(memAdd[i], 16) - int(memAdd[i-1],16)))		

	
	#if 3 or more identical memory addresses
	for i in range(0, len(memAdd)-1):
		if memAdd.count(memAdd[i]) >= 3:
			rules += 1
			memAddRules += 1

	if memAddRules > 0:
		print("Rule 1 VIOLATED: three or more identical memory addresses")

	#if 3 or more identical memory offsets
	for i in range(0, len(memOffset)-1):
		if memOffset.count(memOffset[i]) >= 3:
			rules += 1
			memOffsetRules += 1	
	
	if memOffsetRules > 0:
		print("Rule 2 VIOLATED: three or more identical memory offsets")

	#if 2 or more identical names 
	for i in range(0, len(funcNames)-1):
		if funcNames.count(funcNames[i]) >= 2:
			rules += 1
			funcNamesRules += 1			

	if funcNamesRules > 0:
		print("Rule 3 VIOLATED: two or more identical function names")
	
	if rules == 0:
		print("No Malware in this file!")

	print("----------------------------------------------------------")




	
	

