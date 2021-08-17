import pefile
import sys
import os

for entry in os.scandir(os.getcwd()):

	if(entry.path.endswith(".py")):
	
		continue
		
	else:
	
		array = []
		malware_file = entry.path
		pe = pefile.PE(malware_file)
		print(entry.path)
		
		if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
			for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
				array.append(hex(exp.address + pe.OPTIONAL_HEADER.IMAGEBASE))
				
		array.sort()
		
		for i in array:
			if array.count(i) > 2:
				print("Three or more functions share a memory address.")
				
				break
				
		arrayHelper = []
		
		for i in range(1, len(array)):
			arrayHelper.append((int(array[i],16) - int(array[i-1], 16)))
			
		for i in range(len*arrayHelper)-1):
			j = 0
			
			while(arrayHelper[i+j]==0):
				if((i + j) > (len(arrayHelper)-2)):
					break
					
				j = j + 1
				
			while(j != 0):
				j = j - 1
				
				arrayHelper[] = arrayHelper[i+j+1]
				
		
		for i in arrayHelper:
		
			if arrayHelper.count(i) > 2:
			
				print("Three or more functions have the same offset.")
				
				break
