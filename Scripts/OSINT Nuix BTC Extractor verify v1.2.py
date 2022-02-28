'''
Script to ingest Nuix Bitcoin extraction script spreadsheet result and
lookup each address for num transactions/other btc details.

Any invalid addresses are void, xyzPubs/xyzPrivs are not looked up. 

Written by: Hary F - SWRCCU
Contact: swrccu@avonandsomerset.police.uk with any queries
January 2022
Version 1.2
'''

import csv, os
from blockchain import blockexplorer

def main():

	print("Script start - OSINT Nuix BTC Extractor sister script")
	print("Written by Harry F - SWRCCU")
	print("Contact: swrccu@avonandsomerset.police.uk with any issues\n")

	files = [f for f in os.listdir('.') if os.path.isfile(f)]

	sorted_files = []
	
	for f in files: # Find primary script output files
		if f.endswith("BTC found.csv"):
			sorted_files.append(f)

	print("Please choose a Bitcoin extraction spreadsheet to process:")
	for index, file in enumerate(sorted_files):
		print(str(index+1) + ' - ' + file)

	while True: # Type corresponding number next to requested source file
		try:
			choice = input('\nPlease select one file to process: ')
			source_sheet = sorted_files[int(choice) - 1]
		except:
			print("Error, please select numbers in the range above only")
		else:
			print("Processing: " + source_sheet)
			break
	  
	process_spreadsheet(source_sheet)

	print("Script complete")
	input("")


def process_spreadsheet(file):

	with open(file, errors='ignore', encoding='UTF-8') as csv_file:
		csv_contents = csv.reader(csv_file, delimiter=',')

		with open('PROCESSED_'+file, mode='w', newline="") as output_csv:
			output_csv_writer = csv.writer(output_csv, delimiter=',')
			output_csv_writer.writerow(['Address', 'GUID', 'Num tx', 'Total Received', 'Total Sent', 'Final Balance', 'File Path'])

			for row_index, row in enumerate(csv_contents): # For each row in csv
				if row_index == 0:
					continue
				
				# row = [address/key, GUID, file path]
				addr, guid, file_path = row

				print(str(row_index) + ". Processing: " + addr)

				if addr.lower().startswith(('xpub', 'xprv', 'ypub', 'yprv', 'zpub', 'zprv')):
					output_csv_writer.writerow([addr, guid, '', '', '', '', file_path])
				else:
					try:
						num_tx, total_received, total_sent, balance = addr_lookup(addr)
						output_csv_writer.writerow([addr, guid, num_tx, total_received, total_sent, balance, file_path])
					except:
						print("Invalid address, discarding: " + addr)

			
def addr_lookup(addr): # Ping Blockchain.com with address
	addr_data = blockexplorer.get_address(addr)

	num_tx = addr_data.n_tx
	total_received = addr_data.total_received / 100000000
	total_sent = addr_data.total_sent / 100000000
	balance = addr_data.final_balance / 100000000
	
	return num_tx, total_received, total_sent, balance

	
main()
