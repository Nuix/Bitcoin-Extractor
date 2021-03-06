'''
Script to extract all P2PKH, P2SH, Bech32 Bitcoin addresses/Extended Public and Private Keys (xPubs/xPrvs)
from any Nuix Workstation instance. Hits exported to csv alongside GUID and File Path.

P2PKH and P2SH validation code from savasadar github 
https://gist.github.com/savasadar/efd9e2a6a6540dd2b33b2a24a7996c8e

Bech32 Checksum validation code from sipa GitHub (Pieter Wuille)
https://github.com/sipa/bech32/tree/master/ref/ruby

Current version adds all hits to item set, with hits to csv, and errors to second csv. 

LIMITATION: Wont scan Nuix items greater than 2GB (JAVA variable size limit)
KNOWN ERROR: Some false positives may still be exported, use OSINT Blockchain lookup script to verify

Written By Harry F - SWRCCU
Contact: swrccu@avonandsomerset.police.uk with any queries 
Developed on behalf of the SWRCCU
https://www.swrocu.police.uk/cyber-crime/
'''

# Needs Case: true

# Boostrap NX which we will use for
# - Settings dialog
# - Progress dialog
# Nx is available on GitHub here: https://github.com/Nuix/Nx
script_directory = File.dirname(__FILE__)
require File.join(script_directory,"Nx.jar")
java_import "com.nuix.nx.NuixConnection"
java_import "com.nuix.nx.LookAndFeelHelper"
java_import "com.nuix.nx.dialogs.ChoiceDialog"
java_import "com.nuix.nx.dialogs.TabbedCustomDialog"
java_import "com.nuix.nx.dialogs.CommonDialogs"
java_import "com.nuix.nx.dialogs.ProgressDialog"
java_import "com.nuix.nx.dialogs.ProcessingStatusDialog"
java_import "com.nuix.nx.digest.DigestHelper"
java_import "com.nuix.nx.controls.models.Choice"

LookAndFeelHelper.setWindowsIfMetal
NuixConnection.setUtilities($utilities)
NuixConnection.setCurrentNuixVersion(NUIX_VERSION)

require 'csv'
require 'digest'

$script_version = "v5.3"

# Constants for Base58 decode verification 
B58Chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58Base = B58Chars.length

def main
	dialog = TabbedCustomDialog.new("Bitcoin Extractor #{$script_version}")
	dialog.setHelpUrl("https://github.com/Nuix/Bitcoin-Extractor")

	# For documentation on configuring a dialog tab see
	# https://nuix.github.io/Nx/com/nuix/nx/dialogs/CustomTabPanel.html
	main_tab = dialog.addTab("main_tab","Settings")
	main_tab.appendHeader("Bitcoin Extractor #{$script_version} by Harry F")
	main_tab.appendHeader("Please contact swrccu@avonandsomerset.police.uk with any issues")
	main_tab.appendHeader("Developed on behalf of the SWRCCU - https://www.swrocu.police.uk/cyber-crime/")

	# If there are items selected, allow user to run again only those selected items
	# or all items if they wish
	if $current_selected_items.nil? == false && $current_selected_items.size > 0
		main_tab.appendRadioButton("use_selected_items","Use #{$current_selected_items.size} selected items","input_items_grp",true)
		main_tab.appendRadioButton("use_all_items","Use all #{$current_case.count("")} items in case","input_items_grp",false)
	else
		main_tab.appendRadioButton("use_all_items","Use all #{$current_case.count("")} items in case","input_items_grp",true)
	end

	default_export_dir = File.join($current_case.getLocation.getAbsolutePath,"BitcoinExtractorResults")
	main_tab.appendDirectoryChooser("csv_export_directory","CSV Export Directory",default_export_dir)

	# Here we can define validations for the settings where if something doesn't
	# meet our requirements we can enforce user fixing it before running
	dialog.validateBeforeClosing do |values|
		if values["csv_export_directory"].strip.empty?
			CommonDialogs.showWarning("Please provide a value for 'CSV Export Directory'")
			next false
		end

		next true
	end

	# Display the settings dialog
	dialog.display

	# If all went well, lets get to work
	if dialog.getDialogResult == true
		# Store values from settings dialog into a hash/map
		values = dialog.toMap

		# Display a progress dialog while we are working on things
		ProgressDialog.forBlock do |pd|
			# Log messages should also be puts'ed to console/logs
			pd.onMessageLogged{|msg|puts(msg)}

			pd.logMessage("Bitcoin Extractor #{$script_version} by Harry F")
			pd.logMessage("Please contact swrccu@avonandsomerset.police.uk with any issues")
			pd.logMessage("Developed on behalf of the SWRCCU")
			pd.logMessage("https://www.swrocu.police.uk/cyber-crime/")

			# Provide selected items if settings state to do so, otherwise
			# provide all items in the case
			items_to_process = nil
			if values["use_selected_items"]
				items_to_process = $current_selected_items
			else
				items_to_process = $current_case.searchUnsorted("")
			end

			pd.logMessage("\nExtraction Start...\n")
			bitcoin_address_data, skipped = regex_extractor(items_to_process,pd) # Valid address data with relevant metadata

			pd.logMessage("Extraction Complete, exporting...")
			csv_export(bitcoin_address_data, skipped, pd, values["csv_export_directory"]) # Export to csv and item set

			pd.setCompleted
		end
	end

	return "Complete"
end 

def regex_extractor(items=nil,pd)
	
	# Bitcoin REGEX for initial blanket search 
	regex = [/1[a-km-zA-HJ-NP-Z1-9]{25,34}/,
			 /3[a-km-zA-HJ-NP-Z1-9]{25,34}/,
			 /bc1[ac-hj-np-zAC-HJ-NP-Z02-9]{11,71}/,
			 /xpub[a-km-zA-HJ-NP-Z1-9]{107,108}/,
			 /xprv[a-km-zA-HJ-NP-Z1-9]{107,108}/,
			 /ypub[a-km-zA-HJ-NP-Z1-9]{107,108}/,
			 /yprv[a-km-zA-HJ-NP-Z1-9]{107,108}/,
			 /zpub[a-km-zA-HJ-NP-Z1-9]{107,108}/,
			 /zprv[a-km-zA-HJ-NP-Z1-9]{107,108}/
			]
	
	if items.nil?
		items = $current_case.searchUnsorted("") # Take all items from current case to search REGEX
	end

	num_items = items.length
	pd.logMessage("#{num_items} items will be searched...")
	bitcoin_address_data = [] # [[[item_btc], guid, file_path, item_class], [[item_btc], guid, file_path, item_class].....[]]
	
	skipped = [] # [[guid, file_path], [guid, file_path].....[]]
	
	items.each_with_index do |item, item_index| # Per each Nuix item within case
		pd.setMainProgress(item_index+1,items.size)
		pd.setMainStatus("Processing Item #{item_index+1}/#{items.size}")

		hits = []
		item_btc = []
		
		# Get File Path and GUID of item for later output
		file_path = item.getLocalisedPathNames.to_s 
		guid = item.getGuid.to_s
		file_size = item.getFileSize
		
		if file_size > 2000000000 # Won't scan items larger than 2 GB
			pd.logMessage("Item too large, skipping: #{guid}")
			type = item.getKind
			skipped << [guid, type, file_path] # For later output
			next
		end unless file_size.nil?
		
		item_text = item.getTextObject
		begin 
			regex.each do |expression|
				hits = item_text.toString.scan expression # Search REGEX across text comprehended item 
				item_btc = [item_btc, hits].compact.reduce([], :|)
			end
		rescue # Catch non fatal issues
			pd.logMessage("Error with item, skipping: #{guid}")
			type = item.getKind
			skipped << [guid, type, file_path]
			
		end unless item_text.nil?
		
		verified_item_btc = []
		
		item_btc.each_with_index do |poss_addr,addr_index| # verify each Regex hit
			pd.setSubProgress(addr_index+1,item_btc.size)
			pd.setSubStatus("Verifying #{addr_index+1}/#{item_btc.size}")
			begin
				if poss_addr.downcase.start_with?("xpub", "xprv", "ypub", "yprv", "zpub", "zprv") # Whitelist keys
					verified_item_btc << poss_addr
					pd.logMessage("  Verified key found: #{poss_addr}")
				elsif poss_addr.downcase.start_with?("bc1") # Bech32 verification
					hrp, data = Bech32.decode(poss_addr)
					if data.to_s != "" # Valid address
						verified_item_btc << poss_addr
						pd.logMessage("  Verified address found: #{poss_addr}")
					end				
				elsif verify_address(poss_addr) # If address verified 
					if poss_addr.start_with?("1", "3")
						verified_item_btc << poss_addr
						pd.logMessage("  Verified address found: #{poss_addr}")
					end
				end 
			rescue
			end
		end unless item_btc.nil?
	
		if verified_item_btc != [] # Only output if confirmed addresses present
			bitcoin_address_data << [verified_item_btc.uniq, guid, file_path, item] # Add verified Bitcoin addresses/keys to be outputted later
			pd.logMessage("#{bitcoin_address_data.size} items with valid hits")
		end  
	end	
	
	return bitcoin_address_data, skipped

end 

def csv_export(bitcoin_address_data, skipped, pd, export_directory=nil) # Export validated hits, errors to csv, hits to item set
	if export_directory.nil?
		export_directory = File.dirname(__FILE__)
	end

	case_name = $current_case.getName
	
	csv_name = case_name + " - BTC found.csv"
	file_path = File.join(export_directory, csv_name)
	pd.logMessage("Generating #{file_path}")
	
	item_set_items = []

	CSV.open(file_path, "w") do |csv| # Exports to CSV within script directory
		csv << ['Address', 'GUID', 'File Path']
		bitcoin_address_data.each do |item_btc, guid, file_path, item_class|
			item_set_items << item_class
			item_btc.each do |address|
				csv << [address, guid, file_path]
			end
		end 
	end 
	pd.logMessage("Hits CSV export complete")
	
	# Export items to Item set within Nuix
	item_set = create_item_set("Bitcoin Extraction")
	batch_settings = {
		"batch" => "Bitcoin hits"
		}
	
	item_set.addItems(item_set_items, batch_settings)
	pd.logMessage("Hits Item Set export complete")	
	
	csv_name = case_name + " - BTC errors.csv"
	file_path = File.join(export_directory, csv_name)
	pd.logMessage("Generating #{file_path}")
	
	CSV.open(file_path, "w") do |csv| # Error items export 
		csv << ['Following items failed to scan for BTC - file size too large']
		csv << ['GUID', 'type', 'File Path']
		skipped.each do |guid, type, file_path|
			csv << [guid, type, file_path]
		end 
	end 
	pd.logMessage("Error GUIDS CSV export complete")
	
end 

def create_item_set(item_set_name) # Creates blank item set with passed name
	
	item_set_settings = {
		"deduplication" => "MD5",
		"description" => "Items with Bitcoin hits",
		"deduplicateBy" => "INDIVIDUAL",
		}
	
	item_set = $current_case.findItemSetByName(item_set_name) # Get current case if already been created
	
	unless item_set.nil? # If exists, deletes
		$current_case.deleteItemSet(item_set_name)
	end 
	
	item_set = $current_case.createItemSet(item_set_name, item_set_settings)
	
	return item_set 

end

def verify_address(address) 
	'''
	Verify_address and b58_decode - Code from savasadar Bitcoin Address validator:
	https://gist.github.com/savasadar/efd9e2a6a6540dd2b33b2a24a7996c8e
	Code restructured and optimised for application
	'''
	
	decoded = b58_decode(address, 25)
	
	version = decoded[0, 1]
	checksum = decoded[-4, decoded.length]
	vh160 = decoded[0, decoded.length - 4]

	hashed = (Digest::SHA2.new << (Digest::SHA2.new << vh160).digest).digest

	hashed[0, 4] == checksum ? version[0] : nil
end

def b58_decode(value, length)
	'''
	Full credit to savasadars validation. b58_decode is an extension of address verification
	'''
	
	long_value = 0
	index = 0
	result = ""

	value.reverse.each_char do |c|
		long_value += B58Chars.index(c) * (B58Base ** index)
		index += 1
	end

	while long_value >= 256 do
		div, mod = long_value.divmod 256
		result = mod.chr + result
		long_value = div
	end

	result = long_value.chr + result

	if result.length < length
		result = 0.chr * (length - result.length) + result
	end

	result
end

module Bech32
	'''
	Following code from sipa GitHub (Pieter Wuille) for Bech32 validation. 
	https://github.com/sipa/bech32/tree/master/ref/ruby
	'''

	SEPARATOR = '1'

	CHARSET = %w(q p z r y 9 x 8 g f 2 t v d w 0 s 3 j n 5 4 k h c e 6 m u a 7 l)

	module_function

	# Encode Bech32 string
	def encode(hrp, data)
		checksummed = data + create_checksum(hrp, data)
		hrp + SEPARATOR + checksummed.map{|i|CHARSET[i]}.join
	end

	# Decode a Bech32 string and determine hrp and data
	def decode(bech)
		# check invalid bytes
		return nil if bech.scrub('?').include?('?')
		# check uppercase/lowercase
		return nil if (bech.downcase != bech && bech.upcase != bech)
		bech.each_char{|c|return nil if c.ord < 33 || c.ord > 126}
		bech = bech.downcase
		# check data length
		pos = bech.rindex(SEPARATOR)
		return nil if pos.nil? || pos < 1 || pos + 7 > bech.length || bech.length > 90
		# check valid charset
		bech[pos+1..-1].each_char{|c|return nil unless CHARSET.include?(c)}
		# split hrp and data
		hrp = bech[0..pos-1]
		data = bech[pos+1..-1].each_char.map{|c|CHARSET.index(c)}
		# check checksum
		return nil unless verify_checksum(hrp, data)
		[hrp, data[0..-7]]
	end

	# Compute the checksum values given hrp and data.
	def create_checksum(hrp, data)
		values = expand_hrp(hrp) + data
		polymod = polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
		(0..5).map{|i|(polymod >> 5 * (5 - i)) & 31}
	end

	# Verify a checksum given Bech32 string
	def verify_checksum(hrp, data)
		polymod(expand_hrp(hrp) + data) == 1
	end

	# Expand the hrp into values for checksum computation.
	def expand_hrp(hrp)
		hrp.each_char.map{|c|c.ord >> 5} + [0] + hrp.each_char.map{|c|c.ord & 31}
	end

	# Compute Bech32 checksum
	def polymod(values)
		generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
		chk = 1
		values.each do |v|
			top = chk >> 25
			chk = (chk & 0x1ffffff) << 5 ^ v
			(0..4).each{|i|chk ^= ((top >> i) & 1) == 0 ? 0 : generator[i]}
		end
		chk
	end

	private_class_method :polymod, :expand_hrp

end

class SegwitAddr
	'''
	Additional code from sipa GitHub (Pieter Wuille) for Bech32 validation. 
	'''

	attr_accessor :hrp # human-readable part
	attr_accessor :ver # witness version
	attr_accessor :prog # witness program

	def initialize(addr = nil)
		@hrp, @ver, @prog = parse_addr(addr) if addr
	end

	def to_scriptpubkey
		v = ver == 0 ? ver : ver + 0x50
		([v, prog.length].pack("CC") + prog.map{|p|[p].pack("C")}.join).unpack('H*').first
	end

	def scriptpubkey=(script)
		values = [script].pack('H*').unpack("C*")
		@ver = values[0]
		@prog = values[2..-1]
	end

	def addr
		encoded = Bech32.encode(hrp, [ver] + convert_bits(prog, 8, 5))
		chrp, cver, cprog = parse_addr(encoded)
		raise 'Invalid address' if chrp != hrp || cver != ver || cprog != prog
		encoded
	end

	private

	def parse_addr(addr)
		hrp, data = Bech32.decode(addr)
		raise 'Invalid address.' if hrp.nil? || data[0].nil? || (hrp != 'bc' && hrp != 'tb')
		ver = data[0]
		raise 'Invalid witness version' if ver > 16
		prog = convert_bits(data[1..-1], 5, 8, false)
		raise 'Invalid witness program' if prog.nil? || prog.length < 2 || prog.length > 40
		raise 'Invalid witness program with version 0' if ver == 0 && (prog.length != 20 && prog.length != 32)
		[hrp, ver, prog]
	end

	def convert_bits(data, from, to, padding=true)
		acc = 0
		bits = 0
		ret = []
		maxv = (1 << to) - 1
		max_acc = (1 << (from + to - 1)) - 1
		data.each do |v|
			return nil if v < 0 || (v >> from) != 0
			acc = ((acc << from) | v) & max_acc
			bits += from
			while bits >= to
				bits -= to
				ret << ((acc >> bits) & maxv)
			end
		end
		if padding
			ret << ((acc << (to - bits)) & maxv) unless bits == 0
		elsif bits >= from || ((acc << (to - bits)) & maxv) != 0
			return nil
		end
		ret
	end

end

main
