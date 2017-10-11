#------------------------------------
#--------import error check----------
import argparse
import yara
from gp_lib.yaraparse import yaraparse

#--------import error check----------
#------------------------------------

def main():
	parser = argparse.ArgumentParser(description='run Groom-Porter on yarafile')
	parser.add_argument('yarafile', type=str, nargs=1, help='yara file to process')
	parser.add_argument('-i', '--ignore', action='store_true', help='ignore compile errors')
	args = parser.parse_args()
	
	yara_p = yaraparse(args.yarafile[0])
	
	if args.ignore:
		print "WARNING: Groom-Porter is designed to parse yara files that compile without error. Ignoring this step may result in erroneous data"
		print "\nParsing file: %s..." % yara_p.path
		yara_p.parse()
		print yara_p
	
	else:
		valid, why = yara_p.compile_check()
		if valid:
			print 'no compile errors'
			print "\nParsing file: %s..." % yara_p.path
			yara_p.parse()
			print yara_p
		else:
			print 'Compile Error: %s' % str(why)

if __name__ == "__main__":
	main()
