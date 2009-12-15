#!/usr/bin/env python
"""
This script extracts source code for inclusion in a document.

It reads the imput file (first parameter) and writes the output file (second 
Parameter) If the output file is not provided it write to stdout. If the input 
file name is missing it reads stdin.

It will search the current directory for the source code. 

It looks for ":<filename[tag]>:" on a line by itself except white spaces and 
replaces it with code extracted from the named file.


Copyright (C) 2009 Ed Keith

Free use of this software is granted under the terms of the 
GNU General Public License (GPL).
"""
# Version numbering scheme:
#     
#     the third digit changes with each release but the specification 
#         changes two releases that differ only in the third number should 
#         be functional equivalent. An 'A' indicates and Alpha version, A 'B'
#         indicates a beta version.
#
#     the second number changes when the specification changed, but system 
#         should be backward compatible. It should always be possible to drop 
#         in version with a hight second version number without breading any 
#         thing.
#
#     the first number changes if the new version is not backward compatible 
#         with the previous version.
#    
#
__version__ 	= "1.0.0B1"
__author__ 	= "Ed Keith"
__copyright__ 	= "Copyright 2009, Ed Keith"
__license__ 	= "GPL"
__email__ 	= "edk@users.berlios.de"
__status__ 	= "Beta"
__date__ 	= "03 December 2009"


import logging


_logging_level = logging.INFO # should be logging.INFO for released code

def get_options():
    """
    gets options from the command line and environment.
    """
    from optparse import OptionParser

    logger.debug('getting options')

    usage = "usage: %prog [options] [input file] [output file] " + \
            "if only only one file is given the output will go to stdout. " + \
	    "if no files are given input is read from stdin."

    version="%prog " + __version__ + " - " + __date__
    parser = OptionParser(usage=usage, version=version)

    parser.add_option("-l", "--logging", dest="log_level", default= -1,
            help= "logging level, CRITICAL, ERROR, WARNING, INFO, or DEBUG")

    (options, args) = parser.parse_args()

    if options.log_level in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG") :

        ll = {  "CRITICAL"	: logging.CRITICAL,
		"ERROR"		: logging.ERROR,
		"WARNING"	: logging.WARNING,
		"INFO"		: logging.INFO,
		"DEBUG"		: logging.DEBUG}

        logger.setLevel(ll[options.log_level])


    elif options.log_level != -1:
	logger.warning("Logging Level set to illegal value '%s'", options.log_level)


    if len(args) >= 1:
       options.rfilename = args[0]
    if len(args) >= 2:
       options.ofilename = args[1]



    logger.debug('done reading options %s', options)
 
    return options


def get_tag(file, tag):
    """
    gets tag from file and returns it as a string.

    On the assumption that if we request a tag from a file we will probably 
    want to get other tags from the same file it scans the entire file and 
    caches all tags. 
 
    It stores the cached tags in a dictionary with key of 
    (file name, tag name) and value of a string containing the 
    text to be substituted for the tag.
    """
    import re

    # make sure the  necessary globals are initialised
    global filenames # set of processed files
    if 'filenames' not in globals():
        filenames = set()
    global tags # dictionary of cached tag values
    if 'tags' not in globals() : # the collection has not yet been initialized
        tags = {}


    if file not in filenames:
        # file has not been processed yet
	try:
	    f = open(file, "rt")
	except IOError:
	    logger.warning("File '%s' not found.", file)
	    return "*** ERROR *** File %s Not found***\n" % file

	# matches up to 5 chars at start of line followed the "{{{" 
	# followed by tag name followed by up to five chars 
	# with optional trailing white space.
	starttag = '^(\s*).{0,5}\{{3}(\S+).{0,5}\s*$'
	startre = re.compile(starttag)
	# matches up to 5 chars followed by "}}}" followed by up to 5 chars and
	# optional trailing white space.
	endtag = "^\s*.{0,5}\}{3}.{0,5}\s*$"
	endre = re.compile(endtag)
	capturing = False # are we capturing?
	curtagname = ""
	tagvalue = ""
	trim = 0

	while True:
	    l = f.readline()
	    if not l: break
	    if capturing:
	        if endre.match(l):
		    capturing = False
		    tags[(file, curtagname)] = tagvalue
		    tagvalue = ''
		else:
		    tagvalue += l[trim:]
		    tagvalue += '\n'


	    else:
	        m = startre.match(l)
		if m: # we have a start tag
                    trim = len(m.group(1))
		    curtagname = m.group(2)
		    capturing = True

	f.close()
        filenames.add(file)


    try:
        return tags[(file,tag)]
    except KeyError:
	logger.warning("Tag '%(tag)s' not found in %(file)s", 
			{'file':file, 'tag':tag})

	return "*** ERROR *** Tag %(tag)s not found in file %(file)s ***\n" % \
				{'file':file, 'tag':tag}

 
def process_file(input, output):
    """
    Reads the input file and writes the output file, both must be open already.
    """
    import re

    t = re.compile("^\s*:(.*)<(.*)>:\s*$")
    while True:
        l= input.readline()
	if not l: break
	logger.debug("Read '%s' from input file", l) 
	m = t.match(l)
	if m:
	    logger.debug("Matched line = '%s'", m.group(0))
	    file, tag = m.group(1,2)
	    logger.debug("Finding File = '%s', tag = '%s'", file, tag)
	    s = get_tag(file, tag)
	    output.write(s)

	else:
	    logger.debug("copying '%s' directly to the output.", l)
            output.write(l)
 


def setup_logging():
    """
    Sets up the logger
    """
    import ConfigParser # change this to configparser for Python 3
    # import logging
    import logging.config
    global logger

    try:
    	logging.config.fileConfig("celog.conf")
    except ConfigParser.NoSectionError: 
	# if there is no configuration file setup a default configuration
        logging.basicConfig(filename='code_extract.log',level= _logging_level,
			format='%(asctime)s %(levelname)s - %(message)s',
			datefmt='%Y %b %d, %a %H:%M:%S'
			)
 
    logger = logging.getLogger('%s' % __name__)

    logger.debug('logger ready')



def main():
    """
    main entry point. 

    Makes sure the input and output streams are open.

    calls process_file

    Closes the files if necessary.
    """
    import sys

    setup_logging()

    options = get_options()

    if options.rfilename == "":
        i = sys.stdin
	logger.debug("Reading form console")
    else:
        i=open(options.rfilename, "rt")
	logger.debug("reading from %s", options.rfilename)
    if options.ofilename == "":
    	o = sys.stdout
	logger.debug("Writing to console")
    else:
	o = open(options.ofilename, "wt")
	logger.debug("Writing to %s.", options.ofilename)

    process_file(i,o)

    # close the files, if we opened them
    if i != sys.stdin:
        i.close()
    if o != sys.stdout:
        o.close()


if __name__ == "__main__":
    main()
    

