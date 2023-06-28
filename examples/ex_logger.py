"""
Example using the logger library to provide formatted logging. See full information here:

https://docs.python.org/3/library/logging.html

This library allows logging to various outputs - ie to file and to screen (stdout)/ The script
uses argparse - se the ex_argparse.py script for information on that

new comment for show
"""
# Start with the imports required
import sys
import logging
import argparse

# Useful information to include
__version__ = "1.0"
__author__ = "Andy Doran"
__copyright__ = "Copyright (c) 2023"
__status__ = "Example prototype/template"

# String used with argparse as a description for what this script will do
usage = "Example/template for logging in a Python script"

# initialise the argument parser
parser = argparse.ArgumentParser(
    epilog=usage, formatter_class=argparse.RawDescriptionHelpFormatter
)

parser.add_argument("-d", "--debug-logging", help="Enable debug logging", action="store_true", dest="d")
parser.add_argument("-l", "--log-file", help="Log to file", action="store_true", dest="l")

args = parser.parse_args()

# For logging, set up how the output will look. in this case we want something like:
#
# [INFO] This is a message
formatter = logging.Formatter('%(levelname)s: %(message)s')

# Now set up logging and the log level - we will use INFO unless the option for DEBUG has been set
logger = logging.Logger(__name__)
logger.level = logging.DEBUG if args.d else logging.INFO

# Set up logging handler to the screen (stdout) always
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logger.level)
stdout_handler.setFormatter(formatter)

# Set up logging to a file - could have different formatting and/or log level...
log_file = "/tmp/ex_logfile.log"
file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logger.level)
file_handler.setFormatter(formatter)

# Add the logging handlers
logger.addHandler(stdout_handler)
if args.l:
    logger.addHandler(file_handler)

def main():
    """
    Main routinw for processing
    """

    # The print statement can be used in several ways, most basic is handle variables as strings
    # using %s in the quotes, and %variable, or % (variable1, variable2)
    # excaped and control characters use \ - ie \n for new line.
    print(
        "\n***************************************************************************************"
        "\nlogger example, version: %s\n\n\tCopyright:\t%s,%s\n\tUsage:\t\t%s"
        "\n***************************************************************************************"
        "\n" % (__version__, __copyright__, __author__, __status__)
    )

    # Logger is different to print in how it handles variables - with logger, you can use
    # substitution, but pass variables as a list
    logger.info("Start")
    logger.debug("This is a debug message")

    # Generate an error on purpose
    try:
        x = 10 / "a"
    except Exception as e:
        _error = "The error was: %s" % e
        logger.error(
            "In processing, there was an issue %s", _error
        )

    # Generate a warning - this would be a less severe problem
    logger.warning("At least one issue happened!")

    if args.l:
        logger.info("Log file: %s", log_file)

    logger.info("End")

    
"""
Python parses the script - so if the function "x" calls the function "y", then "def y():" needs to
be above "def x():" otherwise you will get an error. So by having this code to call a function
(ie main), it means everything is parsed and then the order of the functions does not matter. The
call to "main" is last in the script, meaning everything was already parsed and found
"""

if __name__ == "__main__":
    main()
