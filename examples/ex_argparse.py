"""
Example using the argparse library to allow and manage inputs. See full information here:

https://docs.python.org/3/library/argparse.html

This library allows you to specify inputs to a script when you run it - ie:

    python myscript.py -input /tmp/abc.txt -show

here:

    -input is used to specify that a value is expected (/tmp/abc.txt in the example)
    -show is boolean - if you specify it, then it will be treated as True, otherwise it is False

This library can be very powerfule or used to accept very simple input.

"""
# Start with the imports required
import argparse

# Useful information to include
__version__ = "1.0"
__author__ = "Andy Doran"
__copyright__ = "Copyright (c) 2023"
__status__ = "Example prototype/template"

# String used with argparse as a description for what this script will do
usage = "Example/template for processing inputs to a Python script"

# initialise the argument parser - see web page for different ways to do this
parser = argparse.ArgumentParser(
    epilog=usage, formatter_class=argparse.RawDescriptionHelpFormatter
)

# Now set up the inputs - use --help to see how these show up and can be used

# an argument where we expect a value, so "-f /tmp/abc.txt"
parser.add_argument("-f", "--file-name", help="Input file name", dest="f")

# an argument which is boolean - specified it is True, not specified it is False
parser.add_argument("-b", "--boolean-value", help="A boolean value", action="store_true", dest="b")

# an integer value
parser.add_argument("-i", "--integer-value", help="An integer value expected", type=int, default=10, dest="i")

# now we parse the inputs and set up "args" to use in the script
args = parser.parse_args()


def main():
    """
    Main routinw for processing
    """

    # The print statement can be used in several ways, most basic is handle variables as strings
    # using %s in the quotes, and %variable, or % (variable1, variable2)
    # excaped and control characters use \ - ie \n for new line.
    print(
        "\n***************************************************************************************"
        "\nargparse example, version: %s\n\n\tCopyright:\t%s,%s\n\tUsage:\t\t%s"
        "\n***************************************************************************************"
        "\n" % (__version__, __copyright__, __author__, __status__)
    )

    # Show the inputs
    print("-f input: %s" % args.f)
    print("-b input: %s" % args.b)
    print("-i input: %s" % args.i)


"""
Python parses the script - so if the function "x" calls the function "y", then "def y():" needs to
be above "def x():" otherwise you will get an error. So by having this code to call a function
(ie main), it means everything is parsed and then the order of the functions does not matter. The
call to "main" is last in the script, meaning everything was already parsed and found
"""

if __name__ == "__main__":
    main()
