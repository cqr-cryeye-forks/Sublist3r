from src.subbrute.functions.error import error


def check_open(input_file):
    ret = []
    #If we can't find a resolver from an input file, then we need to improvise.
    try:
        ret = open(input_file).readlines()
    except:
        error("File not found:", input_file)
    if not len(ret):
        error("File is empty:", input_file)
    return ret
