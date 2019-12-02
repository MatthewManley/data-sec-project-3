# Reads a file into a string
def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()

# Writes a string to a file
def write_file(filename, contents):
    with open(filename, 'w+') as f:
        f.write(contents)
        f.close()