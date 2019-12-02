import sys
import file_io
from encryption import generate_key

key = 'key'
func = 'func'


def keygen(args: list):
    path = args[0]
    key = generate_key(256 / 8)
    file_io.write_file(path, key)


def encryption(args: list):
    pass


def token_generation(args: list):
    pass


def search(args: list):
    pass


def main(args: list):
    argument_functions = [
        {
            key: 'keygen',
            func: keygen
        },
        {
            key: 'enc',
            func: encryption
        },
        {
            key: 'token',
            func: token_generation
        },
        {
            key: 'search',
            func: search
        }
    ]
    try:
        first_arg = args[0].lower()
    except IndexError:
        print('First argument missing')
        return

    try:
        thing: dict = next(
            filter(lambda x: x[key] == first_arg, argument_functions)
        )
    except StopIteration:
        print('Invalid first argument')
        return

    # Call the function with the rest of the arugments
    thing[func](args[1:])


if __name__ == "__main__":
    main(sys.argv)
