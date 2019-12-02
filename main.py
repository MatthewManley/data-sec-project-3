import os
import sys
import file_io
from encryption import generate_key, InvertedIndex, encryptSha256, encryptAesCbc

key = 'key'
func = 'func'


def keygen(args: list):
    expected = 1
    if len(args) != expected:
        print(
            f'Invalid number of arugments for function keygen, got {len(args)}, expected {expected}')
        return
    path = args[0]
    key = generate_key(256 / 8)
    file_io.write_file(path, key)


def encryption(args: list):
    expected = 4
    if len(args) != expected:
        print(
            f'Invalid number of arugments for function encryption, got {len(args)}, expected {expected}')
        return
    key_file = args[0]  # Read the key from this file
    index_file = args[1]  # Write the index to this file
    plaintext_folder = args[2]  # Read all plaintexts from this folder
    ciphertext_folder = args[3]  # Write all ciphertexts to this folder

    key_file_contents = file_io.read_file(key_file)

    # Create new inverted index
    inverted_index = InvertedIndex()

    if not os.path.exists(ciphertext_folder):
        os.makedirs(ciphertext_folder)

    # Find the names of all files in the plaintext folder
    plaintext_file_names = filter(
        lambda file_name: os.path.isfile(
            os.path.join(plaintext_folder, file_name)),
        os.listdir(plaintext_folder))

    for plaintext_file_name in plaintext_file_names:
        print(f'Processing file: {plaintext_file_name}')
        full_plaintext_path = os.path.join(
            plaintext_folder, plaintext_file_name)
        plaintext = file_io.read_file(full_plaintext_path)
        words = plaintext.split(' ')

        # Add file to index
        for word in words:
            inverted_index.addEntry(encryptSha256(word), plaintext_file_name)

        # Encrypt file and write to ciphertext folder
        iv_hex, encrypted_hex = encryptAesCbc(plaintext, key_file_contents)
        enc_file_content = f'{iv_hex}\n{encrypted_hex}'
        full_cipher_path = os.path.join(
            ciphertext_folder, plaintext_file_name.replace('f', 'c'))
        file_io.write_file(full_cipher_path, enc_file_content)

    # Write inverted index file to disk
    file_io.write_file(index_file, inverted_index.serialize())


def token_generation(args: list):
    pass


def search(args: list):
    expected = 4
    if len(args) != expected:
        print(
            f'Invalid number of arugments for function search, got {len(args)}, expected {expected}')
        return
    index_file = args[0]  # Read the index from this file
    token_file = args[1]  # Read the token from this file
    ciphertext_folder = args[2]
    key_file = args[3]

    index_file_contents = file_io.read_file(index_file)
    key_file_contents = file_io.read_file(key_file)

    # Create new Inv
    inverted_index = InvertedIndex()

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
        first_arg = args[1].lower()
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
    thing[func](args[2:])


if __name__ == "__main__":
    main(sys.argv)
