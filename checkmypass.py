import sys
import hashlib
import requests


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: Code {res.status_code}')
    return res


def get_leaks_count(hashes, hash_to_check):
    split_hashes = (lines.split(':') for lines in hashes.text.splitlines())
    for h, count in split_hashes:
        if h == hash_to_check:
            return count
    return 0


def pwnd_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first_5_char)
    return get_leaks_count(response, tail)


def main(input_file):
    try:
        with open(input_file, mode="r") as in_file:
            text = in_file.read()
            passwords = (password for password in text.split())
            for password in passwords:
                count = pwnd_api_check(password)
                if count:
                    print(f'{password} was found {count} times')
                else:
                    print(f'{password} was NOT found')
            return 'done'

    except FileNotFoundError as err:
        print("File does not exist in directory")


if __name__ == '__main__':
    main(sys.argv[1])
