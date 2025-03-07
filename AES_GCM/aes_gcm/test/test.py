
import re
import subprocess

def parse_sizes(line, line_iter):
    key_len = key_len_regex.search(line).group(1)
    line = next(line_iter)
    iv_len = iv_len_regex.search(line).group(1)
    line = next(line_iter)
    pt_len = pt_len_regex.search(line).group(1)
    line = next(line_iter)
    aad_len = aad_len_regex.search(line).group(1)
    line = next(line_iter)
    tag_len = tag_len_regex.search(line).group(1)

    return key_len, iv_len, pt_len, aad_len, tag_len

def test_encrypt(file):
    success_test = 0
    tests_count = 0
    lines = file.readlines()
    line_iter = iter(lines)

    # Discard initial comment lines
    while(re.search('^#', line := next(line_iter))):
        pass

    try:
        while(1):
            # Discard blank lines
            while re.search('^\s+$', line := next(line_iter)):
                pass

            # Parse sizes
            key_len, iv_len, pt_len, aad_len, tag_len = parse_sizes(line, line_iter)

            for i in range(15):
                # Discard blank lines and 'Count' line
                while(re.search('^\s$', line := next(line_iter))):
                    pass
                
                # Parse variables
                line = next(line_iter)
                key = key_regex.search(line).group(1)
                line = next(line_iter)
                iv = iv_regex.search(line).group(1)
                line = next(line_iter)
                pt = pt_regex.search(line).group(1)
                line = next(line_iter)
                aad = aad_regex.search(line).group(1)
                line = next(line_iter)
                ct = ct_regex.search(line).group(1)
                line = next(line_iter)
                tag = tag_regex.search(line).group(1)

                ret = subprocess.run(["./test_encrypt", "-key", key, "-iv", iv, "-pt", pt, "-aad", aad, "-ct", ct, "-tag", tag])
                tests_count += 1
                if ret.returncode == 0:
                    success_test += 1
                    # print(f'ERROR: K{key_len},IV{iv_len},PT{pt_len},AAD{aad_len},T{tag_len},COUNT{count}')
    except StopIteration:
        return success_test, tests_count

def test_decrypt(file):
    success_test = 0
    tests_count = 0
    lines = file.readlines()
    line_iter = iter(lines)

    # Discard initial comment lines
    while(re.search('^#', line := next(line_iter))):
        pass

    try:
        while(1):
            # Discard blank lines
            while re.search('^\s+$', line := next(line_iter)):
                pass

            # Parse sizes
            key_len, iv_len, pt_len, aad_len, tag_len = parse_sizes(line, line_iter)

            for i in range(15):
                # Discard blank lines and 'Count' line
                while(re.search('^\s$', line := next(line_iter))):
                    pass
                
                # Parse variables
                line = next(line_iter)
                key = key_regex.search(line).group(1)
                line = next(line_iter)
                iv = iv_regex.search(line).group(1)
                line = next(line_iter)
                ct = ct_regex.search(line).group(1)
                line = next(line_iter)
                aad = aad_regex.search(line).group(1)
                line = next(line_iter)
                tag = tag_regex.search(line).group(1)
                line = next(line_iter)

                if fail_regex.search(line):
                    ret = subprocess.run(["./test_decrypt", "-key", key, "-iv", iv, "-ct", ct, "-aad", aad, "-pt", pt, "-tag", tag, "-fail"])
                else:
                    pt = pt_regex.search(line).group(1)
                    ret = subprocess.run(["./test_decrypt", "-key", key, "-iv", iv, "-ct", ct, "-aad", aad, "-pt", pt, "-tag", tag])
                    
                tests_count += 1
                if ret.returncode == 0:
                    success_test += 1
                    # print(f'ERROR: K{key_len},IV{iv_len},PT{pt_len},AAD{aad_len},T{tag_len},COUNT{count}')
    except StopIteration:
        return success_test, tests_count

# Compile REGEX's
key_len_regex = re.compile(r'\[Keylen = (\d+)\]')
iv_len_regex = re.compile(r'\[IVlen = (\d+)\]')
pt_len_regex = re.compile(r'\[PTlen = (\d+)\]')
aad_len_regex = re.compile(r'\[AADlen = (\d+)\]')
tag_len_regex = re.compile(r'\[Taglen = (\d+)\]')

count_regex = re.compile(r'Count = (\d+)')
key_regex = re.compile(r'Key = ([0-9a-f]+)')
iv_regex = re.compile(r'IV = ([0-9a-f]+)')
pt_regex = re.compile(r'PT = ([0-9a-f]*)')
aad_regex = re.compile(r'AAD = ([0-9a-f]*)')
ct_regex = re.compile(r'CT = ([0-9a-f]*)')
tag_regex = re.compile(r'Tag = ([0-9a-f]+)')
fail_regex = re.compile(r'^FAIL')

# Open files and test them
with open('gcmEncryptExtIV128.rsp', 'r') as file:
    success, total = test_encrypt(file)
    print(f'[128 bits encrypt tests]: {success} in {total} tests successful.')

with open('gcmEncryptExtIV192.rsp', 'r') as file:
    success, total = test_encrypt(file)
    print(f'[192 bits encrypt tests]: {success} in {total} tests successful.')

with open('gcmEncryptExtIV256.rsp', 'r') as file:
    success, total = test_encrypt(file)
    print(f'[256 bits encrypt tests]: {success} in {total} tests successful.')

with open('gcmDecrypt128.rsp', 'r') as file:
    success, total = test_decrypt(file)
    print(f'[128 bits decrypt tests]: {success} in {total} tests successful.')

with open('gcmDecrypt192.rsp', 'r') as file:
    success, total = test_decrypt(file)
    print(f'[192 bits decrypt tests]: {success} in {total} tests successful.')

with open('gcmDecrypt256.rsp', 'r') as file:
    success, total = test_decrypt(file)
    print(f'[256 bits decrypt tests]: {success} in {total} tests successful.')
