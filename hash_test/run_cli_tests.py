import subprocess
import os

def run(cmd):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding="utf-8")
    print(f"CMD: {cmd}")
    print(f"EXIT: {res.returncode}")
    print(f"STDOUT:\n{res.stdout.strip()}")
    print(f"STDERR:\n{res.stderr.strip()}")
    print("-" * 50)

print("=== 1.1 DEFAULT ALGO ===")
run("python hash_tool.py generate --file hash_test/sample.txt")

print("=== 1.2 ALL ALGOS ===")
for algo in ["sha256", "md5", "sha512", "sha1", "blake2b", "blake2s"]:
    run(f"python hash_tool.py generate --file hash_test/sample.txt --algo {algo}")

print("=== 1.4 SAVE TO COMPANION FILE ===")
run("python hash_tool.py generate --file hash_test/sample.txt --save")

print("=== 1.5 NONEXISTENT FILE ===")
run("python hash_tool.py generate --file hash_test/does_not_exist.txt")

print("=== 2.1 BASIC TEXT ===")
run('python hash_tool.py generate --text "Hello World"')

print("=== 2.2 EMPTY STRING TEXT ===")
run('python hash_tool.py generate --text ""')

print("=== 2.3 UNICODE TEXT ===")
run('python hash_tool.py generate --text "hello world unicode"')

print("=== 3.1 DIRECTORY ===")
run("python hash_tool.py generate --dir hash_test/testdir")

print("=== 3.2 NONEXISTENT DIRECTORY ===")
run("python hash_tool.py generate --dir hash_test/no_such_dir")

print("=== 3.4 NO FILE/TEXT/DIR ===")
run("python hash_tool.py generate")

print("=== 4.1 CORRECT HASH VERIFY ===")
out = subprocess.run("python hash_tool.py generate --file hash_test/sample.txt", shell=True, capture_output=True, text=True).stdout
h = out.split()[1]
run(f"python hash_tool.py verify --file hash_test/sample.txt --hash {h}")

print("=== 4.2 INCORRECT HASH VERIFY ===")
run("python hash_tool.py verify --file hash_test/sample.txt --hash 0000000000000000000000000000000000000000000000000000000000000000")

print("=== 4.3 CASE INSENSITIVE VERIFY ===")
run(f"python hash_tool.py verify --file hash_test/sample.txt --hash {h.upper()}")

print("=== 4.4 EXTRA WHITESPACE VERIFY ===")
run(f'python hash_tool.py verify --file hash_test/sample.txt --hash "  {h}  "')

print("=== 5.1 VALID HASH FILE ===")
run("python hash_tool.py verify --file hash_test/sample.txt --hash-file hash_test/sample.txt.sha256")

print("=== 5.2 MISSING HASH FILE ===")
run("python hash_tool.py verify --file hash_test/sample.txt --hash-file hash_test/nope.sha256")

print("=== 5.3 EMPTY HASH FILE ===")
open("hash_test/empty.sha256", "w").close()
run("python hash_tool.py verify --file hash_test/sample.txt --hash-file hash_test/empty.sha256")

print("=== 5.3.2 NON-CHECKSUM FILE VERIFY ===")
with open("hash_test/not_checksum.txt", "w") as f:
    f.write("This is a regular document, not a checksum file!\n")
run("python hash_tool.py verify --file hash_test/sample.txt --hash-file hash_test/not_checksum.txt")

print("=== 5.4 NO HASH OR HASH-FILE ===")
run("python hash_tool.py verify --file hash_test/sample.txt")

print("=== 6.1 VIRUSTOTAL MISSING API KEY ===")
run("python hash_tool.py virustotal --file hash_test/sample.txt")

print("=== 6.2 VIRUSTOTAL HASH LOOKUP WITH API KEY ===")
run("python hash_tool.py virustotal --hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 --api-key dummy_key_for_testing")

print("=== 6.3 GENERATE WITH --VT FLAG ===")
run("python hash_tool.py generate --file hash_test/sample.txt --vt")

print("=== 6.4 VIRUSTOTAL MISSING ARGS ===")
run("python hash_tool.py virustotal")
