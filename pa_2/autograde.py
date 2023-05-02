import subprocess
import time
import os
import sys

if len(sys.argv) < 2:
    print("Usage: python3 autograder [1,2]")
    exit()

os.system("./cleanup.sh")
version = 0

try:
    version = int(sys.argv[1])
    assert version == 1 or version == 2
except Exception as e:
    print(e)
    exit()

input_file = open(f"input{version}")


output_file_server = open("output_server", "wb+")
output_file_client = open("output_client", "wb+")
os.chdir("./source")
print(f"Spawning Server and Client CP{version}")
print(f"It might take awhile, so be patient...")
p_server = subprocess.Popen(
    ["python3", f"ServerWithSecurityCP{version}.py"],
    stdout=output_file_server,
)
time.sleep(1)
p_client = subprocess.Popen(
    ["python3", f"ClientWithSecurityCP{version}.py"],
    stdin=input_file,
    stdout=output_file_client,
)
p_client.wait()
p_server.wait()
output_file_server.flush()
output_file_client.flush()
print(f"Server and Client process has terminated")
os.chdir("..")

print("Begin checking output files...")
time.sleep(1)

# check correctness
input_file.seek(0)
input_commands = input_file.readlines()
path_recv_files = "./source/recv_files"
path_recv_files_enc = "./source/recv_files_enc"
path_send_files_enc = "./source/send_files_enc"

marks = 0

for i in range(len(input_commands) - 1):
    filename = input_commands[i]
    raw_filename = filename.split("/")[-1].strip()
    # compare the sent file and the received file (unencrypted)
    filename = "./source/" + input_commands[i].strip()
    filename_recv = path_recv_files + "/recv_" + raw_filename
    command = f"diff {filename} {filename_recv} &> result_plain"
    os.system(command)

    # compare encrypted sent file and encrypted received file
    filename_encrypted = "./source/send_files_enc/enc_" + raw_filename
    filename_encrypted_recv = (
        "./source/recv_files_enc/enc_recv_" + raw_filename
    )
    command = (
        f"diff {filename_encrypted} {filename_encrypted_recv} &> result_enc"
    )
    os.system(command)

    with open("result_plain") as f:
        output = f.readlines()
        if len(output) == 0:
            marks += 1
    f.close()

    with open("result_enc") as f:
        output = f.readlines()
        if len(output) == 0:
            marks += 1
    f.close()

    # cleanup result for the next test case
    os.system("truncate -s 0 result_plain")
    os.system("truncate -s 0 result_enc")

print(f"Autograder done, total marks: {marks}. Exiting now.")
os.system("./cleanup.sh")
