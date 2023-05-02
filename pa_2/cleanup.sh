rm -rf source/recv_files
mkdir source/recv_files
rm -rf source/send_files_enc
mkdir source/send_files_enc
rm -rf source/recv_files_enc
mkdir source/recv_files_enc
truncate -s 0 output_server
truncate -s 0 output_client
truncate -s 0 result