import json
import os
from sys import platform
import requests

from sharder import ShardingTools
from file_crypto import FileCrypto
import exception

from http import Client

from multiprocessing import Pool

MAX_RETRIES_DOWNLOAD_FROM_SAME_FARMER = 3
MAX_RETRIES_GET_FILE_POINTERS = 10


def foo(args):
    self, pointer, shard_index = args
    return self.shard_download(pointer, shard_index)


class Downloader:

    def __init__(self, email, password):
        self.client = Client(email, password)
        # set config variables
        self.combine_tmpdir_name_with_token = False

    def get_file_pointers_count(self, bucket_id, file_id):
        frame_data = self.client.frame_get(self.file_frame.id)
        return len(frame_data.shards)

    def set_file_metadata(self, bucket_id, file_id):
        try:
            file_metadata = self.client.file_metadata(str(bucket_id), str(file_id))
            # Get file name
            self.filename_from_bridge = str(file_metadata.filename)
            print "Filename from bridge: " + self.filename_from_bridge
            # Get file frame
            self.file_frame = file_metadata.frame
        except exception.StorjBridgeApiError as e:
            print "Error while resolving file metadata. "
            print e
        except Exception as e:
            print "Unhandled error while resolving file metadata. "
            print e

    def get_paths(self):
        # set default paths
        temp_dir = ""
        if platform == "linux" or platform == "linux2":
            # linux
            temp_dir = "/tmp"
        elif platform == "darwin":
            # OS X
            temp_dir = "/tmp"
        elif platform == "win32":
            # Windows
            temp_dir = "C:/Windows/temp"
        home = os.path.expanduser('~')
        return temp_dir, home

    def download_begin(self, bucket_id, file_id):
        # Initialize environment
        self.bucket_id = bucket_id
        self.file_id = file_id
        # set file name and file frame
        self.set_file_metadata(bucket_id, file_id)
        # get the number of shards
        self.all_shards_count = self.get_file_pointers_count(bucket_id, file_id)
        # set the paths
        self.tmp_path, self.destination_file_path = self.get_paths()
        print "temp path " + self.tmp_path
        print "destination path " + self.destination_file_path

        mp = Pool()
        try:
            print "Resolving file pointers to download file with ID: " +\
                str(file_id) + "..."

            tries_get_file_pointers = 0
            while MAX_RETRIES_GET_FILE_POINTERS > tries_get_file_pointers:
                print "Attempt number %d of getting a pointer to the file" %\
                    tries_get_file_pointers
                tries_get_file_pointers += 1
                try:
                    # Get all the pointers to the shards
                    shard_pointers = self.client.file_pointers(
                        bucket_id,
                        file_id,
                        limit=str(self.all_shards_count),
                        skip="0")
                    print "There are %d shard pointers: " % len(shard_pointers)

                    print "Begin shards download process"
                    mp.map(foo, [(self, p, shard_pointers.index(p)) for p in
                           shard_pointers])
                except exception.StorjBridgeApiError as e:
                    print "Bridge error"
                    print "Error while resolving file pointers \
                        to download file with ID: " +\
                        str(file_id) + "..."
                    print e
                    continue
                else:
                    break

        except exception.StorjBridgeApiError as e:
            print "Outern Bridge error"
            print "Error while resolving file pointers to \
                download file with ID: " +\
                str(file_id)

        # All the shards have been downloaded
        self.finish_download()
        return

    def finish_download(self):
        print "Finish download"
        fileisencrypted = False
        if "[DECRYPTED]" in self.filename_from_bridge:
            fileisencrypted = False
        else:
            fileisencrypted = True

        # Join shards
        sharing_tools = ShardingTools()
        print "Joining shards..."

        actual_path = os.path.join(self.tmp_path, self.filename_from_bridge)
        destination_path = os.path.join(self.destination_file_path,
                                        self.filename_from_bridge)
        print "TEST: actual path " + actual_path
        print "TEST destination path " + destination_path
        if fileisencrypted:
            sharing_tools.join_shards(actual_path, "-",
                                      actual_path + ".encrypted")
        else:
            sharing_tools.join_shards(actual_path, "-", destination_path)

        if fileisencrypted:
            # decrypt file
            print "Decrypting file..."
            file_crypto_tools = FileCrypto()
            # Begin file decryption
            file_crypto_tools.decrypt_file("AES",
                                           actual_path + ".encrypted",
                                           destination_path,
                                           str(self.client.password))

        print "Finish decryption"
        print "Downloading completed successfully!"
        return True

    def create_download_connection(self, url, path_to_save, shard_index):
        downloaded = False
        farmer_tries = 0

        print "Downloading shard at index " + \
            str(shard_index) + " from farmer: " + str(url)

        tries_download_from_same_farmer = 0
        while MAX_RETRIES_DOWNLOAD_FROM_SAME_FARMER > tries_download_from_same_farmer:
            tries_download_from_same_farmer += 1
            farmer_tries += 1
            try:
                r = requests.get(url)
                # Write the file
                with open(path_to_save, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=1024):
                        if chunk:  # filter out keep-alive new chunks
                            f.write(chunk)
                if r.status_code != 200 and r.status_code != 304:
                    raise exception.StorjFarmerError()
            except exception.StorjFarmerError as e:
                print e
                print "First try failed. Retrying... (" + str(farmer_tries) +\
                    ")"  # update shard download state
                continue
            except Exception as e:
                print "Unhandled error"
                print "Error occured while downloading shard at index " +\
                    str(shard_index) + ". Retrying... (" + str(farmer_tries) + ")"
                print e
                continue
            else:
                break

    def shard_download(self, pointer, shard_index):
        print "Beginning download proccess..."
        try:
            # check ability to write files to selected directories
            # if self.tools.isWritable(os.path.split(file_save_path)[0]) is False:
            #     raise IOError("13")
            # if self.tools.isWritable(self.tmp_path) is False:
            #     raise IOError("13")

            print "Starting download threads..."
            print "Downloading shard at index " + str(shard_index) + "..."

            url = "http://" + \
                  pointer.get('farmer')['address'] + \
                  ":" + \
                  str(pointer.get('farmer')['port']) + \
                  "/shards/" + pointer["hash"] + \
                  "?token=" + pointer["token"]
            print url

            file_temp_path = os.path.join(self.tmp_path,
                                          self.filename_from_bridge) +\
                "-" + str(shard_index)
            if self.combine_tmpdir_name_with_token:
                file_temp_path = os.path.join(self.tmp_path,
                                              pointer["token"],
                                              self.filename_from_bridge) +\
                    "-" + str(shard_index)
            else:
                print "TEST do not combine tmpdir and token"
            self.create_download_connection(url, file_temp_path, shard_index)

            print "Shard downloaded"
            print "Shard at index " + str(shard_index) + " downloaded successfully."
            print file_temp_path + " saved"

        except IOError as e:
            print "Perm error " + str(e)
            if str(e) == str(13):
                print """Error while saving or reading file or temporary file.
                Probably this is caused by insufficient permisions. Please check
                if you have permissions to write or read from selected
                directories.  """
        except Exception as e:
            print "Unhalded error"
            print e
