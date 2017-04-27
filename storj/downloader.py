import json
# import logging
import os
from sys import platform
import requests

from sharder import ShardingTools
from file_crypto import FileCrypto
import threading
import exception

import time

from http import Client

from multiprocessing import Pool

MAX_RETRIES_DOWNLOAD_FROM_SAME_FARMER = 3
MAX_RETRIES_GET_FILE_POINTERS = 10


class Downloader:

    def __init__(self, email, password):
        self.client = Client(email, password)
        self.filename_from_bridge = ""

        self.shards_already_downloaded = 0

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

        # set config variables
        self.combine_tmpdir_name_with_token = False

        self.already_started_shard_downloads_count = 0





    # TODO: deprecate it?
    def createNewDownloadInitThread(self, bucket_id, file_id):
        """Call 1
        """
        file_name_resolve_thread = threading.Thread(target=self.download_begin, args=(bucket_id, file_id))
        file_name_resolve_thread.start()



    def createNewDownloadThread(self, url, filelocation, shard_index):
        """Call 2.1
        """
        download_thread = threading.Thread(target=self.create_download_connection,
                                           args=(url,
                                                 filelocation,
                                                 shard_index))
        download_thread.start()



    def get_file_pointers_count(self, bucket_id, file_id):
        """Call 2.1.1
        """
        frame_data = self.client.frame_get(self.file_frame.id)
        return len(frame_data.shards)











    def set_file_metadata(self, bucket_id, file_id):
        """Call 1.1
        """
        try:
            file_metadata = self.client.file_metadata(str(bucket_id), str(file_id))

            self.filename_from_bridge = str(file_metadata.filename)
            print "Filename from bridge: " + self.filename_from_bridge
            self.file_frame = file_metadata.frame
        except exception.StorjBridgeApiError as e:
            print "Error while resolving file metadata. "
            print e
        except Exception as e:
            print "Unhandled error while resolving file metadata. "
            print e







    #### Begin file download finish function ####
    # Wait for signal to do shards joining and encryption
    def finish_download(self, file_name):
        print "Finish download"
        fileisencrypted = False
        if "[DECRYPTED]" in self.filename_from_bridge:
            fileisencrypted = False
        else:
            fileisencrypted = True

        # Join shards
        # TODO
        sharing_tools = ShardingTools()
        print "Joining shards..."

        actual_path = self.tmp_path + "/" + file_name
        if fileisencrypted:
            sharing_tools.join_shards(actual_path, "-",
                                      self.destination_file_path + ".encrypted")
        else:
            sharing_tools.join_shards(actual_path, "-", self.destination_file_path)

        print "TEST: " + actual_path + ".encrypted"

        if fileisencrypted:
            # decrypt file
            print "Decrypting file..."
            file_crypto_tools = FileCrypto()
            # Begin file decryption
            file_crypto_tools.decrypt_file("AES", str(self.destination_file_path) + ".encrypted",
                                           self.destination_file_path,
                                           str(self.client.password))

        print "Finish decryption"
        print "Downloading completed successfully!"
        return True









    def download_begin(self, bucket_id, file_id):
        """Call 1a
        """
        # Initialize environment
        self.bucket_id = bucket_id
        self.file_id = file_id
        self.set_file_metadata(bucket_id, file_id)
        self.all_shards_count = self.get_file_pointers_count(bucket_id, file_id)

        self.destination_file_path = "/home/marco/" + self.filename_from_bridge
        self.tmp_path = "/tmp"

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
                    print "Shard pointers: " + str(shard_pointers)

                    print "Begin shards download process"
                    # TODO: parallelizzare qui
                    for p in range(len(shard_pointers)):
                        self.shard_download(shard_pointers[p], p)
                    #mp.map(lambda p: self.shard_download(
                    #    p,
                    #    shard_pointers.index(i)),
                    #    shard_pointers)
                    # self.shard_download(
                    #      shard_pointer[0],
                    #      self.destination_file_path)
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


        # QUI I DOWNLOAD SONO FINITI
        # All the shards have been downloaded
        self.finish_download(self.filename_from_bridge)
        return















    def create_download_connection(self, url, path_to_save, shard_index):
        """Call 2.2
        """
        downloaded = False
        farmer_tries = 0

        print "Downloading shard at index " + str(shard_index) + " from farmer: " + str(url)

        tries_download_from_same_farmer = 0
        while MAX_RETRIES_DOWNLOAD_FROM_SAME_FARMER > tries_download_from_same_farmer:
            tries_download_from_same_farmer += 1
            farmer_tries += 1
            try:
                self.current_active_connections += 1
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
                # downloaded = True
                break









    def shard_download(self, pointer, shard_index):
        """Call 2
        """
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

            file_temp_path = self.tmp_path + "/" +\
                self.filename_from_bridge +\
                "-" + str(shard_index)
            if self.combine_tmpdir_name_with_token:
                # 2.1
                file_temp_path = self.tmp_path + "/" +\
                    pointer["token"] + "/" +\
                    self.filename_from_bridge +\
                    "-" + str(shard_index)
                self.create_download_connection(url, file_temp_path, shard_index)
                # self.createNewDownloadThread(url,
                #                              file_temp_path,
                #                              shard_index)
            else:
                # 2.1
                print "TEST do not combine tmpdir and token"
                self.create_download_connection(url, file_temp_path, shard_index)
                # self.createNewDownloadThread(
                #     url, file_temp_path,
                #     shard_index)

            print "Shard downloaded"
            print "Shard at index " + str(shard_index) + " downloaded successfully."
            print file_temp_path + " saved"

        except IOError as e:
            print " perm error " + str(e)
            if str(e) == str(13):
                print """Error while saving or reading file or temporary file.
                Probably this is caused by insufficient permisions. Please check
                if you have permissions to write or read from selected
                directories.  """

        except Exception as e:
            print "Unhalded error"
            print e




