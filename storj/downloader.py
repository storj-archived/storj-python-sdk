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

MAX_RETRIES_DOWNLOAD_FROM_SAME_FARMER = 3
MAX_RETRIES_GET_FILE_POINTERS = 10


class Downloader:

    def __init__(self, email, password, parent=None, bucketid=None, fileid=None):
        self.client = Client(email, password)
        self.filename_from_bridge = ""

        self.bucket_id = bucketid
        self.file_id = fileid

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

        # set overall progress to 0
        #self.ui_single_file_download.overall_progress.setValue(0)

        self.current_active_connections = 0

        self.already_started_shard_downloads_count = 0







    def createNewInitializationThread(self, bucket_id, file_id):
        """Call 1
        """
        file_name_resolve_thread = threading.Thread(target=self.set_file_metadata,
                                                    args=(bucket_id, file_id))
        file_name_resolve_thread.start()



    def createNewDownloadInitThread(self, bucket_id, file_id):
        """Call 2
        """
        self.set_file_metadata(bucket_id, file_id)
        file_name_resolve_thread = threading.Thread(target=self.download_begin, args=(bucket_id, file_id))
        file_name_resolve_thread.start()



    def createNewDownloadThread(self, url, filelocation, options_chain, shard_index):
        """Call 2.2
        """
        download_thread = threading.Thread(target=self.create_download_connection,
                                           args=(url,
                                                 filelocation,
                                                 options_chain,
                                                 shard_index))
        download_thread.start()



    def get_file_pointers_count(self, bucket_id, file_id):
        """Call 2.1.1
        """
        file_frame = self.get_file_frame_id(bucket_id, file_id)
        frame_data = self.client.frame_get(file_frame.id)
        return len(frame_data.shards)











    def set_file_metadata(self, bucket_id, file_id):
        """Call 1.1
        """
        try:
            file_metadata = self.client.file_metadata(str(bucket_id), str(file_id))
            print "Test file metadata: "
            print file_metadata

            self.filename_from_bridge = str(file_metadata.filename)
            print "Filename from bridge: " + self.filename_from_bridge
            self.resolved_file_metadata = True
        except exception.StorjBridgeApiError as e:
            print "Error while resolving file metadata. "
            print e
        except Exception as e:
            print "Unhandled error while resolving file metadata. "
            print e







    def create_download_finish_thread(self, file_name):
        """Call 2.2.1.3
        """
        download_finish_thread = threading.Thread(target=self.finish_download(file_name=file_name), args=())
        download_finish_thread.start()

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

        if fileisencrypted:
            sharing_tools.join_shards(self.tmp_path + "/" + file_name, "-",
                                      self.destination_file_path + ".encrypted")
        else:
            sharing_tools.join_shards(self.tmp_path + "/" + str(file_name), "-", self.destination_file_path)

        print "TEST: " + self.tmp_path + "/" + str(file_name) + ".encrypted"

        if fileisencrypted:
            # decrypt file
            print "Decrypting file..."
            file_crypto_tools = FileCrypto()
            file_crypto_tools.decrypt_file("AES", str(self.destination_file_path) + ".encrypted",
                                           self.destination_file_path,
                                           str(self.client.password))  # begin file decryption

        print "Finish decryption"
        print "Downloading completed successfully!"
        return True





    def request_and_download_next_set_of_pointers(self):
        """Call 2.2.1.2
        """
        print "request and download next set of pointers"
        i = self.already_started_shard_downloads_count
        i2 = 1
        while i < self.all_shards_count and self.current_active_connections + i2 < 4:
            i2 += 1
            tries_get_file_pointers = 0
            while MAX_RETRIES_GET_FILE_POINTERS > tries_get_file_pointers:
                tries_get_file_pointers += 1
                try:
                    options_array = {}
                    options_array["tmp_path"] = self.tmp_path
                    options_array["file_size_is_given"] = "1"
                    options_array["shards_count"] = str(self.all_shards_count)
                    shard_pointer =self.client.file_pointers(
                        self.bucket_id,
                        self.file_id,
                        limit="1",
                        skip=str(i))
                    print shard_pointer[0]
                    options_array["shard_index"] = shard_pointer[0]["index"]

                    options_array["file_size_shard_" + str(i)] = shard_pointer[0]["size"]
                    # TODO: MARCO ??
                    #self.emit(QtCore.SIGNAL("beginShardDownloadProccess"), shard_pointer[0], self.destination_file_path, options_array)
                    print "Begin shard download process"
                    print "MARCO call shard_download function"
                    # 2.1.2
                except exception.StorjBridgeApiError as e:
                    print "Bridge error"
                    print "Error while resolving file pointers to download \
                        file with ID: " + str(self.file_id)
                    continue
                else:
                    break

            self.already_started_shard_downloads_count += 1
            i += 1
        return 1



    '''
    def retry_download_with_new_pointer(self, shard_index):
        print "ponowienie"
        tries_get_file_pointers = 0
        while MAX_RETRIES_GET_FILE_POINTERS > tries_get_file_pointers:
            tries_get_file_pointers += 1
            try:
                options_array = {}
                options_array["tmp_path"] = self.tmp_path
                options_array["progressbars_enabled"] = "1"
                options_array["file_size_is_given"] = "1"
                options_array["shards_count"] = str(self.all_shards_count)
                shard_pointer = self.client.file_pointers(str(self.bucket_id), self.file_id, limit="1",
                                                                             skip=str(shard_index))
                print shard_pointer[0]
                options_array["shard_index"] = shard_pointer[0]["index"]

                options_array["file_size_shard_" + str(shard_index)] = shard_pointer[0]["size"]
                self.emit(QtCore.SIGNAL("beginShardDownloadProccess"), shard_pointer[0],
                          self.destination_file_path, options_array)
            except exception.StorjBridgeApiError as e:
                logger.debug('"title": "Bridge error"')
                logger.debug('"description": "Error while resolving file pointers \
                                                         to download file"')
                self.emit(QtCore.SIGNAL("showStorjBridgeException"), str(e))  # emit Storj Bridge Exception
                continue
            else:
                break

        return 1
    '''




    def download_begin(self, bucket_id, file_id):
        """Call 2.1
        """
        # Call 2.1.1 and 2.1.1.1
        # How many shards does this file have?
        self.all_shards_count = self.get_file_pointers_count(bucket_id, file_id)

        # TODO: delete this variable?
        self.destination_file_path = "/home/marco/" + self.filename_from_bridge
        self.tmp_path = "/tmp"
        # use self.filename_from_bridge instead
        #file_name = os.path.split(self.destination_file_path)[1]


        try:
            print "Resolving file pointers to download file with ID: " +\
                str(file_id) + "..."

            i = 0
            # TODO: 4 or self.all_shards_count?
            #while i < 4:
            while i < self.all_shards_count:
                print "tentativo i = %d" % i
                tries_get_file_pointers = 0
                while MAX_RETRIES_GET_FILE_POINTERS > tries_get_file_pointers:
                    tries_get_file_pointers += 1
                    # time.sleep(1)
                    try:
                        options_array = {}
                        options_array["tmp_path"] = self.tmp_path
                        # options_array["progressbars_enabled"] = "1"
                        options_array["file_size_is_given"] = "1"
                        options_array["shards_count"] = str(self.all_shards_count)
                        shard_pointer = self.client.file_pointers(
                            bucket_id,
                            file_id,
                            limit="1",
                            skip=str(i))
                        print "Shard pointer: " + str(shard_pointer[0])
                        options_array["shard_index"] = shard_pointer[0]["index"]

                        options_array["file_size_shard_" + str(i)] = shard_pointer[0]["size"]
                        #self.emit(QtCore.SIGNAL("beginShardDownloadProccess"), shard_pointer[0], self.destination_file_path, options_array)
                        print "Begin shard download process"
                        print "MARCO call shard_download function"
                        self.shard_download(
                            shard_pointer[0],
                            self.destination_file_path,
                            options_array)
                        # 2.1.2
                    except exception.StorjBridgeApiError as e:
                        print "Bridge error"
                        print "Error while resolving file pointers \
                            to download file with ID: " +\
                            str(file_id) + "..."
                        print e
                        continue
                    else:
                        break

                self.already_started_shard_downloads_count += 1
                i += 1

        except exception.StorjBridgeApiError as e:
            print "Outern Bridge error"
            print "Error while resolving file pointers to \
                download file with ID: " +\
                str(file_id)







    def get_file_frame_id(self, bucket_id, file_id):
        """Call 2.1.1.1 (by get file pointers count)
        """
        try:
            # TODO duplicated?
            file_metadata = self.client.file_metadata(str(bucket_id), str(file_id))
            self.file_frame = file_metadata.frame
        except exception.StorjBridgeApiError as e:
            print "Error while resolving file frame ID."
            print e
        except Exception as e:
            print "Unhandled error while resolving file frame ID."
            print e
        else:
            return self.file_frame






    def set_current_status(self, current_status):
        print 1


    def calculate_final_hmac(self):
        return 1














    def create_download_connection(self, url, path_to_save, options_chain, shard_index):
        """Call 2.2.1
        """
        local_filename = path_to_save
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
                with open(local_filename, 'wb') as f:
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
                downloaded = True
                break

        if not downloaded:
            self.current_active_connections -= 1
            # TODO: MARCO chiamare la funzione?
            # 2.2.1.1
            #self.emit(QtCore.SIGNAL("retryWithNewDownloadPointer"),
            #          shard_index)  # retry download with new download pointer

        else:
            # Get next set of pointers
            # MARCO: qui?
            # 2.2.1.2
            self.request_and_download_next_set_of_pointers()
            #self.emit(QtCore.SIGNAL("getNextSetOfPointers"))
            self.current_active_connections -= 1
            print "Shard downloaded"
            print "Shard at index " + str(shard_index) +\
                " downloaded successfully."
            self.shards_already_downloaded += 1
            if int(self.all_shards_count) <= int(self.shards_already_downloaded):
                # TODO
                # 2.2.1.3
                #self.create_download_finish_thread(os.path.split(str(self.ui_single_file_download.file_save_path.text()))[1])
                self.create_download_finish_thread(self.filename_from_bridge)
                #self.emit(QtCore.SIGNAL("finishDownload"))  # send signal to begin file shards joind and decryption after all shards are downloaded
            return








    def shard_download(self, pointer, file_save_path, options_array):
        """Call 2.1.2
        """
        print "Beginning download proccess..."
        options_chain = {}

        ##### End file download finish point #####

        try:
            # check ability to write files to selected directories
            #if self.tools.isWritable(os.path.split(file_save_path)[0]) is False:
            #    raise IOError("13")
            #if self.tools.isWritable(self.tmp_path) is False:
            #    raise IOError("13")

            try:
                if options_array["file_size_is_given"] == "1":
                    options_chain["file_size_is_given"] = "1"

                shards_count = int(options_array["shards_count"])

                shard_size_array = []
                shard_size_array.append(int(options_array["file_size_shard_" + str(options_array["shard_index"])]))
                print shard_size_array

                part = options_array["shard_index"]

                print "changing tmp_path from " + self.tmp_path +\
                    " to " + options_array["tmp_path"]
                self.tmp_path = options_array["tmp_path"]

                self.set_current_status("Starting download threads...")

                self.set_current_status("Downloading shard at index " + str(part) + "...")

                print pointer
                options_chain["shard_file_size"] = shard_size_array[0]
                url = "http://" + \
                      pointer.get('farmer')['address'] + \
                      ":" + \
                      str(pointer.get('farmer')['port']) + \
                      "/shards/" + pointer["hash"] + \
                      "?token=" + pointer["token"]
                print url

                if self.combine_tmpdir_name_with_token:
                    # 2.2
                    self.createNewDownloadThread(url, self.tmp_path + "/" +
                                                 str(pointer["token"]) +
                                                 "/" +
                                                 str(self.filename_from_bridge) +
                                                 "-" + str(part),
                                                 options_chain,
                                                 part)
                else:
                    # 2.2
                    print "TEST non combinare tmpdir e token"
                    print "TEST filename from bridge: " +\
                    self.filename_from_bridge
                    self.createNewDownloadThread(
                        url, self.tmp_path + "/" +
                        str(self.filename_from_bridge) + "-" + str(part),
                        options_chain, part)

                print self.tmp_path + "/" + self.filename_from_bridge +\
                    "-" + str(part) + "saved"
                part = part + 1

            except Exception as e:
                print e
                print "Unhalded error"

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




