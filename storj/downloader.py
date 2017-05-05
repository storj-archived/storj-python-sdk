
from sys import platform
import os

import logging

import requests

from multiprocessing import Pool

from exception import StorjBridgeApiError, StorjFarmerError
from file_crypto import FileCrypto
from http import Client
from sharder import ShardingTools


MAX_RETRIES_DOWNLOAD_FROM_SAME_FARMER = 3
MAX_RETRIES_GET_FILE_POINTERS = 10


def foo(args):
    self, pointer, shard_index = args
    return self.shard_download(pointer, shard_index)


class Downloader:

    __logger = logging.getLogger('%s.ClassName' % __name__)

    def __init__(self, email, password):
        self.client = Client(email, password, )
        # set config variables
        self.combine_tmpdir_name_with_token = False

    def get_file_pointers_count(self, bucket_id, file_id):
        frame_data = self.client.frame_get(self.file_frame.id)
        return len(frame_data.shards)

    def set_file_metadata(self, bucket_id, file_id):
        try:
            file_metadata = self.client.file_metadata(bucket_id, file_id)
            # Get file name
            self.filename_from_bridge = str(file_metadata.filename)
            self.__logger.debug(
                'Filename from bridge: %s', self.filename_from_bridge)
            # Get file frame
            self.file_frame = file_metadata.frame

        except StorjBridgeApiError as e:
            self.__logger.error(e)
            self.__logger.error('Error while resolving file metadata')

        except Exception as e:
            self.__logger.error(e)
            self.__logger.error('Unhandled error while resolving file metadata')

    def get_paths(self):
        # set default paths
        temp_dir = ""
        if platform == 'linux' or platform == 'linux2':
            # linux
            temp_dir = '/tmp'
        elif platform == 'darwin':
            # OS X
            temp_dir = '/tmp'
        elif platform == 'win32':
            # Windows
            temp_dir = 'C:/Windows/temp'
        home = os.path.expanduser('~')
        return temp_dir, home

    def download_begin(self, bucket_id, file_id):
        # Initialize environment
        self.set_file_metadata(bucket_id, file_id)
        # Get the number of shards
        self.all_shards_count = self.get_file_pointers_count(bucket_id, file_id)
        # Set the paths
        self.tmp_path, self.destination_file_path = self.get_paths()
        self.__logger.debug('temp path %s', self.tmp_path)
        self.__logger.debug('destination path %s', self.destination_file_path)

        mp = Pool()
        try:
            self.__logger.debug(
                'Resolving file pointers to download file with ID: %s ...', file_id)

            tries_get_file_pointers = 0

            while MAX_RETRIES_GET_FILE_POINTERS > tries_get_file_pointers:

                self.__logger.debug(
                    'Attempt number %s of getting a pointer to the file',
                    tries_get_file_pointers)
                tries_get_file_pointers += 1

                try:
                    # Get all the pointers to the shards
                    shard_pointers = self.client.file_pointers(
                        bucket_id,
                        file_id,
                        limit=str(self.all_shards_count),
                        skip='0')
                    self.__logger.debug(
                        'There are %s shard pointers: ', len(shard_pointers))

                    self.__logger.debug('Begin shards download process')
                    mp.map(foo, [(self, p, shard_pointers.index(p)) for p in
                                 shard_pointers])
                except StorjBridgeApiError as e:
                    self.__logger.error(e)
                    self.__logger.error('Bridge error')
                    self.__logger.error(
                        'Error while resolving file pointers to download file with ID: %s ...',
                        file_id)
                    self.__logger.error(e)
                    continue
                else:
                    break

        except StorjBridgeApiError as e:
            self.__logger.error(e)
            self.__logger.error("Outern Bridge error")
            self.__logger.error("Error while resolving file pointers to \
                download file with ID: %s" % str(file_id))

        # All the shards have been downloaded
        self.finish_download()
        return

    def finish_download(self):
        self.__logger.debug('Finish download')
        fileisencrypted = '[DECRYPTED]' not in self.filename_from_bridge

        # Join shards
        sharing_tools = ShardingTools()
        self.__logger.debug('Joining shards...')

        actual_path = os.path.join(self.tmp_path, self.filename_from_bridge)
        destination_path = os.path.join(self.destination_file_path, self.filename_from_bridge)
        self.__logger.debug('Actual path %s', actual_path)
        self.__logger.debug('Destination path %s', destination_path)

        if fileisencrypted:
            sharing_tools.join_shards(
                actual_path,
                '-',
                '%s.encrypted' % actual_path)

        else:
            sharing_tools.join_shards(actual_path, "-", destination_path)

        if fileisencrypted:
            # decrypt file
            self.__logger.debug('Decrypting file...')
            file_crypto_tools = FileCrypto()
            # Begin file decryption
            file_crypto_tools.decrypt_file(
                'AES',
                '%s.encrypted' % actual_path,
                destination_path,
                str(self.client.password))

        self.__logger.debug('Finish decryption')
        self.__logger.info('Download completed successfully!')

        # Remove temp files
        try:
            # Remove shards
            file_shards = map(lambda i: '%s-%s' % (actual_path, i),
                              range(self.all_shards_count))
            map(os.remove, file_shards)
            # Remove encrypted file
            os.remove('%s.encrypted' % actual_path)

        except OSError as e:
            self.__logger.error(e)

        return True

    def create_download_connection(self, url, path_to_save, shard_index):
        farmer_tries = 0

        self.__logger.debug(
            'Downloading shard at index %s from farmer: %s',
            shard_index,
            url)

        tries_download_from_same_farmer = 0
        while MAX_RETRIES_DOWNLOAD_FROM_SAME_FARMER > \
                tries_download_from_same_farmer:

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
                    raise StorjFarmerError()

            except StorjFarmerError as e:
                self.__logger.error(e)
                self.__logger.error("First try failed. Retrying... (%s)" %
                                    str(farmer_tries))  # update shard download state
                continue

            except Exception as e:
                self.__logger.error("Unhandled error")
                self.__logger.error("Error occured while downloading shard \
                    at index %s. Retrying... (%s)" % (shard_index, farmer_tries)
                                    )
                self.__logger.error(e)
                continue
            else:
                break

    def shard_download(self, pointer, shard_index):
        self.__logger.debug('Beginning download proccess...')

        try:
            self.__logger.debug('Starting download threads...')
            self.__logger.debug('Downloading shard at index %s ...', shard_index)

            url = 'http://%s:%s/shards/%s?token=%s' % (
                pointer.get('farmer')['address'],
                str(pointer.get('farmer')['port']),
                pointer['hash'],
                pointer['token'])
            self.__logger.debug(url)

            file_temp_path = "%s-%s" % (
                os.path.join(self.tmp_path, self.filename_from_bridge),
                str(shard_index))
            if self.combine_tmpdir_name_with_token:
                file_temp_path = '%s-%s' % (
                    os.path.join(self.tmp_path,
                                 pointer['token'],
                                 self.filename_from_bridge),
                    str(shard_index))
            else:
                self.__logger.debug('Do not combine tmpdir and token')
            self.create_download_connection(url, file_temp_path, shard_index)

            self.__logger.debug('Shard downloaded')
            self.__logger.debug('Shard at index %s downloaded successfully', shard_index)
            self.__logger.debug('%s saved', file_temp_path)

        except IOError as e:
            self.__logger.error('Perm error %s', e)
            if str(e) == str(13):
                self.__logger.error("""Error while saving or reading file or
                temporary file.
                Probably this is caused by insufficient permisions.
                Please check if you have permissions to write or
                read from selected directories.""")
        except Exception as e:
            self.__logger.error(e)
            self.__logger.error('Unhandled')
