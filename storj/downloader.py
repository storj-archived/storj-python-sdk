import os

import logging

import requests

from multiprocessing.pool import ThreadPool
from multiprocessing import TimeoutError
from tempfile import SpooledTemporaryFile

from exception import StorjBridgeApiError, StorjFarmerError, ClientError
from file_crypto import FileCrypto
from http import Client
from sharder import ShardingTools


MAX_RETRIES_DOWNLOAD_FROM_SAME_FARMER = 3
MAX_RETRIES_GET_FILE_POINTERS = 10


class Downloader:

    __logger = logging.getLogger('%s.ClassName' % __name__)

    def __init__(self, email, password, timeout=None):
        self.client = Client(email, password, timeout=timeout)
        self.max_spooled = 10 * 1024 * 1024   # keep files up to 10MiB in memory

    def _calculate_timeout(self, shard_size, mbps=0.5):
        """
        Calculate the timeout with respect to the minimum bandwidth accepted
        by the user (default: 5 Mbps).

        Args:
            shard_size: shard size in Byte
            mbps: upload throughtput. Default 500 kbps
        """
        if not self.client.timeout:
            self.client.timeout = int(shard_size * 8.0 / (1024 ** 2 * mbps))
        self.__logger.info('Set timeout to %s seconds' % self.client.timeout)

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

    def download_begin(self, bucket_id, file_id):
        # Initialize environment
        self.set_file_metadata(bucket_id, file_id)
        # Get the number of shards
        self.all_shards_count = self.get_file_pointers_count(bucket_id, file_id)
        # Set the paths
        self.destination_file_path = os.path.expanduser('~')
        self.__logger.debug('destination path %s', self.destination_file_path)

        mp = ThreadPool()
        shards = None

        try:
            self.__logger.debug(
                'Resolving file pointers to download file with ID: %s ...',
                file_id)

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

                    # Calculate timeout
                    self._calculate_timeout(shard_pointers[0]['size'], mbps=1)

                    # Upload shards thread pool
                    self.__logger.debug('Begin shards download process')
                    shards = mp.map(
                        lambda x: self.shard_download(x[1], x[0], bucket_id,
                                                      file_id),
                        enumerate(shard_pointers))

                except StorjBridgeApiError as e:
                    self.__logger.error(e)
                    self.__logger.error('Bridge error')
                    self.__logger.error('Error while resolving file pointers \
to download file with ID: %s ...', file_id)
                    self.__logger.error(e)
                    continue
                else:
                    break

        except StorjBridgeApiError as e:
            self.__logger.error(e)
            self.__logger.error('Outern Bridge error')
            self.__logger.error('Error while resolving file pointers to \
download file with ID: %s' % str(file_id))

        # All the shards have been downloaded
        self.__logger.debug(shards)
        if shards is not None:
            self.finish_download(shards)

    def finish_download(self, shards):
        self.__logger.debug('Finish download')
        fileisencrypted = '[DECRYPTED]' not in self.filename_from_bridge

        destination_path = os.path.join(self.destination_file_path,
                                        self.filename_from_bridge)
        self.__logger.debug('Destination path %s', destination_path)

        # Join shards
        sharding_tools = ShardingTools()
        self.__logger.debug('Joining shards...')

        try:
            if not fileisencrypted:
                with open(destination_path, 'wb') as destination_fp:
                    sharding_tools.join_shards(shards, destination_fp)

            else:
                with SpooledTemporaryFile(self.max_spooled, 'r+') as encrypted:
                    sharding_tools.join_shards(shards, encrypted)

                    # move file read pointer at beginning
                    encrypted.seek(0)

                    # decrypt file
                    self.__logger.debug('Decrypting file...')
                    file_crypto_tools = FileCrypto()

                    # Begin file decryption
                    with open(destination_path, 'wb') as destination_fp:
                        file_crypto_tools.decrypt_file_aes(
                            encrypted,
                            destination_fp,
                            str(self.client.password))

            self.__logger.debug('Finish decryption')
            self.__logger.info('Download completed successfully!')

        except (OSError, IOError, EOFError) as e:
            self.__logger.error(e)

        finally:
            # delete temporary shards
            for shard in shards:
                shard.close()

        return True

    def retrieve_shard_file(self, url, shard_index):
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
                # data is spooled in memory until the file size exceeds max_size
                shard = SpooledTemporaryFile(self.max_spooled, 'wb')

                # Request the shard
                r = requests.get(url, stream=True, timeout=self.client.timeout)
                if r.status_code != 200 and r.status_code != 304:
                    raise StorjFarmerError()

                # Write the file
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:  # filter out keep-alive new chunks
                        shard.write(chunk)

                # Everything ok
                # move file read pointer at beginning
                shard.seek(0)
                return shard

            except StorjFarmerError as e:
                self.__logger.error(e)
                # Update shard download state
                self.__logger.error('First try failed. Retrying... (%s)' %
                                    str(farmer_tries))

            except requests.exceptions.Timeout as ret:
                self.__logger.error('Request number %s for shard %s timed out.\
Took too much.' % (farmer_tries, shard_index))
                self.__logger.error(ret)

            except Exception as e:
                self.__logger.error(e)
                self.__logger.error('Unhandled error')
                self.__logger.error('Error occured while downloading shard at '
                                    'index %s. Retrying... (%s)' %
                                    (shard_index,
                                     farmer_tries))

        self.__logger.error('Shard download at index %s failed' % shard_index)
        raise ClientError()

    def shard_download(self, pointer, shard_index, bucket_id, file_id):
        self.__logger.debug('Beginning download proccess...')

        try:
            self.__logger.debug('Starting download threads...')
            self.__logger.debug('Downloading shard at index %s ...',
                                shard_index)

            url = 'http://{address}:{port}/shards/{hash}?token={token}'.format(
                address=pointer.get('farmer')['address'],
                port=str(pointer.get('farmer')['port']),
                hash=pointer['hash'],
                token=pointer['token'])
            self.__logger.debug(url)

            tp = ThreadPool(processes=1)
            async_result = tp.apply_async(
                self.retrieve_shard_file,
                (url, shard_index))  # tuple of args for foo
            shard = async_result.get(self.client.timeout)  # get the return value

            # shard = self.retrieve_shard_file(url, shard_index)
            self.__logger.debug('Shard downloaded')
            self.__logger.debug('Shard at index %s downloaded successfully',
                                shard_index)
            return shard

        except IOError as e:
            self.__logger.error('Perm error %s', e)
            if str(e) == str(13):
                self.__logger.error("""Error while saving or reading file or
                temporary file.
                Probably this is caused by insufficient permisions.
                Please check if you have permissions to write or
                read from selected directories.""")

        except TimeoutError:
            self.__logger.warning('Aborting shard %s download due to timeout' %
                                  shard_index)
            tp.terminate()
            self.__logger.warning('Try with a new pointer')
            new_pointer = self.client.file_pointers(
                bucket_id=bucket_id,
                file_id=file_id,
                limit='1',
                skip=str(shard_index),
                exclude=str([pointer['farmer']['nodeID']]))
            self.__logger.debug('Found new pointer')
            return self.shard_download(new_pointer[0], shard_index,
                                       bucket_id, file_id)

        except Exception as e:
            self.__logger.error(e)
            self.__logger.error('Unhandled')
