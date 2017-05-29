# -*- coding: utf-8 -*-

import os

import base64
import hashlib
import hmac
import logging
from multiprocessing import Pool
import json
import requests
import time

from file_crypto import FileCrypto

import model

from exception import BridgeError, FarmerError, SuppliedTokenNotAcceptedError
from http import Client

import threading
import thread

TIMEOUT = 60    # default = 1 minute


def foo(args):
    self, shard, shard_index, frame, file_name, tmp_path = args
    return self.upload_shard(shard, shard_index, frame, file_name, tmp_path)


def quit_function(fn_name):
    # self.__logger.debug('{0} took too long'.format(fn_name))
    thread.interrupt_main()  # raises KeyboardInterrupt


def exit_after(s):
    '''
    use as decorator to exit process if
    function takes longer than s seconds
    '''
    def outer(fn):
        def inner(*args, **kwargs):
            timer = threading.Timer(s, quit_function, args=[fn.__name__])
            timer.start()
            try:
                result = fn(*args, **kwargs)
            finally:
                timer.cancel()
            return result
        return inner

    return outer


class Uploader:

    """

    Attributes:
        client (:py:class:`storj.http.Client`): the Storj HTTP client.
        shared_already_uploaded (int): number of shards already uploaded.
        max_retries_contract_negotiation (int): maximum number of contract negotiation retries (default=10).
        max_retries_upload_same_farmer (int): maximum number of uploads retries to the same farmer (default=3).
    """

    __logger = logging.getLogger('%s.Uploader' % __name__)

    def __init__(
            self, email, password,
            max_retries_contract_negotiation=10,
            max_retries_upload_same_farmer=3):

        self.client = Client(email, password)
        self.shards_already_uploaded = 0
        self.max_retries_contract_negotiation = max_retries_contract_negotiation
        self.max_retries_upload_same_farmer = max_retries_upload_same_farmer

    def _calculate_hmac(self, base_string, key):
        """HMAC hash calculation and returning
        the results in dictionary collection.

        Args:
            base_string (): .
            key (): .
        """
        hmacs = dict()
        # --- MD5 ---
        hashed = hmac.new(key, base_string, hashlib.md5)
        hmac_md5 = hashed.digest().encode('base64').rstrip('\n')
        hmacs['MD5'] = hmac_md5
        # --- SHA-1 ---
        hashed = hmac.new(key, base_string, hashlib.sha1)
        hmac_sha1 = hashed.digest().encode('base64').rstrip('\n')
        hmacs['SHA-1'] = hmac_sha1
        # --- SHA-224 ---
        hashed = hmac.new(key, base_string, hashlib.sha224)
        hmac_sha224 = hashed.digest().encode('base64').rstrip('\n')
        hmacs['SHA-224'] = hmac_sha224
        # --- SHA-256 ---
        hashed = hmac.new(key, base_string, hashlib.sha256)
        hmac_sha256 = hashed.digest().encode('base64').rstrip('\n')
        hmacs['SHA-256'] = hmac_sha256
        # --- SHA-384 ---
        hashed = hmac.new(key, base_string, hashlib.sha384)
        hmac_sha384 = hashed.digest().encode('base64').rstrip('\n')
        hmacs['SHA-384'] = hmac_sha384
        # --- SHA-512 ---
        hashed = hmac.new(key, base_string, hashlib.sha512)
        hmac_sha512 = hashed.digest().encode('base64').rstrip('\n')
        hmacs['SHA-512'] = hmac_sha512
        return hmacs

    def _prepare_bucket_entry_hmac(self, shard_array):
        """

        Args:
            shard_array (): .
        """
        storj_keyring = model.Keyring()
        encryption_key = storj_keyring.get_encryption_key('test')
        current_hmac = ''

        for shard in shard_array:
            base64_decoded = '%s%s' % (base64.decodestring(shard.hash),
                                       current_hmac)
            current_hmac = self._calculate_hmac(base64_decoded, encryption_key)

        self.__logger.debug('current_hmac=%s' % current_hmac)

        return current_hmac

    @exit_after(TIMEOUT)
    def require_upload(self, shard_path, url, index):
        with open(shard_path, 'rb') as f:
            response = requests.post(
                url,
                data=self._read_in_chunks(
                    f, shard_index=index),
                timeout=1)
            return response

    def _calculate_timeout(self, shard_size, mbps=0.5):
        """
        Args:
            shard_size: shard size in Byte
            mbps: upload throughtput. Default 500 kbps
        """
        global TIMEOUT
        TIMEOUT = int(shard_size * 8.0 / (1024 ** 2 * mbps))
        self.__logger.debug('Set timeout to %s seconds' % TIMEOUT)

    def upload_shard(self, shard, chapters, frame,
                     file_name_ready_to_shard_upload, tmp_path):
        """

        Args:
            shard:
            chapters:
            frame:
            file_name_ready_to_shard_upload:
            tmp_path:
        """
        contract_negotiation_tries = 0
        exchange_report = model.ExchangeReport()

        while self.max_retries_contract_negotiation > \
                contract_negotiation_tries:
            contract_negotiation_tries += 1
            self.__logger.debug('Negotiating contract')
            self.__logger.debug('Trying to negotiate storage contract for \
shard at index %s. Attempt %s' % (chapters, contract_negotiation_tries))

            try:
                frame_content = self.client.frame_add_shard(shard, frame.id)

                farmerNodeID = frame_content['farmer']['nodeID']

                url = 'http://%s:%d/shards/%s?token=%s' % (
                    frame_content['farmer']['address'],
                    frame_content['farmer']['port'],
                    frame_content['hash'],
                    frame_content['token'])
                self.__logger.debug('Done contract for shard %s with url=%s',
                                    chapters,
                                    url)

                # begin recording exchange report
                # exchange_report = model.ExchangeReport()

                current_timestamp = int(time.time())

                exchange_report.exchangeStart = str(current_timestamp)
                exchange_report.farmerId = str(farmerNodeID)
                exchange_report.dataHash = str(shard.hash)

                farmer_tries = 0
                response = None

                while self.max_retries_upload_same_farmer > farmer_tries:
                    farmer_tries += 1

                    try:
                        self.__logger.debug(
                            'Upload shard at index %s to %s attempt #%d',
                            shard.index,
                            frame_content['farmer']['address'],
                            farmer_tries)

                        mypath = os.path.join(
                            tmp_path, '%s-%s' % (
                                file_name_ready_to_shard_upload,
                                chapters + 1))

                        """
                        with open(mypath, 'rb') as f:
                            response = requests.post(
                                url,
                                data=self._read_in_chunks(
                                    f, shard_index=chapters),
                                timeout=1)
                        """
                        response = self.require_upload(mypath, url, chapters)
                        self.__logger.debug('>>> Shard %s Uploaded' % chapters)

                        j = json.loads(str(response.content))
                        self.__logger.info('>>>> %s' % str(j))

                        if j.get('result') == \
                                'The supplied token is not accepted':
                            raise SuppliedTokenNotAcceptedError()

                    # Exceptions raised when uploading shards
                    except FarmerError as e:
                        self.__logger.error('Farmer error')
                        self.__logger.error(e)
                        continue

                    except KeyboardInterrupt:
                        self.__logger.error()
                        self.__logger.error()
                        self.__logger.error(
                            'Upload shard %s to %s too slow.' % (
                                chapters, url))
                        self.__logger.error(
                            'Upload timed out. Redo upload of shard %s' %
                            chapters)
                        continue

                    except Exception as e:
                        self.__logger.error('Exception')
                        self.__logger.error(e)
                        self.__logger.error(
                            'Shard upload error for %s to %s:%d',
                            chapters,
                            frame_content['farmer']['address'],
                            frame_content['farmer']['port'])
                        continue

                    else:
                        self.shards_already_uploaded += 1
                        self.__logger.info(
                            'Shard uploaded successfully to %s:%d',
                            frame_content['farmer']['address'],
                            frame_content['farmer']['port'])

                        self.__logger.debug(
                            '%s shards, %s sent',
                            self.all_shards_count,
                            self.shards_already_uploaded)

                        if int(self.all_shards_count) <= \
                                int(self.shards_already_uploaded):
                            self.__logger.debug('finish upload')

                        break

            # Exceptions raised negotiating contracts
            except BridgeError as e:
                self.__logger.error('Bridge error')
                self.__logger.error(e)

                # upload failed due to Storj Bridge failure
                self.__logger.debug('Exception raised while trying to \
negotiate contract: ')
                continue

            except Exception as e:
                # now send Exchange Report
                # upload failed probably while sending data to farmer
                self.__logger.error(e)
                self.__logger.error('Error occured while trying to upload \
shard or negotiate contract. Retrying... ')
                self.__logger.error('Unhandled exception occured while trying \
to upload shard or negotiate contract for shard at index %s . Retrying...',
                                    chapters)

                current_timestamp = int(time.time())
                exchange_report.exchangeEnd = str(current_timestamp)
                exchange_report.exchangeResultCode = (exchange_report.FAILURE)
                exchange_report.exchangeResultMessage = \
                    (exchange_report.STORJ_REPORT_UPLOAD_ERROR)
                # Send exchange report
                # self.client.send_exchange_report(exchange_report)
                continue
            else:
                # uploaded with success
                current_timestamp = int(time.time())
                # prepare second half of exchange heport
                exchange_report.exchangeEnd = str(current_timestamp)
                exchange_report.exchangeResultCode = exchange_report.SUCCESS
                exchange_report.exchangeResultMessage = \
                    exchange_report.STORJ_REPORT_SHARD_UPLOADED

                self.__logger.info('Shard %s successfully added and exchange \
report sent.    ', chapters + 1)
                # Send exchange report
                # self.client.send_exchange_report(exchange_report)
                # break
                return True
            return False

    def _read_in_chunks(self, file_object, blocksize=4096, chunks=-1,
                        shard_index=None):
        """Lazy function (generator) to read a file piece by piece.

        Default chunk size: 1k.

        Args:
            file_object (): .
            blocksize (): .
            chunks (): .
        """

        i = 0

        while chunks:
            data = file_object.read(blocksize)
            if not data:
                break
            yield data
            i += 1

            chunks -= 1

    def file_upload(self, bucket_id, file_path, tmp_file_path):
        """"""

        self.__logger.debug('Upload %s in bucket %s', file_path, bucket_id)
        self.__logger.debug('Temp folder %s', tmp_file_path)

        bname = os.path.split(file_path)[1]  # File name

        file_mime_type = 'text/plain'

        # Encrypt file
        self.__logger.debug('Encrypting file...')

        file_crypto_tools = FileCrypto()

        # File name of encrypted file
        file_name_ready_to_shard_upload = '%s.encrypted' % bname
        # Path where to save the encrypted file in temp dir
        file_path_ready = os.path.join(tmp_file_path,
                                       file_name_ready_to_shard_upload)
        self.__logger.debug('file_path_ready: %s', file_path_ready)

        # Begin file encryption
        file_crypto_tools.encrypt_file(
            'AES',
            file_path,
            file_path_ready,
            self.client.password)

        self.fileisdecrypted_str = ''

        file_size = os.stat(file_path).st_size
        self.__logger.debug('File encrypted')

        # Get the PUSH token from Storj Bridge
        self.__logger.debug('Get PUSH Token')

        push_token = None
        try:
            push_token = self.client.token_create(bucket_id, 'PUSH')
        except BridgeError as e:
            self.__logger.error(e)
            self.__logger.debug('PUSH token create exception')

        self.__logger.debug('PUSH Token ID %s', push_token.id)

        # Get a frame
        self.__logger.debug('Frame')
        frame = None

        try:
            frame = self.client.frame_create()
        except BridgeError as e:
            self.__logger.error(e)
            self.__logger.debug('Unhandled exception while creating file \
staging frame')

        self.__logger.debug('frame.id = %s', frame.id)

        # Now generate shards
        self.__logger.debug('Sharding started...')
        shards_manager = model.ShardManager(filepath=file_path_ready,
                                            tmp_path=tmp_file_path)
        self.all_shards_count = len(shards_manager.shards)

        self.__logger.debug('Sharding ended...')

        self.__logger.debug('There are %s shards', self.all_shards_count)

        # Calculate timeout
        self._calculate_timeout(shard_size=shards_manager.shards[0].size,
                                mbps=1)

        # Upload shards
        mp = Pool()
        res = mp.map(foo, [(self, shards_manager.shards[x], x, frame,
                            file_name_ready_to_shard_upload, tmp_file_path)
                           for x in range(len(shards_manager.shards))])

        self.__logger.debug('===== RESULTS =====')
        self.__logger.debug(res)
        if False in res:
            self.__logger.error('File not uploaded: shard %s not uploaded' %
                                res.index(False))
            self.__logger.error('Exiting with errors')
            exit(1)
        # finish_upload
        self.__logger.debug('Generating HMAC...')

        # create file hash
        hash_sha512_hmac_b64 = self._prepare_bucket_entry_hmac(
            shards_manager.shards)
        hash_sha512_hmac = hashlib.sha224(str(
            hash_sha512_hmac_b64['SHA-512'])).hexdigest()

        self.__logger.debug('Now upload file')
        data = {
            'x-token': push_token.id,
            'x-filesize': str(file_size),
            'frame': frame.id,
            'mimetype': file_mime_type,
            'filename': str(bname) + str(self.fileisdecrypted_str),
            'hmac': {
                'type': 'sha512',
                'value': hash_sha512_hmac
            },
        }

        self.__logger.debug('Finishing upload')
        self.__logger.debug('Adding file %s to bucket...', bname)

        success = False
        try:
            # Post an upload_file request
            response = self.client._request(
                method='POST',
                path='/buckets/%s/files' % bucket_id,
                headers={
                    'x-token': push_token.id,
                    'x-filesize': str(file_size),
                },
                json=data,
            )
            success = True

        except BridgeError as e:
            self.__logger.error(e)
            self.__logger.debug('Unhandled bridge exception')

        if success:
            self.__logger.debug('File uploaded successfully!')

        # Remove temp files
        try:
            # Remove shards
            file_shards = map(lambda i: '%s-%s' % (file_path_ready, i),
                              range(1, self.all_shards_count + 1))
            self.__logger.debug('Remove shards %s' % file_shards)
            map(os.remove, file_shards)
            # Remove encrypted file
            self.__logger.debug('Remove encrypted file %s' % file_path_ready)
            os.remove(file_path_ready)
        except OSError as e:
            self.__logger.error(e)
