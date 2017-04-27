# -*- coding: utf-8 -*-

import os

import base64
import hashlib
import hmac
import logging
import json
import requests
import threading
import time
import model

from Crypto.Cipher import AES
from Crypto import Random

from exception import BridgeError, FarmerError, SuppliedTokenNotAcceptedError
from http import Client


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
        """HMAC hash calculation and returning the results in dictionary collection.

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
            base64_decoded = str(base64.decodestring(shard.hash)) + str(current_hmac)
            current_hmac = self._calculate_hmac(base64_decoded, encryption_key)

        self.__logger.debug('current_hmac=%s', current_hmac)

        return current_hmac

    def createNewUploadThread(self, bucket_id, file_path, tmp_file_path):
        """

        Args:
            bucket_id:
            file_path:
            tmp_file_path:
        """

        self.bid = bucket_id
        self.file_path = file_path
        self.tmp_path = tmp_file_path

        upload_thread = threading.Thread(
            target=self.file_upload,
            args=())
        upload_thread.start()

    def createNewShardUploadThread(self, shard, chapters, frame, file_name):
        """

        Args:
            shard ():
            chapters ():
            frame ():
            file_name ():
        """

        # another worker thread for single shard uploading and
        # it will retry if download fail
        upload_thread = threading.Thread(
            target=self.upload_shard(
                shard=shard,
                chapters=chapters,
                frame=frame,
                file_name_ready_to_shard_upload=file_name),
            args=())
        upload_thread.start()

    def upload_shard(self, shard, chapters, frame, file_name_ready_to_shard_upload):
        """

        Args:
            shard:
            chapters:
            frame:
            file_name_ready_to_shard_upload:
        """

        contract_negotiation_tries = 0
        exchange_report = model.ExchangeReport()

        while self.max_retries_contract_negotiation > contract_negotiation_tries:
            contract_negotiation_tries += 1
            self.__logger.debug('Negotiating contract')
            self.__logger.debug(
                'Trying to negotiate storage contract for shard at index %s...', str(chapters))

            try:
                frame_content = self.client.frame_add_shard(shard, frame.id)

                farmerNodeID = frame_content['farmer']['nodeID']

                url = 'http://%s:%d/shards/%s?token=%s' % (
                    frame_content['farmer']['address'],
                    frame_content['farmer']['port'],
                    frame_content['hash'],
                    frame_content['token'])
                self.__logger.debug('upload_shard url=%s', url)

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
                            'Upload shard at index %s to %s:%d attempt #%d',
                            shard.index,
                            frame_content['farmer']['address'],
                            frame_content['farmer']['port'],
                            farmer_tries)

                        mypath = os.path.join(self.tmp_path,
                                              file_name_ready_to_shard_upload +
                                              '-' + str(chapters + 1))

                        with open(mypath, 'rb') as f:
                            response = requests.post(
                                url,
                                data=self._read_in_chunks(f, shard_index=chapters),
                                timeout=1)

                        j = json.loads(str(response.content))

                        if j.get('result') == 'The supplied token is not accepted':
                            raise SuppliedTokenNotAcceptedError()

                    except FarmerError as e:
                        self.__logger.error(e)
                        continue

                    except Exception as e:
                        self.__logger.error(e)
                        self.__logger.error(
                            'Shard upload error for to %s:%d',
                            frame_content['farmer']['address'], frame_content['farmer']['port'])
                        continue

                    self.shards_already_uploaded += 1
                    self.__logger.info(
                        'Shard uploaded successfully to %s:%d',
                        frame_content['farmer']['address'],
                        frame_content['farmer']['port'])

                    self.__logger.debug(
                        '%s shards, %s sent',
                        self.all_shards_count,
                        self.shards_already_uploaded)

                    if int(self.all_shards_count) <= int(self.shards_already_uploaded):
                        self.__logger.debug('finish upload')

                    break

                self.__logger.debug('response.content=%s', response.content)

                j = json.loads(str(response.content))
                if j.get('result') == 'The supplied token is not accepted':
                    raise SuppliedTokenNotAcceptedError()

            except BridgeError as e:
                self.__logger.error(e)

                # upload failed due to Storj Bridge failure
                self.__logger.debug('Exception raised while trying to negotiate contract: ')
                continue

            except Exception as e:
                # now send Exchange Report
                # upload failed probably while sending data to farmer
                self.__logger.error(e)
                self.__logger.error(
                    'Error occured while trying to upload shard or negotiate contract. Retrying... ')
                self.__logger.error(
                    'Unhandled exception occured while trying to upload shard or negotiate contract for'
                    'shard at index %s . Retrying...', chapters)

                current_timestamp = int(time.time())
                exchange_report.exchangeEnd = str(current_timestamp)
                exchange_report.exchangeResultCode = (exchange_report.FAILURE)
                exchange_report.exchangeResultMessage = (exchange_report.STORJ_REPORT_UPLOAD_ERROR)
                # self.client.send_exchange_report(exchange_report) # send exchange report
                continue

            # uploaded with success
            current_timestamp = int(time.time())
            # prepare second half of exchange heport
            exchange_report.exchangeEnd = str(current_timestamp)
            exchange_report.exchangeResultCode = exchange_report.SUCCESS
            exchange_report.exchangeResultMessage = exchange_report.STORJ_REPORT_SHARD_UPLOADED

            self.__logger.info('Shard %s successfully added and exchange report sent.', chapters + 1)
            # self.client.send_exchange_report(exchange_report) # send exchange report
            break

    def _read_in_chunks(self, file_object, blocksize=4096, chunks=-1, shard_index=None):
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

    def file_upload(self):
        """"""

        bucket_id = self.bid
        file_path = self.file_path
        tmpPath = self.tmp_path

        self.__logger.debug('Upload %s in bucket %d', file_path, bucket_id)
        self.__logger.debug('Temp folder %s', tmpPath)

        encryption_enabled = True

        bname = os.path.split(file_path)[1]  # File name

        file_mime_type = 'text/plain'

        # Encrypt file
        self.__logger.debug('Encrypting file...')

        file_crypto_tools = FileCrypto()
        # Path where to save the encrypted file in temp dir
        file_path_ready = os.path.join(tmpPath,
                                       bname + ".encrypted")
        self.__logger.debug('file_path_ready: %s', file_path_ready)

        # begin file encryption
        file_crypto_tools.encrypt_file(
            'AES',
            file_path,
            file_path_ready,
            self.client.password)

        file_name_ready_to_shard_upload = '%s.encrypted' % bname

        self.fileisdecrypted_str = ''

        file_size = os.stat(file_path).st_size

        # Get the PUSH token from Storj Bridge
        self.__logger.debug('Get PUSH Token')

        push_token = None
        try:
            push_token = self.client.token_create(bucket_id, 'PUSH')
        except BridgeError as e:
            self.__logger.error(e)
            self.__logger.debug('PUSH token create exception')

        self.__logger.debug('PUSH Token ID %s', push_token.id)

        self.__logger.debug('Frame')
        frame = None

        try:
            frame = self.client.frame_create()
        except BridgeError as e:
            self.__logger.error(e)
            self.__logger.debug('Unhandled exception while creating file staging frame')

        self.__logger.debug('frame.id = %s', frame.id)

        # Now encrypt file

        # Now generate shards
        self.__logger.debug('Sharding started...')
        shards_manager = model.ShardManager(filepath=file_path_ready,
                                            tmp_path=self.tmp_path)
        self.all_shards_count = shards_manager.index
        self.__logger.debug('Sharding ended...')

        self.__logger.debug('There are %d shards', self.all_shards_count)

        # create file hash

        chapters = 0

        for shard in shards_manager.shards:
            self.createNewShardUploadThread(shard, chapters, frame, file_name_ready_to_shard_upload)
            chapters += 1

        # finish_upload
        self.__logger.debug('Generating HMAC...')

        hash_sha512_hmac_b64 = self._prepare_bucket_entry_hmac(shards_manager.shards)
        hash_sha512_hmac = hashlib.sha224(str(hash_sha512_hmac_b64['SHA-512'])).hexdigest()

        self.__logger.debug('Now upload file')
        data = {
            'x-token': push_token.id,
            'x-filesize': str(file_size),
            'frame': frame.id,
            'mimetype': file_mime_type,
            'filename': str(bname) + str(self.fileisdecrypted_str),
            'hmac': {
                'type': "sha512",
                'value': hash_sha512_hmac
            },
        }

        self.__logger.debug('Finishing upload')
        self.__logger.debug('Adding file %s to bucket...', bname)

        success = False
        try:
            # TODO

            # This is the actual upload_file method
            response = self.client._request(
                method='POST', path='/buckets/%s/files' % bucket_id,
                # files={'file' : file},
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

        # delete encrypted file (if encrypted and duplicated)
        if encryption_enabled and file_path_ready != "":
            self.__logger.debug('Remove file %s', file_path_ready)
            os.remove('%s*' % file_path_ready)


class FileCrypto:
    """"""

    def encrypt_file(self, algorithm, file_path, encrypted_file_save_path, password):
        """

        Args:
            algorithm:
            file_path:
            encrypted_file_save_path:
            password:
        """

        if algorithm == 'AES':
            with open(file_path, 'rb') as in_file, open(encrypted_file_save_path, 'wb') as out_file:
                self.encrypt_file_aes(in_file, out_file, password)

    def decrypt_file(self, algorithm, file_path, decrypted_file_save_path, password):
        """

        Args:
            algorithm:
            file_path:
            decrypted_file_save_path:
            password:
        """

        if algorithm == 'AES':
            with open(file_path, 'rb') as in_file, open(decrypted_file_save_path, 'wb') as out_file:
                self.decrypt_file_aes(in_file, out_file, password)

    def derive_key_and_iv(self, password, salt, key_length, iv_length):
        """

        Args:
            password:
            salt:
            key_length:
            iv_length:
        """

        d = d_i = ''

        while len(d) < key_length + iv_length:
            d_i = hashlib.md5(d_i + password + salt).digest()
            d += d_i

        return d[:key_length], d[key_length:key_length + iv_length]

    def encrypt_file_aes(self, in_file, out_file, password, key_length=32):
        """

        Args:
            in_file:
            out_file:
            password:
            key_length:
        """

        bs = AES.block_size
        salt = Random.new().read(bs - len('Salted__'))
        key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write('Salted__' + salt)
        finished = False

        while not finished:
            chunk = in_file.read(1024 * bs)
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = bs - (len(chunk) % bs)
                chunk += padding_length * chr(padding_length)
                finished = True
            out_file.write(cipher.encrypt(chunk))

    def decrypt_file_aes(self, in_file, out_file, password, key_length=32):
        """

        Args:
            in_file:
            out_file:
            password:
            key_length:
        """

        bs = AES.block_size
        salt = in_file.read(bs)[len('Salted__'):]
        key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False

        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))

            if len(next_chunk) == 0:
                padding_length = ord(chunk[-1])

                if padding_length < 1 or padding_length > bs:
                    raise ValueError('bad decrypt pad (%d)' % padding_length)

                # all the pad-bytes must be the same
                if chunk[-padding_length:] != (padding_length * chr(padding_length)):
                    # this is similar to the bad decrypt:evp_enc.c from openssl program
                    raise ValueError('bad decrypt')

                chunk = chunk[:-padding_length]
                finished = True

            out_file.write(chunk)