import base64
import hashlib
import hmac

import json
import os
import requests
import threading
import time

import exception
from http import Client
import model

# FileCrypto class
from Crypto.Cipher import AES
from Crypto import Random

MAX_RETRIES_UPLOAD_TO_SAME_FARMER = 3
MAX_RETRIES_NEGOTIATE_CONTRACT = 10


class Uploader:

    def __init__(self, email, password):
        self.client = Client(email, password)
        self.shards_already_uploaded = 0

    def _calculate_hmac(self, base_string, key):
        """
        HMAC hash calculation and returning the results in dictionary collection
        """
        hmacs = dict()
        # --- MD5 ---
        hashed = hmac.new(key, base_string, hashlib.md5)
        hmac_md5 = hashed.digest().encode("base64").rstrip('\n')
        hmacs['MD5'] = hmac_md5
        # --- SHA-1 ---
        hashed = hmac.new(key, base_string, hashlib.sha1)
        hmac_sha1 = hashed.digest().encode("base64").rstrip('\n')
        hmacs['SHA-1'] = hmac_sha1
        # --- SHA-224 ---
        hashed = hmac.new(key, base_string, hashlib.sha224)
        hmac_sha224 = hashed.digest().encode("base64").rstrip('\n')
        hmacs['SHA-224'] = hmac_sha224
        # --- SHA-256 ---
        hashed = hmac.new(key, base_string, hashlib.sha256)
        hmac_sha256 = hashed.digest().encode("base64").rstrip('\n')
        hmacs['SHA-256'] = hmac_sha256
        # --- SHA-384 ---
        hashed = hmac.new(key, base_string, hashlib.sha384)
        hmac_sha384 = hashed.digest().encode("base64").rstrip('\n')
        hmacs['SHA-384'] = hmac_sha384
        # --- SHA-512 ---
        hashed = hmac.new(key, base_string, hashlib.sha512)
        hmac_sha512 = hashed.digest().encode("base64").rstrip('\n')
        hmacs['SHA-512'] = hmac_sha512
        return hmacs

    def _prepare_bucket_entry_hmac(self, shard_array):
        storj_keyring = model.Keyring()
        encryption_key = storj_keyring.get_encryption_key("test")
        current_hmac = ""
        for shard in shard_array:
            base64_decoded = str(base64.decodestring(shard.hash)) + str(current_hmac)
            current_hmac = self._calculate_hmac(base64_decoded, encryption_key)
        print current_hmac
        return current_hmac

    def createNewUploadThread(self, bucket_id, file_path, tmp_file_path):
        self.bid = bucket_id
        self.file_path = file_path
        self.tmp_path = tmp_file_path
        upload_thread = threading.Thread(
            target=self.file_upload,
            args=())
        upload_thread.start()

    def createNewShardUploadThread(self, shard, chapters, frame, file_name):
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
        contract_negotiation_tries = 0
        exchange_report = model.ExchangeReport()
        while MAX_RETRIES_NEGOTIATE_CONTRACT > contract_negotiation_tries:
            contract_negotiation_tries += 1
            print "Negotiating contract"
            print "Trying to negotiate storage contract for shard at \
                    index " + str(chapters) + "..."
            try:
                frame_content = self.client.frame_add_shard(shard, frame.id)

                farmerNodeID = frame_content["farmer"]["nodeID"]

                url = "http://" + frame_content["farmer"]["address"] + ":" +\
                      str(frame_content["farmer"]["port"]) + "/shards/" +\
                      frame_content["hash"] + "?token=" +\
                      frame_content["token"]
                print "URL: " + url

                # begin recording exchange report
                # exchange_report = model.ExchangeReport()

                current_timestamp = int(time.time())

                exchange_report.exchangeStart = str(current_timestamp)
                exchange_report.farmerId = str(farmerNodeID)
                exchange_report.dataHash = str(shard.hash)

                shard_size = int(shard.size)

                farmer_tries = 0
                response = None
                while MAX_RETRIES_UPLOAD_TO_SAME_FARMER > farmer_tries:
                    farmer_tries += 1
                    try:
                        print "Upload shard at index " + str(shard.index) +\
                            " to " +\
                            str(frame_content["farmer"]["address"]) +\
                            ":" +\
                            str(frame_content["farmer"]["port"])

                        mypath = os.path.join(self.tmp_path,
                                              file_name_ready_to_shard_upload +
                                              '-' + str(chapters + 1))
                        with open(mypath, 'rb') as f:
                            response = requests.post(url,
                                                     data=self._read_in_chunks(
                                                         f,
                                                         shard_size,
                                                         shard_index=chapters),
                                                     timeout=1)

                        j = json.loads(str(response.content))
                        print j
                        if (j.get("result") == "The supplied token is not accepted"):
                            raise exception.StorjFarmerError(
                                exception.StorjFarmerError.SUPPLIED_TOKEN_NOT_ACCEPTED)

                    except exception.StorjFarmerError as e:
                        # upload failed due to Farmer Failure
                        print e
                        if str(e) == str(exception.StorjFarmerError.SUPPLIED_TOKEN_NOT_ACCEPTED):
                            print "The supplied token not accepted"
                        continue

                    except Exception as e:
                        print "Shard upload error"
                        print "Error while uploading shard to: " +\
                            str(frame_content["farmer"]["address"]) +\
                            ":" +\
                            str(frame_content["farmer"]["port"]) +\
                            " Retrying... (" + str(farmer_tries) +\
                            ")"
                        print e
                        continue
                    else:
                        self.shards_already_uploaded += 1
                        print "Shard uploaded successfully to " +\
                            str(frame_content["farmer"]["address"]) +\
                            ":" +\
                            str(frame_content["farmer"]["port"])

                        print str(self.all_shards_count) + " shards, " +\
                            str(self.shards_already_uploaded) + " sent"
                        if int(self.all_shards_count) <= int(self.shards_already_uploaded):
                            print "Finish upload"
                            # finish_upload(self)
                        break

                print response.content

                j = json.loads(str(response.content))
                if j.get("result") == "The supplied token is not accepted":
                    raise exception.StorjFarmerError(exception.StorjFarmerError.SUPPLIED_TOKEN_NOT_ACCEPTED)

            except exception.StorjBridgeApiError as e:
                # upload failed due to Storj Bridge failure
                print "Exception raised while trying to negotiate \
                             contract: "
                print e
                continue
            except Exception as e:
                # now send Exchange Report
                # upload failed probably while sending data to farmer
                print "Error occured while trying to upload shard or\
                             negotiate contract. Retrying... "
                print e
                print "Unhandled exception occured while trying to upload \
                    shard or negotiate contract for shard at index " +\
                    str(chapters) + " . Retrying..."

                current_timestamp = int(time.time())
                exchange_report.exchangeEnd = str(current_timestamp)
                exchange_report.exchangeResultCode = (exchange_report.FAILURE)
                exchange_report.exchangeResultMessage = (exchange_report.STORJ_REPORT_UPLOAD_ERROR)
                # self.client.send_exchange_report(exchange_report) # send exchange report
                continue
            else:
                # uploaded with success
                current_timestamp = int(time.time())
                # prepare second half of exchange heport
                exchange_report.exchangeEnd = str(current_timestamp)
                exchange_report.exchangeResultCode = exchange_report.SUCCESS
                exchange_report.exchangeResultMessage = exchange_report.STORJ_REPORT_SHARD_UPLOADED
                print "Shard " + str(chapters + 1) + " successfully added and exchange report sent."
                # self.client.send_exchange_report(exchange_report) # send exchange report
                break

    def _read_in_chunks(self, file_object, shard_size, blocksize=4096, chunks=-1, shard_index=None):
        """Lazy function (generator) to read a file piece by piece.
        Default chunk size: 1k."""
        # chunk number (first is 0)
        i = 0
        while chunks:
            data = file_object.read(blocksize)
            if not data:
                break
            yield data
            i += 1
            t1 = float(shard_size) / float(blocksize)
            if shard_size <= blocksize:
                t1 = 1

            # percent_uploaded = int(round((100.0 * i) / t1))
            print "chunk %d" % i
            chunks -= 1

    def file_upload(self):

        bucket_id = self.bid
        file_path = self.file_path
        tmpPath = self.tmp_path
        print "Upload " + file_path + " in bucket " + bucket_id
        print "Temp folder " + tmpPath

        encryption_enabled = True

        bname = os.path.split(file_path)[1]  # File name

        print bname

        file_mime_type = "text/plain"

        # Encrypt file
        print "Encrypting file..."

        file_crypto_tools = FileCrypto()
        # Path where to save the encrypted file in temp dir
        file_path_ready = os.path.join(tmpPath,
                                       bname + ".encrypted")
        print "temp path: " + file_path_ready
        # begin file encryption"
        file_crypto_tools.encrypt_file(
            "AES",
            file_path,
            file_path_ready,
            self.client.password)

        file_name_ready_to_shard_upload = bname + ".encrypted"
        self.fileisdecrypted_str = ""

        file_size = os.stat(file_path).st_size

        # Get the PUSH token from Storj Bridge
        print "Get PUSH Token"
        push_token = None
        try:
            push_token = self.client.token_create(bucket_id, 'PUSH')
        except exception.StorjBridgeApiError as e:
            print "PUSH token create exception"
            print e

        print "PUSH Token ID " + push_token.id

        print "Frame"
        frame = None  # initialize variable
        try:
            frame = self.client.frame_create()  # Create file frame
        except exception.StorjBridgeApiError as e:
            print "Unhandled exception while creating file staging frame"
            print e

        print "Frame ID: " + frame.id
        # Now encrypt file

        # Now generate shards
        print "Sharding"
        shards_manager = model.ShardManager(filepath=file_path_ready,
                                            tmp_path=self.tmp_path)
        shards_count = shards_manager.index
        print "End sharding"
        print "There are " + str(shards_count) + " shards"
        # create file hash
        # self.client.logger.debug('file_upload() push_token=%s', push_token)

        # upload shards to frame

        # set shards count
        self.all_shards_count = shards_count

        chapters = 0

        for shard in shards_manager.shards:
            self.createNewShardUploadThread(shard, chapters, frame, file_name_ready_to_shard_upload)
            chapters += 1

        # finish_upload
        print "Generating HMAC..."
        hash_sha512_hmac_b64 = self._prepare_bucket_entry_hmac(shards_manager.shards)
        hash_sha512_hmac = hashlib.sha224(str(hash_sha512_hmac_b64["SHA-512"])).hexdigest()
        print "Now upload file"
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

        print "Finishing upload"
        print "Adding file " + str(bname) + " to bucket..."

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
        except exception.StorjBridgeApiError as e:
            print "Unhandled bridge exception"
            print e
        if success:
            print "File uploaded successfully!"

        # delete encrypted file (if encrypted and duplicated)
        if encryption_enabled and file_path_ready != "":
            print "Remove file " + file_path_ready
            os.remove(file_path_ready + "*")


class FileCrypto:

    def encrypt_file(self, algorithm, file_path, encrypted_file_save_path, password):
        if algorithm == "AES":
            with open(file_path, 'rb') as in_file, open(encrypted_file_save_path, 'wb') as out_file:
                self.encrypt_file_aes(in_file, out_file, password)

    def decrypt_file(self, algorithm, file_path, decrypted_file_save_path, password):
        if algorithm == "AES":
            with open(file_path, 'rb') as in_file, open(decrypted_file_save_path, 'wb') as out_file:
                self.decrypt_file_aes(in_file, out_file, password)

    def derive_key_and_iv(self, password, salt, key_length, iv_length):
        d = d_i = ''
        while len(d) < key_length + iv_length:
            d_i = hashlib.md5(d_i + password + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length + iv_length]

    def encrypt_file_aes(self, in_file, out_file, password, key_length=32):
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
                    raise ValueError("bad decrypt pad (%d)" % padding_length)
                # all the pad-bytes must be the same
                if chunk[-padding_length:] != (padding_length * chr(padding_length)):
                    # this is similar to the bad decrypt:evp_enc.c from openssl program
                    raise ValueError("bad decrypt")
                chunk = chunk[:-padding_length]
                finished = True
            out_file.write(chunk)
