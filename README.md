metadisk-python-sdk
===================

A Python SDK for the Storj Metadisk API


Installation
------------

`pip install metadisk`


Usage
-----

### Create a user account

```python
import metadisk
metadisk.register_new_user(email='someone@email.com', password='a better password than this')
# Check email for confirmation link
```

### Generate a key pair and start using it for authentication

```python
import metadisk
(private_key, public_key) = metadisk.generate_new_key_pair()
metadisk.authenticate(email='someone@email.com', password='a better password than this')
metadisk.public_keys.add(public_key)
metadisk.authenticate(ecdsa_private_key=private_key)
```

### Manage your public keys

```python
import metadisk
# Get all registered public keys
key_list = metadisk.public_keys.all()
# Add a key
metadisk.public_keys.add(public_key)
# Remove one key
metadisk.public_keys.remove(public_key)
# Remove all keys
metadisk.public_keys.clear()
```

### Manage your buckets

```python
import metadisk
# Get all buckets
bucket_list = metadisk.buckets.all()
# Get a single bucket
existing_bucket = metadisk.buckets.get(id='56ef0d4656bf7b950faace7a')
# Create a new bucket
new_bucket = metadisk.buckets.create(name='my first bucket')
another_bucket = metadisk.buckets.create(name='another bucket', storage_limit=300, transfer_limit=100)
# Delete a bucket
new_bucket.delete()
# Delete a bucket without fetching it
metadisk.buckets.delete(bucket_id='56ef0d4656bf7b950faace7a')
```

### Get file metadata for files in a bucket

```python
existing_bucket.files.all()
```

### Create a PUSH or PULL token for a bucket

```python
push_token = existing_bucket.tokens.create(operation='PUSH')
```

### Upload a file

```python
# Use a file path string
new_bucket.files.upload('/path/to/file.txt')
# Or a file handle
with open('/path/to/another/file.png') as file:
    another_bucket.files.upload(file)
```

### Download a file

Not yet implemented.  Waiting for a finalized transfer protocol.

### Delete a file

Not yet implemented.  Waiting for API support.

### Manage a bucket's public keys

```python
# Get all registered public keys
key_list = existing_bucket.authorized_public_keys.all()
# Add a key
existing_bucket.authorized_public_keys.add(public_key)
# Remove a key
existing_bucket.authorized_public_keys.remove(public_key)
# Remove all keys
existing_bucket.authorized_public_keys.clear()
```

### Use your own metadisk API service

```python
import metadisk
metadisk.api_client.base_url = 'https://myserver.org'
```
