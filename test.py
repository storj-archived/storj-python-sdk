
import storj
mdc = storj.api.MetadiskClient()
storj.authenticate("Misker@protonmail.com", "pinhead1")
mdc.authenticate("Misker@protonmail.com", "pinhead1")

shardman = storj.sdk.ShardManager("C:/test/test.txt", 1024)

fileman = storj.sdk.FileManager('57aa3ee9dd072de41856f8c6')

# file = mdc.download_file("57aa3ee9dd072de41856f8c6","57ad18df3a91dae863d1ec86")

frames = mdc.get_all_frames()

print shardman.shards[0].all()

mdc.add_shard_to_frame(shardman.shards[0], '57acbb01905cfece30b3671f')
