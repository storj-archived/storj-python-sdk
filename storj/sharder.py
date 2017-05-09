import shutil
import math
import os


class ShardingTools():

    def __init__(self):
        self.MAX_SHARD_SIZE = 4294967296  # 4Gb
        self.SHARD_MULTIPLES_BACK = 4

    def get_optimal_shard_parametrs(self, file_size):
        shard_parameters = {}
        accumulator = 0
        shard_size = None
        while (shard_size is None):
            shard_size = self.determine_shard_size(file_size, accumulator)
            accumulator += 1
        shard_parameters["shard_size"] = str(shard_size)
        shard_parameters["shard_count"] = math.ceil(file_size / shard_size)
        shard_parameters["file_size"] = file_size
        return shard_parameters

    def determine_shard_size(self, file_size, accumulator):

        # Based on <https://github.com/aleitner/shard-size-calculator
        # /blob/master/src/shard_size.c>

        hops = 0

        if (file_size <= 0):
            return 0
            # if accumulator != True:
            # accumulator  = 0
        print accumulator

        # Determine hops back by accumulator
        if ((accumulator - self.SHARD_MULTIPLES_BACK) < 0):
            hops = 0
        else:
            hops = accumulator - self.SHARD_MULTIPLES_BACK

        # accumulator = 10
        byte_multiple = self.shard_size(accumulator)

        check = file_size / byte_multiple
        # print check
        if (check > 0 and check <= 1):
            while (hops > 0 and self.shard_size(hops) > self.MAX_SHARD_SIZE):
                if hops - 1 <= 0:
                    hops = 0
                else:
                    hops = hops - 1
            return self.shard_size(hops)

        # Maximum of 2 ^ 41 * 8 * 1024 * 1024
        if (accumulator > 41):
            return 0

            # return self.determine_shard_size(file_size, ++accumulator)

    def shard_size(self, hops):
        return (8 * (1024 * 1024)) * pow(2, hops)

    def sort_index(self, f1, f2):

        index1 = f1.rfind('-')
        index2 = f2.rfind('-')

        if index1 != -1 and index2 != -1:
            i1 = int(f1[index1:len(f1)])
            i2 = int(f2[index2:len(f2)])
            return i2 - i1

    def join_shards(self, shards, destination_fp):
        print 'Creating output file'

        for shard in shards:
            shutil.copyfileobj(shard, destination_fp)

        print 'Wrote file'
        return True


class ShardingException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return str(self.value)
