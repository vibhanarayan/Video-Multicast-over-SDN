class MCIPMap(object):
    def __init__(self):
        self.mapping = {}
        self.pool = ["224.0.0." + str(i) for i in range(1,101)]

    def assign_mcip(self, vid_id, hostip):
        if len(self.pool) > 0:
            mcip = self.pool.pop()
            if vid_id in self.mapping:
                self.mapping[vid_id].append((mcip,hostip))
            else:
                self.mapping[vid_id] = [(mcip, hostip)]
            return mcip
        return None
    
    def get_mcip(self, vid_id):
        if vid_id in self.mapping:
            return self.mapping[vid_id]
        else:
            return None
