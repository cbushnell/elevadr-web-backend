

def open_zeek(input_path):
    input_path = "./data/conn.log"
    with open(input_path) as f:
        for line in f.readlines():
            if line[0] == "#":
                pass
            elif line.contains("#fields"):
                
            else:
                data_tuple = line.strip().split()
                #add to relevant dict
                
                print(data_tuple)

open_zeek("Test")