import click
import os
import re
from datetime import datetime
import numpy as np
from soupsieve import match 


leakable_regs = ["rdi","r8","r9","r10","r11","r12","r13","r14","xmm0","xmm1","xmm6","xmm7","xmm8","xmm9"]
instruction_history = []

leakage_result = set()

def split_key(key,key_len):
    key_parts = set()

    #the full key or split
    key_parts.add(key)
    
    #8 byte / 128 byte
    block_sizes = [16,32]

    #special case for XMM:
    for i in range(0,len(key),8):
        key_parts.add(key[i:i+8] + "0" * (24))


    for bs in block_sizes:
        for i in range(0,len(key),bs):
            key_parts.add(key[i:i+bs])
            #pad until register size
    return key_parts


def little_endian_hex_str(hex_str):
    res = ""
    for x in range(len(hex_str),-2, -2):
        res += hex_str[x:x+2]
    return res

def evaluate_results(results_folder,multiple_secrets=False):
    file_ctr = 0
    full_match = 0
    partial_match = 0
    total_second = []
    if multiple_secrets:
        keys = {}
    else:
        key = ""
    
    for file in os.scandir(results_folder):
        with open(os.path.join(results_folder,file.name),"r") as f:
            file_ctr += 1
            lines = f.readlines()
            lines = list(dict.fromkeys(lines))

            #find time
            key_cmp = ""
            leaked_vals = 0
            cmp_keys = {}
            for l in lines:
                new_l = re.sub(r'\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]', '', l)
                
                #secrets should always be printed before the leaked values...
                if multiple_secrets:
                    #this is ugly but it's 
                    # too late to fix this now
                    new_l = re.sub(r'\[idt.c\].*','',new_l)
                    res = re.search("(key_.*:.*)",new_l)
                    if res is not None:
                        key = res.group(0).replace("key_","").split(":")
                        if len(key) == 2 and key[0] != "Invq":
                            keys[key[0].lower()] = key[1].lower().replace("0x","")
                            cmp_keys[key[0].lower()] = "0"*len(keys[key[0].lower()])

                    # search results for keys 
                    res = re.search("( =.*)",new_l)
                    key_part_idx = re.search("(\w+_\d)",new_l)
                    if res != None:
                        leaked_vals += 1
                        result = res.group(0).replace('|','').replace('= ','').strip().replace('00000000','').replace('01000000','')
                        
                        result = little_endian_hex_str(result)

                        if key_part_idx is not None:
                            key_part_split = key_part_idx.group(0).lower().split("_")
                            key_id = key_part_split[0]
                            key_idx = int(key_part_split[1]) - 1

                            #TODO: this is now hard-coded for 64 bit regs 
                            #add parameter for that
                            updated_key_val = list(cmp_keys[key_id])
                            #updated_key_val[key_idx*8] = result
                            for i,j in enumerate(result):
                                updated_key_val[key_idx*16+i] = j
                            
                            cmp_keys[key_id] = "".join(updated_key_val)
                        else:
                            print("There is something wrong with the output format!!!")

                        #split the result relevant for AES
                    # if result not in key_cmp:
                    #     key_cmp += result
                else:
                    res = re.search("(key:.*)",new_l)
                    if res is not None:
                        key = little_endian_hex_str(res.group(0).replace("key:","").lower())
                        

                    res = re.search("( =.*)",new_l)
                    if res != None:
                        result = res.group(0).replace('|','').replace('= ','').strip().replace('00000000','').replace('01000000','')

                        #split the result relevant for AES
                        if result not in key_cmp:
                            key_cmp += result

                    if len(key_cmp) == len(key):
                        break
            #convert key_cmp to little endian
            if multiple_secrets:
                is_full_match = True
                match_cnt = 0
                
                for k,v in cmp_keys.items():
                    if v == keys[k]:
                        match_cnt += 1
                    else:
                        is_full_match = False
                if match_cnt >= 1:
                    partial_match += 1
                elif leaked_vals >= 7:
                    print(f.name)
                else:
                    print("Too few results")
                

                if is_full_match:
                    full_match += 1
            else:
                key_cmp = little_endian_hex_str(key_cmp)
                #print(key)
                #print(key_cmp)
                if(key in key_cmp):
                    full_match += 1
                else:
                    print(f.name)

            #find runtime
            for x in range(len(lines)-1,0,-1):
                t = re.search("(\d+:\d+.\d+elapsed)",lines[x])
                if t is not None:
                    val = datetime.strptime(t.group(0).replace("elapsed",""),'%M:%S.%f')
                    total_second.append(val.minute*60 + val.second + val.microsecond / 1e6)
                    break
            #return
    print(f"Partial: {partial_match / file_ctr}")
    print(f"Full: {full_match / file_ctr}")
    print(f"{np.mean(total_second)} +- {100.0 * np.std(total_second)/np.mean(total_second)}%")



@click.command()
@click.argument('results_folder', type=click.Path(exists=True))
@click.option('--multiple_secrets',type=click.BOOL,default=False)
def main(results_folder,multiple_secrets):
    if not os.path.isdir(results_folder):
        print("results folder must be directory")
        return 

    evaluate_results(results_folder,multiple_secrets)




if __name__ == "__main__":
    main()
