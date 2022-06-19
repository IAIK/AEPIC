import click

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

def parse_line(line_no,trace):
    global instruction_history
    current_instruction_and_reg_vals = {}
    
    try:
        current_instruction_and_reg_vals["instruction"] = int(trace[line_no].replace("\"","").split(" ")[0].split("\t")[0],16)
    except:
        current_instruction_and_reg_vals["instruction"] = trace[line_no]
    line_no += 1
    while "RDI=" not in trace[line_no]:
        line_no += 1

    for val in range(line_no,line_no+len(leakable_regs)):
        l = trace[val].split("=")
        if l[1] in current_instruction_and_reg_vals:
            current_instruction_and_reg_vals[l[1].strip().replace("0x","")].append(l[0])
        else:
            current_instruction_and_reg_vals[l[1].strip().replace("0x","")] = [l[0]]
        
        line_no += 1

    #skip also last line
    line_no += 1
    instruction_history.append(current_instruction_and_reg_vals)
    return line_no


#track as long back in the history until
def track_back(line_no,k_idx):
    value = instruction_history[line_no]["instruction"]

    if(type(value) is int):
        page_number = (value & 0x7F000) >> 12
    else:
        #print("double check output in trace no address given at " + value)
        return -1

    #prevent duplicated leakage of same key 
    for vals in leakage_result:
        split = vals.split(",")
        if(value == 0x00007ffff744b282):
            print(hex(page_number))
            print(hex((int(split[0],16) & 0x7F000)>>12))
            print("found")

        if (page_number == (int(split[0],16) & 0x7F000)>>12):
            if k_idx == split[-2]:
                return -1

    
    instructions_till_page_change = 1
    start_offset = line_no - 1

    while start_offset >= 0:
        if(type(instruction_history[start_offset]["instruction"]) is not int):
            start_offset -= 1
            instructions_till_page_change += 1
            continue

        if page_number != ((instruction_history[start_offset]["instruction"] & 0X7F000) >> 12):
            break
        start_offset -= 1
        instructions_till_page_change += 1
        
    return instructions_till_page_change


    
def report_findings(key_splits,trace):
    global instruction_history
    global leakage_result

    #skip first lines in trace until -----
    for i in range(len(trace)):
        if "---" in trace[i]:
            break
    
    #always skip the 
    ctr = i + 1
    insn_counter = 0

    while(ctr + len(leakable_regs) + 2 <= len(trace)):
        ctr = parse_line(ctr,trace)

        # check if one of the registers contains parts of the secret
        for k_idx,k_split in enumerate(key_splits):
            if k_split in instruction_history[insn_counter]:
                leak_regs = "".join(instruction_history[insn_counter][k_split])
                diff = track_back(insn_counter,f'key_{k_idx}')

                if diff != -1:
                    leakage_result.add(f"{hex(instruction_history[insn_counter]['instruction'] & 0xFFFFF)},{diff},{leak_regs.lower()},key_{k_idx},{k_split}")
                    #print(instruction_history[insn_counter])
        
        insn_counter += 1
    
    leakage_result = sorted(leakage_result)
    for l in leakage_result:
        print(l)


@click.command()
@click.argument('key_file',type=click.Path(exists=True))
@click.argument('trace_file', type=click.Path(exists=True))
@click.option('-endianess',default='little')
def main(trace_file,key_file,endianess):
    with open(key_file,"r") as f:
        key = f.readline()
    
    with open(trace_file,"r") as f:
        trace = f.readlines()

    if(endianess == 'little'):
        key = little_endian_hex_str(key)


    #0x will be added again
    key_splits = split_key(key.replace("0x",""),len(key))

    print("Key splits:")

    for knr,ks in enumerate(key_splits):
        print(f"{knr}:{ks}")

    report_findings(key_splits,trace)


if __name__ == "__main__":
    main()
