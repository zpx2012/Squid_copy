import pandas as pd, os, sys, matplotlib.pyplot as plt, numpy as np, re
from datetime import datetime, timedelta
from matplotlib.offsetbox import AnchoredText

pd.options.mode.chained_assignment = None

def load_dataframe(in_file):
    df = pd.read_csv(in_file, sep=',').dropna(how='any')#.drop_duplicates(subset=['is_range','conn','seq_start','seq_end'], keep='first'),error_bad_lines=False
    df['time'] = pd.to_numeric(df['time'],errors='ignore')
    df['seq_start'] = pd.to_numeric(df['seq_start'],errors='ignore')
    df['seq_end'] = pd.to_numeric(df['seq_end'],errors='ignore')
    return df

def find_process_file(search_dir, input_file):
    curl_file_time = datetime.strptime(input_file.split(".txt")[0].split('_')[-1], '%Y%m%d%H%M%S')
    for root, dirs, files in os.walk(os.path.expanduser(search_dir)): 
        for finfo in sorted(files):
            if finfo.startswith("processed_seq") and finfo.endswith(".csv"):
                input_file_time = datetime.strptime(finfo.split(".csv")[0].split('_')[-1], '%Y%m%d%H%M%S')
                if curl_file_time <= input_file_time and input_file_time - curl_file_time < timedelta(0,30):
                    print("Found: %s" % finfo)
                    return finfo
    return None


def get_configs_filename(in_file):
    output = [0, 0, 0]
    fname_fields = in_file.split('.txt')[0].split('_')
    for fname_field in fname_fields:
        if 'range' in fname_field:
            sub_fields = fname_field.split('+')
            output[0] = int(sub_fields[0].strip('optim'))
            num_str = sub_fields[1].strip('range')
            output[1] = int(num_str.split('*')[0])
            output[2] = int(num_str.split('*')[1])
    return output


import pandas as pd

def calculate_loss_rate_from_file(df):
    """
    Calculates the packet loss rate from a tshark capture file in CSV format.

    Args:
        file_path (str): The path to the CSV file.

    Returns:
        float: The estimated loss rate, or None if calculation is not possible.
    """
    try:

        # Data cleaning: convert columns to numeric, coercing errors
        for col in ['data_len', 'tcp_seq_rel']:
            df[col] = pd.to_numeric(df[col], errors='coerce')

        # Drop rows where essential data is missing
        df.dropna(subset=['data_len', 'tcp_seq_rel', 'src_ip'], inplace=True)

        # Cast to integer types
        df['data_len'] = df['data_len'].astype(int)
        df['tcp_seq_rel'] = df['tcp_seq_rel'].astype(int)


        # Let's determine the server's IP.
        server_ip = df.groupby('src_ip')['data_len'].sum().idxmax()
        print(f"Identified server IP: {server_ip}")

        # Filter for packets sent by the server and with data
        server_df = df[(df['src_ip'] == server_ip) & (df['data_len'] > 0)].copy()

        if server_df.empty:
            print("No data packets from the server found.")
            return None

        # Create a list of (sequence_number, type) points
        points = []
        for index, row in server_df.iterrows():
            start_seq = row['tcp_seq_rel']
            end_seq = start_seq + row['data_len']
            points.append((start_seq, 1))
            points.append((end_seq, -1))

        # Sort points
        points.sort()

        # Sweep-line algorithm
        received_bytes = 0
        count = 0
        
        if not points:
            return 0.0

        last_seq = points[0][0]

        for seq, type in points:
            if count > 0:
                received_bytes += seq - last_seq
            
            count += type
            last_seq = seq
            
        # Calculate total expected bytes
        min_seq = server_df['tcp_seq_rel'].min()
        max_seq = (server_df['tcp_seq_rel'] + server_df['data_len']).max()
        total_expected_bytes = max_seq - min_seq

        if total_expected_bytes == 0:
            return 0.0
            
        lost_bytes = total_expected_bytes - received_bytes
        
        loss_rate = lost_bytes / total_expected_bytes
        
        print(f"Total Bytes Received: {received_bytes}")
        print(f"Total Bytes Expected: {total_expected_bytes}")
        print(f"Total Bytes Lost: {lost_bytes}")

        return received_bytes, lost_bytes

    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
        return 0.1,0
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0.1,0



def get_total_recvbytes(dirc, in_file, goodbytes, ports):
    tshark_file = in_file.replace('curl_squid', 'tcpdump').replace('.txt', '.pcap.tshark')
    with open(os.path.join(dirc, tshark_file), 'r') as inf:
        lines = inf.read().splitlines()
        fields = lines[0].split(',')
        if len(fields) == 8:
            df_tshark = pd.read_csv(os.path.join(dirc, tshark_file), lineterminator='\n',sep=',', header =  None, names = ['time','ipid','src_ip','srcport','tcplen','seq','ack','ooo']) #'dstport','rwnd'
    #df_tshark = df_tshark[df_tshark.srcport == 80]
            return df_tshark[df_tshark.seq <= goodbytes]['tcplen'].sum(), 0
        elif len(fields) == 10:
            df_tshark = pd.read_csv(os.path.join(dirc, tshark_file), lineterminator='\n',sep=',', header = None, names = ['time','ipid','src_ip','srcport','dstport','data_len','tcp_seq_rel','ack_sel','rwnd','ooo']) #'dstport','rwnd'
            df_tshark = df_tshark[df_tshark.srcport == 80]
            df_tshark = df_tshark[df_tshark.tcp_seq_rel <= goodbytes]
            received_bytes_sum, lost_bytes_sum = 0,0
            for port in ports:
                #print(df_tshark[df_tshark.dstport == port])
                received_bytes, lost_bytes = calculate_loss_rate_from_file(df_tshark[df_tshark.dstport == port])
                received_bytes_sum += received_bytes
                lost_bytes_sum += lost_bytes
            print(df_tshark[df_tshark.tcp_seq_rel <= goodbytes]['data_len'].sum(),received_bytes_sum)
            return df_tshark[df_tshark.tcp_seq_rel <= goodbytes]['data_len'].sum(), lost_bytes_sum/(lost_bytes_sum+received_bytes_sum)


in_dir = os.path.expanduser(sys.argv[1])
date_string = os.path.basename(os.path.abspath(in_dir))
out_file = in_dir + '/' + sys.argv[2] + "_" + date_string + "_group_throughput.csv"
lossrate = sys.argv[2].split("loss")[0]
tag_fields = sys.argv[2].split('_')
optim_num, fix_num, rtt = 0,0,0
fix_kw, test_kw = '',''
kw_dict = {'group':1, 'thread':2}
for field in tag_fields:
    if 'optim' in field:
        subfields = field.split('optim')
        optim_num = int(subfields[0])
        if 'thread' in subfields[1]:
            fix_kw = 'thread'
            test_kw = 'group'
        elif 'group' in subfields[1]:
            fix_kw = 'group'
            test_kw = 'thread'
        if fix_kw:
            fix_num = int(subfields[1].split(fix_kw)[0])
    elif 'ms' in field:
        rtt = int(field.strip('ms'))
    elif 'wholeset' in field or 'pareto' in field:
        fix_kw = 'wholeset'
print(optim_num, fix_kw, fix_num)
# optim_num, fix_num = 1,3

cols = ['optim_num', 'group_num', 'thread_num', 'range','range_sum','optim','curl','goodbytes','recvedbytes', 'effi', 'lossrate',  'filename']
df_output = pd.DataFrame(columns = cols)

count = 0
with open(out_file, 'w') as outf:
    for root, dirs, files in os.walk(in_dir):
        for in_file in files:
            # print("Process: " + in_file)
            if(in_file.startswith('curl_squid') and in_file.endswith('.txt')) and sys.argv[2] in in_file:
                configs = get_configs_filename(in_file)
                # print(configs, optim_num, configs[kw_dict[fix_kw]], fix_num, configs[0] == optim_num, configs[kw_dict[fix_kw]] == fix_num)
                if True: #configs[0] == optim_num and configs[kw_dict[fix_kw]] == fix_num: #fix_kw == '' or fix_kw == 'wholeset' or (configs[0] == optim_num configs[kw_dict[fix_kw]] == fix_num): #and (configs[1] < 12)
                    print("Process: " + in_file)
                    process_file = find_process_file(in_dir, in_file)
                    total_goodbytes = 87548090
                    if process_file:
                        with open(os.path.join(root, in_file), 'r') as inf:
                            lines = list(filter(None, inf.read().splitlines()))
                            for line in lines[::-1]: 
                                #print(line)                                   
                                if 'curl: (18)' in line or 'curl: (52)' in line or 'curl: (28) Operation too slow' in line:
                                    if 'curl: (18)' in line and '83.4M' in lines[::-2]:
                                        fields = list(filter(None,line.replace('d ','d').split(' ')))
                                        if int(fields[0]) >= 98:
                                            lr = re.findall(r'\d+', line)
                                            total_bytes -= int(lr[1])
                                            break
                                    total_goodbytes = 0
                                    print("\033[31m%s\n\033[0m" % line)
                                    break
                                elif 'curl: (28)' in line:
                                    lr = re.findall(r'\d+', line)
                                    total_goodbytes = int(lr[2])
                                    break

                        if not total_goodbytes:
                            continue

                        # print(total_recvbytes)
                        df = load_dataframe(os.path.join(root, process_file))
                        #print(df[df.is_range=='optim_recv']['port'].unique())
                        total_recvbytes,lossrate = get_total_recvbytes(root, in_file, total_goodbytes, df[df.is_range=='optim_recv']['port'].unique())
                        
                        df = df[ df['seq_start'] <= total_goodbytes ]
                        # 1. check if duration is larger than 59
                        duration = df['time'].iloc[-1] - df['time'].iloc[0]
                        #print(duration_real)
                        #duration = 60

                        df_optim = df[ df.is_range == 'optim_recv']
                        df_optim['byte'] = (df_optim['seq_end'] - df_optim['seq_start'])*8
                        optim_bytes = df_optim['byte'].sum()
                        optim_thrpt = optim_bytes/1024.0/duration

                        df_range = df[ df.is_range == 'range_recv' ]
                        df_range['bytes'] = (df_range['seq_end'] - df_range['seq_start'])*8
                        df_range_sum = df_range.groupby(by=['conn'], as_index=False).sum()
                        range_thrpt = df_range_sum['bytes'].sum()/1024.0/duration

                        df_range_sum['range'] = df_range_sum['bytes']/1024.0/duration
                        df_range_sum['optim_num'] = configs[0]
                        df_range_sum['group_num'] = configs[1]
                        df_range_sum['thread_num'] = configs[2]

                        df_range_sum['optim'] = optim_thrpt
                        df_range_sum['range_sum'] = range_thrpt
                        df_range_sum['curl'] = (optim_thrpt+range_thrpt)/1000.0
                        df_range_sum['goodbytes'] = total_goodbytes
                        df_range_sum['recvedbytes'] = total_recvbytes
                        df_range_sum['effi'] = total_goodbytes*100.0/total_recvbytes
                        df_range_sum['lossrate'] = lossrate
                        df_range_sum['filename'] = in_file
                        df_output = pd.concat([df_output, df_range_sum[cols]])

                        print(total_goodbytes, total_recvbytes, total_goodbytes*100.0/total_recvbytes)
                        print(optim_thrpt, range_thrpt, optim_thrpt+range_thrpt, duration)
                        print()
                        count += 1
                        #if count == 10:
                        #    break
        break


print(df_output)
df_output = df_output[ df_output.range > 0 ]
#df_output = df_output[ df_output.thread_num % 2 == 0]
df_output.to_csv(out_file, encoding='utf-8',index=False)

#df_output_5 = df_output[df_output['lossrate'] <= 0.051]
#df_output_5_above = df_output[df_output['lossrate'] > 0.051]
#df_output_10 = df_output_5_above[df_output_5_above['lossrate'] <= 0.10]
#df_output_10_above = df_output_5_above[df_output_5_above['lossrate'] > 0.10]


#if  fix_kw == '' or fix_kw != 'wholeset':
# fix_kw = 'thread'
# test_kw = 'group'
    # for optinum in [1, 2]:
# fig, axes = plt.subplots(nrows=1, ncols=3, figsize=(9.5,5.5))

# axes1 = df.boxplot(ax=axes[0], column='curl', by='%s_num' % test_kw, showmeans=True)
# axes1.set_ylim(0, 11)
# axes1.set_xlabel('')
# axes1.set_ylabel('Goodput(Mpbs)')
# axes1.set_title(f"{fix_kw} = {i+3}")

# axes2 = df_output.boxplot(ax=axes[1], column='range_sum', by='%s_num' % test_kw, showmeans=True)
# axes2.set_ylim(0, 1100)
# axes2.set_xlabel('')
# axes2.set_ylabel('Goodput(Kpbs)')
# axes2.set_title("Overall Recovery Bandwidth of All Groups")

# axes3 = df_output.boxplot(ax=axes[2], column='effi', by='thread_num', showmeans=True)
# axes3.set_ylim(0, 1000)
# axes3.set_xlabel('')
# axes3.set_ylabel('Efficiency(%)')
# axes3.set_title("Efficiency")
# axes2.text(0.98, 0.98, date_string, ha='right', va='bottom', transform=axes2.transAxes)

# xlabels = {'group':'Number of Threads Inside Each Group', 'thread': 'Number of Group'}

# fig.add_subplot(111, frameon=False)
# plt.figtext(0.98, 0.08, date_string, ha='right', va='bottom', transform=fig.transFigure)
# plt.tick_params(labelcolor='none', top=False, bottom=False, left=False, right=False)
# plt.grid(False)
# plt.xlabel(xlabels[fix_kw]) #Groups, 
# fig.suptitle(f"Optim = {optim_num}, {fix_kw.capitalized()} = {fix_num}, Loss rate = {lossrate}, RTT = 250ms") # lossrate, rtt)
# plt.savefig(out_file.replace('.csv', 'curl_range_sum_%doptim_%d%s.png' % (optim_num, fix_kw, fix_num)), bbox_inches="tight")

