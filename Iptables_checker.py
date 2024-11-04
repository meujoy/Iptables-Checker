import json
import paramiko
import pandas as pd

'''
vital feilds to check
["source","target","pt","dpt","summary"]

exception
["in"]
'''
source_ip = "10.1.1.11"
drawer_ip = "192.168.1.60"

def ssh_Iptables(drawer_ip):
   #SSH connection parameters
    hostname = drawer_ip
    port = port #int
    username = 'username'
    password=password

    # Command to run
    command_to_run = 'sudo iptables -t nat -L -nv --line-numbers'

    # Create an SSH client
    client = paramiko.SSHClient()

    # Automatically add the server's host key
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


    try:
        print ("trying to connect....")
        # Connect to the remote server
        client.connect(hostname, username=username, password=password,port = port)

        print("connected")
        # Execute the command
        stdout = client.exec_command(command_to_run,get_pty=True)
        stdout = stdout.readlines()

        with open('iptables.txt', 'w') as file:
          for line in stdout:
           #print (type(line))
           file.write(line)

        # Close the SSH connection
        client.close()

        print(f"IP Tables acquired from {drawer_ip}")

    except Exception as e:
        print(f"An error occurred: {e}")

def iptables_parser():
    with open("iptables.txt", 'r') as file:
        counter = 0
        rules_count = 0
        iptables ={}
        header_list = []
        for line in file.readlines():
            line = line.split()
            if line:
                if counter == 1:
                    header_list = line
                    list1= ["pt","dpt","summary"]
                    header_list.extend(list1)
                if line[0].isdigit():
                    iptables [f'rule{rules_count}'] = dict(zip(header_list, line))
                    iptables[f'rule{rules_count}'].update({'checked': False})
                    rules_count += 1
            counter += 1
        
        with open("iptables_RPI.json",'w') as file:
            json.dump(iptables, file, indent=4)

        return rules_count

def find_duplicates():
    # Convert the dictionary to a DataFrame
    with open("iptables_RPI.json", 'r') as file:
        rules_dict = json.load(file)

    df = pd.DataFrame.from_dict(rules_dict, orient='index')

    # Exclude rows where target is MASQUERADE
    df = df[df['target'] != 'MASQUERADE']

    # Check for duplicates based on the important fields
    important_fields = ['target', 'pt', 'dpt', 'summary']
    duplicates = df[df.duplicated(subset=important_fields, keep=False)]
    
    return duplicates


def check_iptables(source_ip):
    with open("iptables_RPI.json", 'r') as rpi:
        with open("iptables_source.json", 'r') as source:
            rpi_iptables = json.load(rpi)
            source_iptables = json.load(source)
            
            
            if len(rpi_iptables) == 0:
                raise Exception ("Empty iptables")
            if len(rpi_iptables) > len(source_iptables):
                duplicates = find_duplicates()
                if not duplicates.empty:
                    raise Exception (f"duplicates found{duplicates}")
  

            for rule_num_source in range(0,len(source_iptables)): 
                
                for rule_num_rpi in range(0,len(rpi_iptables)): 
                    if source_iptables[f'rule{rule_num_source}']['checked'] == False:

                        # For backward rules
                        if rpi_iptables[f'rule{rule_num_rpi}']['in'] != "*":
                            if (source_iptables[f'rule{rule_num_source}']['target'] == rpi_iptables[f'rule{rule_num_rpi}']['target'] and
                                source_iptables[f'rule{rule_num_source}']['pt'] == rpi_iptables[f'rule{rule_num_rpi}']['pt'] and
                                source_iptables[f'rule{rule_num_source}']['dpt'] == rpi_iptables[f'rule{rule_num_rpi}']['dpt'] and
                                source_iptables[f'rule{rule_num_source}']['summary'] == rpi_iptables[f'rule{rule_num_rpi}']['summary']):
                                source_iptables[f'rule{rule_num_source}']['checked'] = True
                                rpi_iptables[f'rule{rule_num_rpi}']['checked'] = True
                                break

                        # For the rest of the rules
                        if rpi_iptables[f'rule{rule_num_rpi}']['source'] == source_ip:
                            if (source_iptables[f'rule{rule_num_source}']['target'] == rpi_iptables[f'rule{rule_num_rpi}']['target'] and
                                source_iptables[f'rule{rule_num_source}']['pt'] == rpi_iptables[f'rule{rule_num_rpi}']['pt'] and
                                source_iptables[f'rule{rule_num_source}']['dpt'] == rpi_iptables[f'rule{rule_num_rpi}']['dpt'] and
                                source_iptables[f'rule{rule_num_source}']['summary'] == rpi_iptables[f'rule{rule_num_rpi}']['summary']):
                                source_iptables[f'rule{rule_num_source}']['checked'] = True
                                rpi_iptables[f'rule{rule_num_rpi}']['checked'] = True
                                break
        
                        # For masquerade rule
                        if rpi_iptables[f'rule{rule_num_rpi}']['target'] == "MASQUERADE" and rpi_iptables[f'rule{rule_num_rpi}']['target'] == source_iptables[f'rule{rule_num_source}']['target'] :
                            source_iptables[f'rule{rule_num_source}']['checked'] = True
                            rpi_iptables[f'rule{rule_num_rpi}']['checked'] = True
                            break


            with open("output_source.json",'w') as file:
                json.dump(source_iptables, file, indent=4)
            with open("output_rpi.json",'w') as file:
                json.dump(rpi_iptables, file, indent=4)
             


def display_invalid():
    invalid = {}
    with open("output_source.json",'r') as output_source:
        output = json.load(output_source)
        for rule_num in range(len(output)):
            if output[f'rule{rule_num}']['checked'] == False:
                invalid[f'rule{rule_num}'] = output[f'rule{rule_num}']
                #print(f"The rule(s) displayed is/are not right or not found{json.dumps(output[f'rule{rule_num}'],indent=4)}")
    with open("output_rpi.json",'r') as output_rpi:
        output = json.load(output_rpi)
        for rule_num in range(len(output)):
            if output[f'rule{rule_num}']['checked'] == False:
                invalid[f'rule{rule_num}'] = output[f'rule{rule_num}']
                #print(f"The rule(s) displayed is/are not right or not found{json.dumps(output[f'rule{rule_num}'],indent=4)}")

    if invalid:
        print (json.dumps(invalid,indent=4))
    else:
        print ("rules are ok")


if __name__ == "__main__":
    #ssh_Iptables(drawer_ip)
    rules_count = iptables_parser()
    check_iptables(source_ip)
    display_invalid()
    



