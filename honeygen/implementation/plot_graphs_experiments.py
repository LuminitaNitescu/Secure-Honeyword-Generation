import os
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.legend import Legend
from scipy import spatial

def produce_flatness_table_info():
    #produce e-flatness table results (Table 5) for chaffing by tweaking HGT.
    statistics = "chaffing_by_tweaking_only/statistics_flatness_graph_a3/"
    
    print("Chaffing by tweaking")
    print("====================")
    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics+filename):
            continue
        with open(statistics+filename) as file:
            lines = file.readlines()

        #read total lines number in selected to be attacked passwords
        with open("password_lists_processed_50000_records/"+filename,"r") as file1:
            total_lines = file1.readlines()
            total_lines = len(total_lines)

        #statistics
        attacker_files=[]
        target_file = filename
        all_probs=[]
        i = 0

        while i < len(lines):
            i+=1
            attacker_file = lines[i].split(" ")
            attacker_file= attacker_file[1]
            attacker_files.append(attacker_file)
            i+=1
            line = lines[i]
            line = line.split(" ")
            del line[len(line)-1]

            all_probs.append(line[0])
            i+=2

        avg = 0
        for z in all_probs:
            avg+=(int(z)/total_lines)

        print("Target file: "+target_file+" Average e-flatness: "+str(avg/len(all_probs)))
        #print("Average e-flatness: "+str(avg/len(all_probs)))
        print()

    print("-------------")
    print()

    #produce e-flattness results for chaffing with a password model hgt
    statistics = "chaffing_by_model_only/statistics_flatness_graph_a3/"
    print("Chaffing with a password model")
    print("==================")
    
    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics+filename):
            continue
        with open(statistics+filename) as file:
            lines = file.readlines()

        #read total lines number in selected to be attacked passwords
        with open("password_lists_processed_50000_records/"+filename,"r") as file1:
            total_lines = file1.readlines()
            total_lines = len(total_lines)

        #statistics
        attacker_files=[]
        target_file = filename
        all_probs=[]
        i = 0

        while i < len(lines):
            i+=1
            attacker_file = lines[i].split(" ")
            attacker_file= attacker_file[1]
            attacker_files.append(attacker_file)
            i+=1
            line = lines[i]
            line = line.split(" ")
            del line[len(line)-1]

            all_probs.append(line[0])
            i+=2

        avg = 0
        for z in all_probs:
            avg+=(int(z)/total_lines)

        print("Target file: "+target_file+" Average e-flatness: "+str(avg/len(all_probs)))
        #print("Average e-flatness: "+str(avg/len(all_probs)))
        print()

    print("--------------")
    print()

    #produce e-flatness table results for chaffing with a hybrid model hgt
    statistics  = "chaffing_by_hybrid_model/statistics_flatness_graph_a3/"
    print("Chaffing with a hybrid model")
    print("==================")

    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics+filename):
            continue
        with open(statistics+filename) as file:
            lines = file.readlines()

        #read total lines number in selected to be attacked passwords
        with open("password_lists_processed_50000_records/"+filename,"r") as file1:
            total_lines = file1.readlines()
            total_lines = len(total_lines)

        #statistics
        attacker_files=[]
        target_file = filename
        all_probs=[]
        i = 0

        while i < len(lines):
            i+=1
            attacker_file = lines[i].split(" ")
            attacker_file= attacker_file[1]
            attacker_files.append(attacker_file)
            i+=1
            line = lines[i]
            line = line.split(" ")
            del line[len(line)-1]

            all_probs.append(line[0])
            i+=2

        avg = 0
        for z in all_probs:
            avg+=(int(z)/total_lines)

        print("Target file: "+target_file+" Average e-flatness: "+str(avg/len(all_probs)))
        #print("Average e-flatness: "+str(avg/len(all_probs)))
        print()

    print("-----------------")
    print()


"This script plots the successful logins vs the honeywords logins for a single target file for each attacker file winth " \
"20 allowed tries."
def plot_single_target_all_t1_20(t2_list,attacker_files,target_file,hgt):

    # process attacker
    temp = []
    for i in attacker_files:
        i = i.replace("_sorted_preprocessed.txt\n", "")
        i = i.replace("-com","")
        i = i.replace("-2016","")
        temp.append(i)
    attacker_files = temp.copy()

    perf_success = []
    perf_fail = []
    y = 1
    x = 19

    max_len=0
    success_res=[]
    for z in range(len(attacker_files)):
        curr_len = len(t2_list[(z+1)*20-1])
        success_res.append(t2_list[(z+1)*20-1])
        if curr_len>max_len:
            max_len=curr_len

    t2 = max_len
    while y <= t2:
        perf_success.append(y)
        perf_fail.append(x)
        x += 19
        y += 1

    fig, ax = plt.subplots()
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.autoscale_view()

    plt.plot(perf_fail, perf_success, "-", markerfacecolor='None', label='random guessing\nbaseline')

    count=0
    for j in success_res:
        perf_success_1 = []
        for z in range(1, len(j)+1):
            perf_success_1.append(z)
        plt.plot(j, perf_success_1, "--", markerfacecolor='None', label=attacker_files[count])
        count+=1


    target_file = target_file.replace("_sorted_preprocessed.txt", "")
    target_file = target_file.replace("-com","")
    target_file = target_file.replace("-2016","")
    if hgt==1:
        plt.title("Chaffing-by-tweaking")
    elif hgt==2:
        plt.title("Chaffing-with-a-password-model")
    elif hgt ==3:
        plt.title("Chaffing-with-a-hybrid-model")
    #plt.title("Target dataset: " + target_file)
    plt.ylabel("Successfull login attempts using real password")
    plt.xlabel("Failed honeyword login attempts")
    plt.legend(loc="lower right", prop={'size': 8}, frameon=False)

    plt.show()

def plot_success_number_graphs(t2_allowed, user_option):
    #first produce tweaking success-number graph.
    statistics = "chaffing_by_tweaking_only/statistics_successful_vs_failed_a3/"

    total_avg = 0
    count=0
    if user_option==3:
        print("Chaffing-by-tweaking attack success rates with T1=20 and T2=61.")
        print("==============")
    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics + filename):
            continue

        #increase counter
        count+=1

        with open(statistics + filename) as file:
            lines = file.readlines()

        if user_option == 2 and filename!='rockyou_sorted_preprocessed.txt':
            continue
        # statistics
        attacker_files = []
        target_file = filename
        all_probs = []
        i = 0
        while i < len(lines):
            i += 1
            attacker_file = lines[i].split(" ")
            attacker_file = attacker_file[1]
            attacker_files.append(attacker_file)
            i += 1

            for z in range(20):

                line = lines[i]
                line = line.split(" ")
                #delete the new line element at the end of the list
                del line[len(line) - 1]

                probs = []
                for j in line:
                    probs.append(int(j))

                all_probs.append(probs)
                i += 1

            # go to the next attacker file line
            i+=1

        # create flatness graph
        if user_option==2:
            plot_single_target_all_t1_20(all_probs, attacker_files, target_file,1)
        elif user_option==3:
           
            total_avg += success_number_table(all_probs, attacker_files, target_file, t2_allowed,statistics)
            print("Total average: "+ str(total_avg/count))
    print("--------------")
    print()
    #next peroduce chaffing by model success-number graph.
    statistics = "chaffing_by_model_only/statistics_successful_vs_failed_a3/"

    total_avg = 0
    count=0
    if user_option==3:
        print("Chaffing-with-a-password-model attack success rates with T1=20 and T2=61.")
        print("==============")
    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics + filename):
            continue

        #increase counter
        count+=1

        with open(statistics + filename) as file:
            lines = file.readlines()
        if user_option == 2 and filename!='rockyou_sorted_preprocessed.txt':
            continue
        # statistics
        attacker_files = []
        target_file = filename
        all_probs = []
        i = 0
        while i < len(lines):
            i += 1
            attacker_file = lines[i].split(" ")
            attacker_file = attacker_file[1]
            attacker_files.append(attacker_file)
            i += 1

            for z in range(20):

                line = lines[i]
                line = line.split(" ")
                #delete the new line element at the end of the list
                del line[len(line) - 1]

                probs = []
                for j in line:
                    probs.append(int(j))

                all_probs.append(probs)
                i += 1

            # go to the next attacker file line
            i+=1

        # create flatness graph
        if user_option==2:
            plot_single_target_all_t1_20(all_probs, attacker_files, target_file,2)
        elif user_option==3:
           
            total_avg += success_number_table(all_probs, attacker_files, target_file, t2_allowed,statistics)
            print("Total average: "+ str(total_avg/count))
    print("--------------")
    print()

    #finally produce chaffing with a hybrid model success-number graph.
    statistics = "chaffing_by_hybrid_model/statistics_successful_vs_failed_a3/"

    total_avg = 0
    count=0
    if user_option==3:
        print("Chaffing-with-a-hybrid-model attack success rates with T1=20 and T2=61.")
        print("==============")
    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics + filename):
            continue

        #increase counter
        count+=1

        with open(statistics + filename) as file:
            lines = file.readlines()
        if user_option == 2 and filename!='rockyou_sorted_preprocessed.txt':
            continue
        # statistics
        attacker_files = []
        target_file = filename
        all_probs = []
        i = 0
        while i < len(lines):
            i += 1
            attacker_file = lines[i].split(" ")
            attacker_file = attacker_file[1]
            attacker_files.append(attacker_file)
            i += 1

            for z in range(20):

                line = lines[i]
                line = line.split(" ")
                #delete the new line element at the end of the list
                del line[len(line) - 1]

                probs = []
                for j in line:
                    probs.append(int(j))

                all_probs.append(probs)
                i += 1

            # go to the next attacker file line
            i+=1

        # create flatness graph
        if user_option==2:
            plot_single_target_all_t1_20(all_probs, attacker_files, target_file,3)
        elif user_option==3:
           
            total_avg += success_number_table(all_probs, attacker_files, target_file, t2_allowed,statistics)
            print("Total average: "+ str(total_avg/count))
    print("--------------")
    print()

def plot_flatness_graph(all_probs,attacker_files,target_file,hgt):
    # plot flatness graph
    # perfect method
    success_rate = []
    login_attempts = []
    prob_e = 1 / 20
    for i in range(1, 21):
        success_rate.append(i * prob_e)
        login_attempts.append(i)

    fig, ax = plt.subplots()
    ax.autoscale_view()
    ax.set_xticks(np.arange(len(login_attempts)+1))

    # perfect adv
    plt.plot(login_attempts, success_rate, "-", markerfacecolor='None', label='random guessing\nbaseline')

    #process attacker
    temp = []
    for i in attacker_files:
        i = i.replace("_sorted_preprocessed.txt\n","")
        i = i.replace("-com","")
        #i = i.replace("-","")
        i = i.replace("-2016","")
        temp.append(i)
    attacker_files = temp.copy()

    # plot experimental values
    for i in range(len(all_probs)):
        plt.plot(login_attempts, all_probs[i], "--", markerfacecolor='None', label=attacker_files[i])


    target_file = target_file.replace("_sorted_preprocessed.txt","")
    target_file = target_file.replace("-com","")
    #target_file = target_file.replace("-","")
    target_file = target_file.replace("-2016","")
    if hgt==1:
        plt.title("Chaffing-by-tweaking")
    elif hgt ==2:
        plt.title("Chaffing-with-a-password-model")
    elif hgt==3:
        plt.title("Chaffing-with-a-hybrid-model")
    #plt.title("Target dataset: "+target_file)
    plt.ylabel("Success rate")
    # plt.ylim([-0.017355596914455252, 0.3644675352035603])
    plt.xlabel("Sweetword login attempts")
    plt.legend(loc="lower right", prop={'size': 8}, frameon=False)

    #att_files=attacker_files[:5]
    #plt.legend(att_files,loc="upper left", prop={'size': 8}, frameon=False)

    # Create the second legend and add the artist manually.
    #att_files =attacker_files[5:]
    #leg = Legend(ax, attacker_files[5:], att_files, loc='lower right', frameon=False)
    #ax.add_artist(leg);

    plt.show()

def plot_flatness_graphs():
    #plot tweaking flatness graph first.
    statistics = "chaffing_by_tweaking_only/statistics_flatness_graph_a3/"

    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics+filename):
            continue
        with open(statistics+filename) as file:
            lines = file.readlines()

        #read total lines number in selected to be attacked passwords
        if filename!='rockyou_sorted_preprocessed.txt':
            continue
        with open("password_lists_processed_50000_records/"+filename,"r") as file1:
            total_lines = file1.readlines()
            total_lines = len(total_lines)

        #statistics
        attacker_files=[]
        target_file = filename
        all_probs=[]
        i = 0
        while i < len(lines):
            i+=1
            attacker_file = lines[i].split(" ")
            attacker_file= attacker_file[1]
            attacker_files.append(attacker_file)
            i+=1
            line = lines[i]
            line = line.split(" ")
            del line[len(line)-1]

            probs=[]
            for j in line:
                probs.append(int(j)/total_lines)

            all_probs.append(probs)
            i+=2

        #create flatness graph
        plot_flatness_graph(all_probs,attacker_files,target_file,1)

    #next plot chaffing with a model flatness graph.
    statistics = "chaffing_by_model_only/statistics_flatness_graph_a3/"

    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics+filename):
            continue
        with open(statistics+filename) as file:
            lines = file.readlines()

        #read total lines number in selected to be attacked passwords
        if filename!='rockyou_sorted_preprocessed.txt':
            continue
        with open("password_lists_processed_50000_records/"+filename,"r") as file1:
            total_lines = file1.readlines()
            total_lines = len(total_lines)

        #statistics
        attacker_files=[]
        target_file = filename
        all_probs=[]
        i = 0
        while i < len(lines):
            i+=1
            attacker_file = lines[i].split(" ")
            attacker_file= attacker_file[1]
            attacker_files.append(attacker_file)
            i+=1
            line = lines[i]
            line = line.split(" ")
            del line[len(line)-1]

            probs=[]
            for j in line:
                probs.append(int(j)/total_lines)

            all_probs.append(probs)
            i+=2

        #create flatness graph
        plot_flatness_graph(all_probs,attacker_files,target_file,2)

    #finally produce chaffing with a hybrid model flatness graph.
    statistics = "chaffing_by_hybrid_model/statistics_flatness_graph_a3/"

    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics+filename):
            continue
        with open(statistics+filename) as file:
            lines = file.readlines()

        #read total lines number in selected to be attacked passwords
        if filename!='rockyou_sorted_preprocessed.txt':
            continue
        with open("password_lists_processed_50000_records/"+filename,"r") as file1:
            total_lines = file1.readlines()
            total_lines = len(total_lines)

        #statistics
        attacker_files=[]
        target_file = filename
        all_probs=[]
        i = 0
        while i < len(lines):
            i+=1
            attacker_file = lines[i].split(" ")
            attacker_file= attacker_file[1]
            attacker_files.append(attacker_file)
            i+=1
            line = lines[i]
            line = line.split(" ")
            del line[len(line)-1]

            probs=[]
            for j in line:
                probs.append(int(j)/total_lines)

            all_probs.append(probs)
            i+=2

        #create flatness graph
        plot_flatness_graph(all_probs,attacker_files,target_file,3)





"This script plots the successful logins vs the honeywords logins for a single target file for each number of allowed" \
"honeyword logins from 1-20 for each attacker file."
def plot_single_target_all_t1(t2_list,attacker_files,target_file):

    # process attacker
    temp = []
    for i in attacker_files:
        i = i.replace("_sorted_preprocessed.txt\n", "")
        temp.append(i)
    attacker_files = temp.copy()

    counter=0
    for i in attacker_files:
        perf_success = []
        perf_fail = []
        y = 1
        x = 19

        max_len=0
        for z in range(20):
            curr_len = len(t2_list[counter+z])
            #curr_len = t2_list[counter+z][-1]
            #print(counter+z)
            #print(curr_len)
            if curr_len>max_len:
                max_len=curr_len

        #print("======")
        #print(max_len)
        #print()

        #t2 = len(t2_list[0])
        t2 = max_len
        while y <= t2:
            # y = (epsilon / (1 - epsilon)) * x
            perf_success.append(y)
            perf_fail.append(x)
            # x += 1
            x += 19
            y += 1

        fig, ax = plt.subplots()
        ax.set_xscale('log')
        ax.set_yscale('log')
        ax.autoscale_view()

        plt.plot(perf_fail, perf_success, "-", markerfacecolor='None', label='random guessing\nbaseline')

        for j in range(20):
            #prepare the graps only for 1,3,5,10 and 20 number of allowed attempts.
            if j!=0 and j!=2 and j!=4 and j!=9 and j!=19:
                counter+=1
                continue
            #prepare perf success
            perf_success_1=[]
            for z in range(1,len(t2_list[counter])+1):
                perf_success_1.append(z)
            plt.plot(t2_list[counter], perf_success_1, "--", markerfacecolor='None', label=str(j+1))
            counter += 1

        target_file = target_file.replace("_sorted_preprocessed.txt", "")
        plt.title("Target dataset: " + target_file+"\n"+"Attacker dataset: "+i.replace("\n",""))
        plt.ylabel("Successfull login attempts using real password")
        plt.xlabel("Failed honeyword login attempts")
        plt.legend(loc="lower right", prop={'size': 8}, frameon=False)
        plt.show()



"This function prints the statitstics for the success number table."
def success_number_table(t2_list,attacker_files,target_file,t2_allowed,statistics):

    #read target file lines
    statistics = statistics.split("/")[0]
    statistics+="/"
    with open(statistics+target_file,"r") as file:
        lines = file.readlines()
    total_records =len(lines)

    # process attacker
    temp = []
    for i in attacker_files:
        i = i.replace("_sorted_preprocessed.txt\n", "")
        i = i.replace("-com","")
        i = i.replace("-2016","")
        temp.append(i)
    attacker_files = temp.copy()

    avg=0
    for i in range(len(attacker_files)):
        successful_guesses=0
        flag=0
        for z in range(len(t2_list[i*20])):
            if t2_list[i*20][z]>t2_allowed:
                successful_guesses=z
                flag=1
                break
            elif t2_list[i*20][z]==t2_allowed:
                successful_guesses=z+1
                flag=1
                break
        if flag==0:
            successful_guesses = z

        #print("Target file: "+target_file)
        #print("Attacker file: "+attacker_files[i])
        #print(t2_list[i*20][z])
        #print("Successful guesses until T2 reached: "+str(successful_guesses))
        #print("=============")
        avg+=successful_guesses


    #calculate average succesfully guessed passwords for all attacker files
    avg = int(avg/(len(attacker_files)))
    #calculate the % of the recovered passwords for the target dataset
    total_average = (avg*100)/total_records
    print("Average % for the target dataset \'"+target_file+"\' is: "+ str(total_average)+ " ("+str(avg)+" records).")
    return total_average







def plot_flatness_vs_tweaking_model_hybrid():
    statistics = ["chaffing_by_tweaking_only/statistics_flatness_graph_a3/","chaffing_by_model_only/statistics_flatness_graph_a3/","chaffing_by_hybrid_model/statistics_flatness_graph_a3/"]
    stats_names=["chaffing-by-tweaking","chaffing-with-a-password-model","chaffing-with-a-hybrid-model"]

    final_stats=[]
    for directory in statistics:
        total_lines_no = 0
        avg_stats = [0 for i in range(20)]
        for filename in os.listdir(directory):
            if not os.path.isfile(directory+filename):
                continue
            with open(directory+filename) as file:
                lines = file.readlines()

            # read total lines number in selected to be attacked passwords
            with open(directory.replace("statistics_flatness_graph_a3/","") + filename, "r") as file1:
                total_lines = file1.readlines()
                total_lines = len(total_lines)

            #statistics
            attacker_files=[]
            i = 0
            while i < len(lines):
                i+=1
                attacker_file = lines[i].split(" ")
                attacker_file= attacker_file[1]
                attacker_files.append(attacker_file)
                i+=1
                line = lines[i]
                line = line.split(" ")
                del line[len(line)-1]
                #print(line)
                for j in range(len(line)):
                    avg_stats[j]+= int(line[j])
                i+=2
                total_lines_no+=1

        #print(total_lines_no)

        #calculate the average for each HGT vector
        avg_stats_temp= []
        for i in range(len(avg_stats)):
            avg_stats_temp.append(int(avg_stats[i]/total_lines_no)/total_lines)

        avg_stats = avg_stats_temp.copy()
        final_stats.append(avg_stats)
    #average stats in final_stats

    # plot flatness graph
    # perfect method
    success_rate = []
    login_attempts = []
    prob_e = 1 / 20
    for i in range(1, 21):
        success_rate.append(i * prob_e)
        login_attempts.append(i)

    fig, ax = plt.subplots()
    ax.autoscale_view()
    #ax.set_xticks(np.arange(len(login_attempts) + 1))
    ax.set_xticks(np.append(np.arange(1,len(login_attempts),5),20))


    # perfect adv
    plt.plot(login_attempts, success_rate, "-", markerfacecolor='None', label='random guessing baseline')

    # plot experimental values
    j=0
    for i in range(len(final_stats)):
        print(final_stats[i])
        plt.plot(login_attempts, final_stats[i], "--", markerfacecolor='None', label=stats_names[j])
        j+=1


    #plt.title("Target dataset: ")
    plt.title("Average flatness graph")
    plt.ylabel("Success rate")
    # plt.ylim([-0.017355596914455252, 0.3644675352035603])
    plt.xlabel("Sweetword login attempts")
    #plt.legend(loc="lower right", prop={'size': 8}, frameon=False)
    plt.legend(loc="upper left", prop={'size': 8}, frameon=False)

    # att_files=attacker_files[:5]
    # plt.legend(att_files,loc="upper left", prop={'size': 8}, frameon=False)

    # Create the second legend and add the artist manually.
    # att_files =attacker_files[5:]
    # leg = Legend(ax, attacker_files[5:], att_files, loc='lower right', frameon=False)
    # ax.add_artist(leg);

    plt.show()

    #show cosine similarity between vectors
    print("Consine similarity between 1st and perfect vector:")
    dist= 1-spatial.distance.cosine(final_stats[0],success_rate)
    print(dist)

    print("Consine similarity between 2nd and perfect vector:")
    dist = 1 - spatial.distance.cosine(final_stats[1], success_rate)
    print(dist)

    print("Consine similarity between 3rd and perfect vector:")
    dist = 1 - spatial.distance.cosine(final_stats[2], success_rate)
    print(dist)


def plot_success_number_vs_tweaking_model_hybrid():
    statistics = ["chaffing_by_tweaking_only/statistics_successful_vs_failed_a3/","chaffing_by_model_only/statistics_successful_vs_failed_a3/","chaffing_by_hybrid_model/statistics_successful_vs_failed_a3/"]
    stats_names=["chaffing-by-tweaking","chaffing-with-a-password-model","chaffing-with-a-hybrid-model"]

    final_stats = []
    for directory in statistics:
        total_lines_no = 0
        all_probs = []
        for filename in os.listdir(directory):
            if not os.path.isfile(directory + filename):
                continue

            with open(directory + filename) as file:
                lines = file.readlines()

            # statistics
            attacker_files = []
            target_file = filename
            i = 0
            while i < len(lines):
                i += 1
                attacker_file = lines[i].split(" ")
                attacker_file = attacker_file[1]
                attacker_files.append(attacker_file)
                i += 20 # go to the line where the t1=20 i.e., an attacker is allowed to use all 20 sweetwords
                line = lines[i]
                line = line.split(" ")
                del line[len(line)-1] #remove the \n element from the list
                probs=[]
                for j in line:
                    probs.append((int(j)))

                all_probs.append(probs)
                i += 1 #skip ======== line

                i += 1 # go to the next attacker file line
                total_lines_no+=1

        if total_lines_no!=len(all_probs):
            print("Error: False division!")
            exit(0)

        avg_all_probs=[0 for i in range(len(all_probs[0]))]
        for i in all_probs:
            for z in range(len(i)):
                avg_all_probs[z]+=int(i[z])
        for i in range(len(avg_all_probs)):
            avg_all_probs[i]/=len(all_probs)

        final_stats.append(avg_all_probs) #append average success-vs-failed honeyword logins to the final stats list

    #until here we have the averaged vectors for each of the 3 HGTs in the final stats list. Now let's plot the success-number graph comparing those techniques.
    #first plot the random guessing baseline
    perf_success = []
    perf_fail = []
    y = 1
    x = 19
    while y <= len(final_stats[0]):
        perf_success.append(y)
        perf_fail.append(x)
        x += 19
        y += 1
    fig, ax = plt.subplots()
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.autoscale_view()
    plt.plot(perf_fail, perf_success, "-", markerfacecolor='None', label='random guessing baseline')

    #now plot the graphs for the 3 HGTs.
    j=0
    for i in final_stats:
        plt.plot(i, perf_success, "--", markerfacecolor='None', label=stats_names[j])
        j+=1

    #plt.title("Target dataset: " + target_file)
    plt.title("Average success-number graph")	
    plt.ylabel("Successful login attempts\nusing real password")
    plt.xlabel("Failed honeyword login attempts")
    #plt.legend(loc="lower right", prop={'size': 8}, frameon=False)
    plt.legend(loc="upper left", prop={'size': 8}, frameon=False)
    plt.show()

    # show cosine similarity between vectors
    print("Consine similarity between 1st and perfect vector:")
    dist = 1 - spatial.distance.cosine(final_stats[0], perf_success)
    print(dist)

    print("Consine similarity between 2nd and perfect vector:")
    dist = 1 - spatial.distance.cosine(final_stats[1], perf_success)
    print(dist)

    print("Consine similarity between 3rd and perfect vector:")
    dist = 1 - spatial.distance.cosine(final_stats[2], perf_success)
    print(dist)



def plot_8_vs_12andbigger_passwords_flatness():
    path = "chaffing_by_hybrid_model==8/statistics_flatness_graph_test/"
    path2 = "chaffing_by_hybrid_model_>=12/statistics_flatness_graph_test/"
    statistics = os.listdir(path)
    statistics2 = os.listdir(path2)
    stats_names=["8",">=12"]

    final_stats = []
    #get results for path, i.e., passwords with length == 8
    for filename in statistics:
        if not os.path.isfile(path+filename):
            continue

        with open(path+filename) as file:
            lines = file.readlines()

        # statistics
        attacker_files = []
        target_file = filename
        total_lines_no = 0
        all_probs = [0 for i in range(20)]

        i = 0
        while i < len(lines):
            i += 1
            attacker_file = lines[i].split(" ")
            attacker_file = attacker_file[1]
            attacker_files.append(attacker_file)
            i += 1
            line = lines[i]
            line = line.split(" ")
            del line[len(line) - 1]
            # print(line)
            for j in range(len(line)):
                all_probs[j] += int(line[j])
            i += 2
            total_lines_no += 1

        # calculate the average for each HGT vector
        avg_stats_temp = []
        for i in range(len(all_probs)):
            avg_stats_temp.append(int(all_probs[i] / total_lines_no))

        final_stats.append(avg_stats_temp) #append average success-vs-failed honeyword logins to the final stats list

    # get results for path2, i.e., passwords with length >= 12
    for filename in statistics2:
        if not os.path.isfile(path2 + filename):
            continue

        with open(path2 + filename) as file:
            lines = file.readlines()

        # statistics
        attacker_files = []
        target_file = filename
        total_lines_no = 0
        all_probs = [0 for i in range(20)]

        i = 0
        while i < len(lines):
            i += 1
            attacker_file = lines[i].split(" ")
            attacker_file = attacker_file[1]
            attacker_files.append(attacker_file)
            i += 1
            line = lines[i]
            line = line.split(" ")
            del line[len(line) - 1]
            # print(line)
            for j in range(len(line)):
                all_probs[j] += int(line[j])
            i += 2
            total_lines_no += 1

        # calculate the average for each HGT vector
        avg_stats_temp = []
        for i in range(len(all_probs)):
            avg_stats_temp.append(int(all_probs[i] / total_lines_no))

        final_stats.append(avg_stats_temp)  # append average success-vs-failed honeyword logins to the final stats list

    for i in range(len(final_stats)):
        for j in range(len(final_stats[0])):
            final_stats[i][j]/=final_stats[i][len(final_stats[i])-1]


    #until here we have the average flatness vectors for passwords with length 8 and >=12
    # plot flatness graph
    # perfect method
    success_rate = []
    login_attempts = []
    prob_e = 1 / 20
    for i in range(1, 21):
        success_rate.append(i * prob_e)
        login_attempts.append(i)

    fig, ax = plt.subplots()
    ax.autoscale_view()
    ax.set_xticks(np.arange(len(login_attempts) + 1))

    # perfect adv
    plt.plot(login_attempts, success_rate, "-", markerfacecolor='None', label='random guessing baseline')

    # plot experimental values
    j = 0
    for i in range(len(final_stats)):
        plt.plot(login_attempts, final_stats[i], "--", markerfacecolor='None', label=stats_names[j])
        j += 1

    # plt.title("Target dataset: ")
    #plt.title("Average flatness graph")
    plt.ylabel("Success rate")
    #plt.ylabel("Success rate", fontsize=12)
    # plt.ylim([-0.017355596914455252, 0.3644675352035603])
    plt.xlabel("Sweetword login attempts")
    plt.legend(loc="lower right", prop={'size': 10}, frameon=False)

    # att_files=attacker_files[:5]
    # plt.legend(att_files,loc="upper left", prop={'size': 8}, frameon=False)

    # Create the second legend and add the artist manually.
    # att_files =attacker_files[5:]
    # leg = Legend(ax, attacker_files[5:], att_files, loc='lower right', frameon=False)
    # ax.add_artist(leg);

    plt.show()


def plot_8_vs_12andbigger_passwords_success_number():
    path = "chaffing_by_hybrid_model==8/statistics_successful_vs_failed_test/"
    path2 = "chaffing_by_hybrid_model_>=12/statistics_successful_vs_failed_test/"
    statistics = os.listdir(path)
    statistics2 = os.listdir(path2)
    stats_names=["8",">=12"]

    final_stats = []
    #get results for path, i.e., passwords with length == 8
    for filename in statistics:
        if not os.path.isfile(path+filename):
            continue

        all_probs=[]
        total_lines_no=0
        with open(path+filename) as file:
            lines = file.readlines()
            # statistics
            attacker_files = []
            target_file = filename
            i = 0
            while i < len(lines):
                i += 1
                attacker_file = lines[i].split(" ")
                attacker_file = attacker_file[1]
                attacker_files.append(attacker_file)
                i += 20  # go to the line where the t1=20 i.e., an attacker is allowed to use all 20 sweetwords
                line = lines[i]
                line = line.split(" ")
                del line[len(line) - 1]  # remove the \n element from the list
                probs = []
                for j in line:
                    probs.append((int(j)))

                all_probs.append(probs)
                i += 1  # skip ======== line

                i += 1  # go to the next attacker file line
                total_lines_no += 1

        if total_lines_no != len(all_probs):
            print("Error: False division!")
            exit(0)

        avg_all_probs = [0 for i in range(len(all_probs[0]))]
        for i in all_probs:
            for z in range(len(i)):
                avg_all_probs[z] += int(i[z])
        for i in range(len(avg_all_probs)):
            avg_all_probs[i] /= len(all_probs)

        final_stats.append(avg_all_probs)  # append average success-vs-failed honeyword logins to the final stats list

    # get results for path2, i.e., passwords with length >=12
    for filename in statistics2:
        if not os.path.isfile(path2 + filename):
            continue

        all_probs = []
        total_lines_no = 0
        with open(path2 + filename) as file:
            lines = file.readlines()
            # statistics
            attacker_files = []
            target_file = filename
            i = 0
            while i < len(lines):
                i += 1
                attacker_file = lines[i].split(" ")
                attacker_file = attacker_file[1]
                attacker_files.append(attacker_file)
                i += 20  # go to the line where the t1=20 i.e., an attacker is allowed to use all 20 sweetwords
                line = lines[i]
                line = line.split(" ")
                del line[len(line) - 1]  # remove the \n element from the list
                probs = []
                for j in line:
                    probs.append((int(j)))

                all_probs.append(probs)
                i += 1  # skip ======== line

                i += 1  # go to the next attacker file line
                total_lines_no += 1

        if total_lines_no != len(all_probs):
            print("Error: False division!")
            exit(0)

        avg_all_probs = [0 for i in range(len(all_probs[0]))]
        for i in all_probs:
            for z in range(len(i)):
                avg_all_probs[z] += int(i[z])
        for i in range(len(avg_all_probs)):
            avg_all_probs[i] /= len(all_probs)

        final_stats.append(avg_all_probs)  # append average success-vs-failed honeyword logins to the final stats list

    for i in final_stats:
        count=0
        for j in i:
            if j>=61:
                print(count)
                break
            count+=1

    #until here we have the averaged vectors for each of the 3 HGTs in the final stats list. Now let's plot the success-number graph comparing those techniques.
    #first plot the random guessing baseline
    perf_success = []
    perf_fail = []
    y = 1
    x = 19
    while y <= len(final_stats[0]):
        perf_success.append(y)
        perf_fail.append(x)
        x += 19
        y += 1
    fig, ax = plt.subplots()
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.autoscale_view()
    plt.plot(perf_fail, perf_success, "-", markerfacecolor='None', label='random guessing baseline')


    #now plot the graphs for the 3 HGTs.
    j=0
    for i in final_stats:
        plt.plot(i, perf_success, "--", markerfacecolor='None', label=stats_names[j])
        j+=1

    #plt.title("Target dataset: " + target_file)
    plt.ylabel("Successful login attempts\nusing real password")
    plt.xlabel("Failed honeyword login attempts")
    plt.legend(loc="lower right", prop={'size': 10}, frameon=False)
    plt.show()

def plot_user_study():

    #the flatness graph results from the user_study.xls
    final_stats=[[0.063636364,0.121212121,0.163636364,0.184848485,0.239393939]]
    stats_names=["HoneyGen's chaffing-with-a-hybrid-model"]

    #until here we have the average flatness vectors for passwords with length 8 and >=12
    # plot flatness graph
    # perfect method
    success_rate = []
    login_attempts = []
    prob_e = 1 / 20
    for i in range(1, 6):
        success_rate.append(i * prob_e)
        login_attempts.append(i)

    fig, ax = plt.subplots()
    ax.autoscale_view()
    ax.set_xticks(np.arange(len(login_attempts) + 1))

    # perfect adv
    plt.plot(login_attempts, success_rate, "-", markerfacecolor='None', label='random guessing baseline')

    # plot experimental values
    j = 0
    for i in range(len(final_stats)):
        plt.plot(login_attempts, final_stats[i], "--", markerfacecolor='None', label=stats_names[j])
        j += 1

    # plt.title("Target dataset: ")
    plt.ylabel("Success rate")
    # plt.ylim([-0.017355596914455252, 0.3644675352035603])
    plt.xlabel("Sweetword login attempts")
    plt.legend(loc="lower right", prop={'size': 8}, frameon=False)

    # att_files=attacker_files[:5]
    # plt.legend(att_files,loc="upper left", prop={'size': 8}, frameon=False)

    # Create the second legend and add the artist manually.
    # att_files =attacker_files[5:]
    # leg = Legend(ax, attacker_files[5:], att_files, loc='lower right', frameon=False)
    # ax.add_artist(leg);

    plt.show()


def produce_epsilon_flatness_table_info_differnt_k():
    statistics  = "chaffing_by_hybrid_model_different_k/statistics_flatness_graph_a3/"

    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics+filename):
            continue
        with open(statistics+filename) as file:
            lines = file.readlines()

        #read total lines number in selected to be attacked passwords
        with open("chaffing_by_hybrid_model_different_k/"+filename,"r") as file1:
            total_lines = file1.readlines()
            total_lines = len(total_lines)

        #statistics
        attacker_files=[]
        target_file = filename
        all_probs=[]
        i = 0

        while i < len(lines):
            i+=1
            attacker_file = lines[i].split(" ")
            attacker_file= attacker_file[1]
            attacker_files.append(attacker_file)
            i+=1
            line = lines[i]
            line = line.split(" ")
            del line[len(line)-1]

            all_probs.append(line[0])
            i+=2

        avg = 0
        for z in all_probs:
            avg+=(int(z)/total_lines)

        print("Target file: "+target_file+" Average e-flatness: "+str(avg/len(all_probs)))
        #print("Average e-flatness: "+str(avg/len(all_probs)))
        print()


def plot_success_number_num_honeywords_per_user():
    path = "chaffing_by_hybrid_model_different_k/statistics_successful_vs_failed_a3/"
    statistics = os.listdir(path)
    stats_names = ["20", "40", "60", "80", "100", "160", "200"]

    final_stats = []
    for directory in statistics:
        total_lines_no = 0
        all_probs = []
        for filename in os.listdir(directory):
            if not os.path.isfile(directory + filename):
                continue

            with open(directory + filename) as file:
                lines = file.readlines()

            # statistics
            attacker_files = []
            target_file = filename
            i = 0
            while i < len(lines):
                i += 1
                attacker_file = lines[i].split(" ")
                attacker_file = attacker_file[1]
                attacker_files.append(attacker_file)
                i += 20 # go to the line where the t1=20 i.e., an attacker is allowed to use all 20 sweetwords
                line = lines[i]
                line = line.split(" ")
                del line[len(line)-1] #remove the \n element from the list
                probs=[]
                for j in line:
                    probs.append((int(j)))

                all_probs.append(probs)
                i += 1 #skip ======== line

                i += 1 # go to the next attacker file line
                total_lines_no+=1

        if total_lines_no!=len(all_probs):
            print("Error: False division!")
            exit(0)

        avg_all_probs=[0 for i in range(len(all_probs[0]))]
        for i in all_probs:
            for z in range(len(i)):
                avg_all_probs[z]+=int(i[z])
        for i in range(len(avg_all_probs)):
            avg_all_probs[i]/=len(all_probs)

        final_stats.append(avg_all_probs) #append average success-vs-failed honeyword logins to the final stats list

    #until here we have the averaged vectors for each of the 3 HGTs in the final stats list. Now let's plot the success-number graph comparing those techniques.
    #first plot the random guessing baseline
    perf_success = []
    perf_fail = []
    y = 1
    x = 19
    while y <= len(final_stats[0]):
        perf_success.append(y)
        perf_fail.append(x)
        x += 19
        y += 1
    fig, ax = plt.subplots()
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.autoscale_view()
    plt.plot(perf_fail, perf_success, "-", markerfacecolor='None', label='random guessing baseline')

    #now plot the graphs for the 3 HGTs.
    j=0
    for i in final_stats:
        plt.plot(i, perf_success, "--", markerfacecolor='None', label=stats_names[j])
        j+=1

    #plt.title("Target dataset: " + target_file)
    plt.ylabel("Successful login attempts\nusing real password")
    plt.xlabel("Failed honeyword login attempts")
    #plt.legend(loc="lower right", prop={'size': 8}, frameon=False)
    plt.legend(loc="upper left", prop={'size': 10}, frameon=False)
    plt.show()


def plot_flatness_num_honeywords_per_user():
    path = "chaffing_by_hybrid_model_different_k/statistics_flatness_graph_a3/"
    statistics = os.listdir(path)
    stats_names=["20","40","60","80","100","160","200"]

    final_stats = []
    for filename in statistics:
        if not os.path.isfile(path+filename):
            continue

        with open(path+filename) as file:
            lines = file.readlines()

        # statistics
        attacker_files = []
        target_file = filename
        total_lines_no = 0

        i = 0
        all_probs=[]
        while i < len(lines):
            i += 1
            attacker_file = lines[i].split(" ")
            attacker_file = attacker_file[1]
            attacker_files.append(attacker_file)
            i += 1
            line = lines[i]
            line = line.split(" ")
            del line[len(line) - 1]
            all_probs_0 = [0 for i in range(len(line))]
            # print(line)
            for j in range(len(line)):
                all_probs_0[j] += int(line[j])
            i += 2
            total_lines_no += 1

            all_probs.append(all_probs_0)

        all_probs = all_probs[0].copy()

        # calculate the average for each HGT vector
        avg_stats_temp = []
        for i in range(len(all_probs)):
            avg_stats_temp.append(int(all_probs[i] / total_lines_no))

        final_stats.append(avg_stats_temp) #append average success-vs-failed honeyword logins to the final stats list


    for i in range(len(final_stats)):
        #print(final_stats[i])
        #print(len(final_stats[i]))
        for j in range(len(final_stats[i])):
            final_stats[i][j]/=final_stats[i][len(final_stats[i])-1]
        #print(final_stats[i])

    for j in final_stats:
        #until here we have the averaged vectors for each of the 3 HGTs in the final stats list. Now let's plot the success-number graph comparing those techniques.
        # plot flatness graph
        # perfect method
        success_rate = []
        login_attempts = []
        prob_e = 1 / len(j)
        for i in range(1, len(j)+1):
            success_rate.append(i * prob_e)
            login_attempts.append(i)

        fig, ax = plt.subplots()
        ax.autoscale_view()
        ax.set_xticks(np.arange(1,len(login_attempts) + 1,10))

        # perfect adv
        plt.plot(login_attempts, success_rate, "-", markerfacecolor='None', label='random guessing baseline')

        # plot experimental values
        plt.plot(login_attempts, j, "--", markerfacecolor='None', label=len(j))

        # plt.title("Target dataset: ")
        plt.ylabel("Success rate")
        # plt.ylim([-0.017355596914455252, 0.3644675352035603])
        plt.xlabel("Sweetword login attempts")
        plt.legend(loc="lower right", prop={'size': 10}, frameon=False)

        # att_files=attacker_files[:5]
        # plt.legend(att_files,loc="upper left", prop={'size': 8}, frameon=False)

        # Create the second legend and add the artist manually.
        # att_files =attacker_files[5:]
        # leg = Legend(ax, attacker_files[5:], att_files, loc='lower right', frameon=False)
        # ax.add_artist(leg);

        plt.show()



"This function prints the statitstics for the success number table."
def success_number_table_k_honeywords(t2_list, attacker_files, target_file, t2_allowed, statistics,k_value):
    # read target file lines
    statistics = statistics.split("/")[0]
    statistics += "/"
    with open(statistics + target_file, "r") as file:
        lines = file.readlines()
    total_records = len(lines)

    # process attacker
    temp = []
    for i in attacker_files:
        i = i.replace("_sorted_preprocessed.txt\n", "")
        i = i.replace("-com", "")
        i = i.replace("-2016", "")
        temp.append(i)
    attacker_files = temp.copy()

    avg = 0
    for i in range(len(attacker_files)):
        successful_guesses = 0
        flag = 0
        for z in range(len(t2_list[i * k_value])):
            if t2_list[i * k_value][z] > t2_allowed:
                successful_guesses = z
                flag = 1
                break
            elif t2_list[i * k_value][z] == t2_allowed:
                successful_guesses = z + 1
                flag = 1
                break
        if flag == 0:
            successful_guesses = z

        # print("Target file: "+target_file)
        # print("Attacker file: "+attacker_files[i])
        # print(t2_list[i*20][z])
        # print("Successful guesses until T2 reached: "+str(successful_guesses))
        # print("=============")
        avg += successful_guesses

    # calculate average successfully guessed passwords for all attacker files
    avg = int(avg / (len(attacker_files)))
    # calculate the % of the recovered passwords for the target dataset
    total_average = (avg * 100) / total_records
    print("Average % for the target dataset \'" + target_file + "\' is: " + str(total_average) + " (" + str(
        avg) + " records).")
    return total_average



def plot_single_target_all_t1_20_different_k(t2_list,attacker_files,target_file,k_value):

    # process attacker
    temp = []
    for i in attacker_files:
        i = i.replace("_sorted_preprocessed.txt\n", "")
        i = i.replace("-com","")
        i = i.replace("-2016","")
        temp.append(i)
    attacker_files = temp.copy()

    perf_success = []
    perf_fail = []
    y = 1
    x = k_value-1

    max_len=0
    success_res=[]
    for z in range(len(attacker_files)):
        curr_len = len(t2_list[(z+1)*k_value-1])
        success_res.append(t2_list[(z+1)*k_value-1])
        if curr_len>max_len:
            max_len=curr_len

    t2 = max_len
    while y <= t2:
        perf_success.append(y)
        perf_fail.append(x)
        x += (k_value-1)
        y += 1

    fig, ax = plt.subplots()
    ax.set_xscale('log')
    ax.set_yscale('log')
    ax.autoscale_view()

    plt.plot(perf_fail, perf_success, "-", markerfacecolor='None', label='random guessing baseline')

    count=0
    for j in success_res:
        perf_success_1 = []
        for z in range(1, len(j)+1):
            perf_success_1.append(z)
        plt.plot(j, perf_success_1, "--", markerfacecolor='None', label=k_value)
        count+=1


    target_file = target_file.replace("_sorted_preprocessed.txt", "")
    target_file = target_file.replace("-com","")
    target_file = target_file.replace("-2016","")
    #plt.title("Target dataset: " + target_file)
    plt.ylabel("Successfull login attempts\nusing real password")
    plt.xlabel("Failed honeyword login attempts")
    plt.legend(loc="lower right", prop={'size': 10}, frameon=False)
    plt.show()

def plot_success_number_graphs_k(t2_allowed, user_option):

    statistics = "chaffing_by_hybrid_model_different_k/statistics_successful_vs_failed_a3/"

    total_avg = 0
    count = 0
    for filename in os.listdir(statistics):
        if not os.path.isfile(statistics + filename):
            continue

        k_value=filename.split("_")
        k_value=k_value[3]
        k_value=k_value.replace(".txt","")
        k_value=int(k_value)


        # increase counter
        count += 1

        with open(statistics + filename) as file:
            lines = file.readlines()

        # statistics
        attacker_files = []
        target_file = filename
        all_probs = []
        i = 0
        while i < len(lines):
            i += 1
            attacker_file = lines[i].split(" ")
            attacker_file = attacker_file[1]
            attacker_files.append(attacker_file)
            i += 1

            for z in range(k_value):

                line = lines[i]
                line = line.split(" ")
                # delete the new line element at the end of the list
                del line[len(line) - 1]

                probs = []
                for j in line:
                    probs.append(int(j))

                all_probs.append(probs)
                i += 1

            # go to the next attacker file line
            i += 1

        # create flatness graph
        if user_option == 12:
            success_number_table_k_honeywords(all_probs, attacker_files, target_file, t2_allowed, statistics,k_value)
        elif user_option == 13:
            plot_single_target_all_t1_20_different_k(all_probs, attacker_files, target_file,k_value)




#execute program
print("Welcome to the plot_graphs_experiments.py script. Select an option from the menu shown below by giving the respective number.")
print("==============")
print("1. Produce flatness graphs targeting RockYou dataset using each of the HGTs (Figure 3a-3c).")
print("2. Produce success-number graphs for T1=20 targeting RockYou dataset using each of the HGTs (Figure 3d-3f).")
print("3. Produce success-number table info for T1=1 and T2=61 (Table 4).")
print("4. Produce e-flatness table's info (Table 5).")
print("5. Produce flatness graphs taking the average of each HGT. This is a comparison graph for our 3 HGTs (Figure 4a).")
print("6. Produce success-number graphs taking the average of each HGT. This is a comparison graph for our 3 HGTs (Figure 4b).")
print("7. Produce flatness graph for passwords with length 8 vs passwords with length >=12 (Figure 7a).")
print("8. Produce success-number graph for passwords with length 8 vs passwords with length >=12 (Figure 7b).")
print("9. Produce the user study flatness graph for T1=1 to T1=5 (Figure 6a).")
print("10: Produce e-flatness table info for the RockYou dataset as target and phpbb as attacker dataset with different k, i.e., different number of honeywords per user (Table 6).")
print("11: Produce flatness graphs for different k, i.e., number of honeywords pper user (Figure 8).")
print("12: Produce success-number table info for T1=1 and T2=61 for different k, i.e., number of honeywords per user (Table 6).")
print("13. Produce success-number graphs for T1=20 for different k files, i.e., files with different number of honeywords per user (Figure 9).\n")


user_option = input()
user_option = int(user_option)

if user_option==1:
    plot_flatness_graphs()
elif user_option==2 or user_option==3:
    t2_allowed=61
    plot_success_number_graphs(t2_allowed,user_option)
elif user_option==4:
    produce_flatness_table_info()
elif user_option==5:
    plot_flatness_vs_tweaking_model_hybrid()
elif user_option==6:
    plot_success_number_vs_tweaking_model_hybrid()
elif user_option==7:
    plot_8_vs_12andbigger_passwords_flatness()
elif user_option==8:
    plot_8_vs_12andbigger_passwords_success_number()
elif user_option==9:
    plot_user_study()
elif user_option==10:
    produce_epsilon_flatness_table_info_differnt_k()
elif user_option==11:
    plot_flatness_num_honeywords_per_user()
elif user_option==12 or user_option==13:
    t2_allowed=5000
    plot_success_number_graphs_k(t2_allowed,user_option)
