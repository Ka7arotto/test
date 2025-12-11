## coding:utf-8
from joern.all import JoernSteps
from igraph import *
from access_db_operate import *
from slice_op import *
from py2neo.packages.httpstream import http
http.socket_timeout = 9999




def get_slice_file_sequence(store_filepath, list_result, count, func_name, startline, filepath_all):
    list_for_line = []
    statement_line = 0
    vulnline_row = 0
    list_write2file = []
    for node in list_result:    
        if node['type'] == 'Function':
            f2 = open(node['filepath'], 'r')
            content = f2.readlines()
            f2.close()
            raw = int(node['location'].split(':')[0])-1
            code = content[raw].strip()

            new_code = ""
            if code.find("#define") != -1:
                list_write2file.append(code + ' ' + str(raw+1) + '\n')
                continue

            while (len(code) >= 1 and code[-1] != ')' and code[-1] != '{'):
                if code.find('{') != -1:
                    index = code.index('{')
                    new_code += code[:index].strip()
                    list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                    break

                else:
                    new_code += code + '\n'
                    raw += 1
                    code = content[raw].strip()
                    #print "raw", raw, code

            else:
                new_code += code
                new_code = new_code.strip()
                if new_code[-1] == '{':
                    new_code = new_code[:-1].strip()
                    list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                    #list_line.append(str(raw+1))
                else:
                    list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                    #list_line.append(str(raw+1))

        elif node['type'] == 'Condition':
            raw = int(node['location'].split(':')[0])-1
            if raw in list_for_line:
                continue
            else:
                #print node['type'], node['code'], node['name']
                f2 = open(node['filepath'], 'r')
                content = f2.readlines()
                f2.close()
                code = content[raw].strip()
                pattern = re.compile("(?:if|while|for|switch)")
                #print code
                res = re.search(pattern, code)
                if res == None:
                    raw = raw - 1
                    code = content[raw].strip()
                    new_code = ""

                    while (code[-1] != ')' and code[-1] != '{'):
                        if code.find('{') != -1:
                            index = code.index('{')
                            new_code += code[:index].strip()
                            list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                            #list_line.append(str(raw+1))
                            list_for_line.append(raw)
                            break

                        else:
                            new_code += code + '\n'
                            list_for_line.append(raw)
                            raw += 1
                            code = content[raw].strip()

                    else:
                        new_code += code
                        new_code = new_code.strip()
                        if new_code[-1] == '{':
                            new_code = new_code[:-1].strip()
                            list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                            #list_line.append(str(raw+1))
                            list_for_line.append(raw)

                        else:
                            list_for_line.append(raw)
                            list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                            #list_line.append(str(raw+1))

                else:
                    res = res.group()
                    if res == '':
                        print filepath_all + ' ' + func_name + " error!"
                        exit()

                    elif res != 'for':
                        new_code = res + ' ( ' + node['code'] + ' ) '
                        list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                        #list_line.append(str(raw+1))

                    else:
                        new_code = ""
                        if code.find(' for ') != -1:
                            code = 'for ' + code.split(' for ')[1]

                        while code != '' and code[-1] != ')' and code[-1] != '{':
                            if code.find('{') != -1:
                                index = code.index('{')
                                new_code += code[:index].strip()
                                list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                                #list_line.append(str(raw+1))
                                list_for_line.append(raw)
                                break

                            elif code[-1] == ';' and code[:-1].count(';') >= 2:
                                new_code += code
                                list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                                #list_line.append(str(raw+1))
                                list_for_line.append(raw)
                                break

                            else:
                                new_code += code + '\n'
                                list_for_line.append(raw)
                                raw += 1
                                code = content[raw].strip()

                        else:
                            new_code += code
                            new_code = new_code.strip()
                            if new_code[-1] == '{':
                                new_code = new_code[:-1].strip()
                                list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                                #list_line.append(str(raw+1))
                                list_for_line.append(raw)

                            else:
                                list_for_line.append(raw)
                                list_write2file.append(new_code + ' ' + str(raw+1) + '\n')
                                #list_line.append(str(raw+1))
        
        elif node['type'] == 'Label':
            f2 = open(node['filepath'], 'r')
            content = f2.readlines()
            f2.close()
            raw = int(node['location'].split(':')[0])-1
            code = content[raw].strip()
            list_write2file.append(code + ' ' + str(raw+1) + '\n')
            #list_line.append(str(raw+1))

        elif node['type'] == 'ForInit':
            continue

        elif node['type'] == 'Parameter':
            if list_result[0]['type'] != 'Function':
                row = node['location'].split(':')[0]
                list_write2file.append(node['code'] + ' ' + str(row) + '\n')
                #list_line.append(row)
            else:
                continue

        elif node['type'] == 'IdentifierDeclStatement':
            if node['code'].strip().split(' ')[0] == "undef":
                f2 = open(node['filepath'], 'r')
                content = f2.readlines()
                f2.close()
                raw = int(node['location'].split(':')[0])-1
                code1 = content[raw].strip()
                list_code2 = node['code'].strip().split(' ')
                i = 0
                while i < len(list_code2):
                    if code1.find(list_code2[i]) != -1:
                        del list_code2[i]
                    else:
                        break
                code2 = ' '.join(list_code2)

                list_write2file.append(code1 + ' ' + str(raw+1) + '\n' + code2 + ' ' + str(raw+2) + '\n')

            else:
                list_write2file.append(node['code'] + ' ' + node['location'].split(':')[0] + '\n')

        elif node['type'] == 'ExpressionStatement':
            row = int(node['location'].split(':')[0])-1
            if row in list_for_line:
                continue

            if node['code'] in ['\n', '\t', ' ', '']:
                list_write2file.append(node['code'] + ' ' + str(row+1) + '\n')
                #list_line.append(row+1)
            elif node['code'].strip()[-1] != ';':
                list_write2file.append(node['code'] + '; ' + str(row+1) + '\n')
                #list_line.append(row+1)
            else:
                list_write2file.append(node['code'] + ' ' + str(row+1) + '\n')
                #list_line.append(row+1)

        elif node['type'] == "Statement":
            row = node['location'].split(':')[0]
            list_write2file.append(node['code'] + ' ' + str(row) + '\n')
            #list_line.append(row+1)

        else:         
            #print node['name'], node['code'], node['type'], node['filepath']
            if node['location'] == None:
                continue
            f2 = open(node['filepath'], 'r')
            content = f2.readlines()
            f2.close()
            row = int(node['location'].split(':')[0])-1
            code = content[row].strip()
            if row in list_for_line:
                continue

            else:
                list_write2file.append(node['code'] + ' ' + str(row+1) + '\n')
                #list_line.append(str(row+1))

    f = open(store_filepath, 'a')
    f.write(str(count) + ' ' + filepath_all + ' ' + func_name + ' ' + startline + '\n')
    for wb in list_write2file:
        f.write(wb)
    f.write('------------------------------' + '\n')     
    f.close()


def program_slice(pdg, startnodesID, slicetype, testID):#process startnodes as a list, because main func has many different arguments
    list_startnodes = []
    if pdg == False or pdg == None:
        return [], [], []
        
    for node in pdg.vs:
        #print node['functionId']
        if node['name'] in startnodesID:
            list_startnodes.append(node)
    if list_startnodes == []:
        return [], [], []

    if slicetype == 0:#backwords
        start_line = list_startnodes[0]['location'].split(':')[0]
        start_name = list_startnodes[0]['name']
        startline_path = list_startnodes[0]['filepath']
        results_back = program_slice_backwards(pdg, list_startnodes)
        
        not_scan_func_list = []
        results_back, temp = process_cross_func(results_back, testID, 1, results_back, not_scan_func_list)


        return [results_back], start_line, startline_path

    elif slicetype == 1:#forwords
        #print "start extract forword dataflow!"
        #print list_startnodes, startnodesID
        start_line = list_startnodes[0]['location'].split(':')[0]
        start_name = list_startnodes[0]['name']
        startline_path = list_startnodes[0]['filepath']
        results_for = program_slice_forward(pdg, list_startnodes)

        not_scan_func_list = []
        results_for, temp = process_cross_func(results_for, testID, 1, results_for, not_scan_func_list)

        return [results_for], start_line, startline_path

    else:#bi_direction
        #print "start extract backwords dataflow!"

        start_line = list_startnodes[0]['location'].split(':')[0]
        start_name = list_startnodes[0]['name']
        startline_path = list_startnodes[0]['filepath']
        results_back = program_slice_backwards(pdg, list_startnodes)#results_back is a list of nodes

        results_for = program_slice_forward(pdg, list_startnodes)      
        

        _list_name = []
        for node_back in results_back:
            _list_name.append(node_back['name'])

        for node_for in results_for:
            if node_for['name'] in _list_name:
                continue
            else:
                results_back.append(node_for)

        results_back = sortedNodesByLoc(results_back)
       
        iter_times = 0
        start_list = [[results_back, iter_times]]
        i = 0
        not_scan_func_list = []
        list_cross_func_back, not_scan_func_list = process_crossfuncs_back_byfirstnode(start_list, testID, i, not_scan_func_list)
        list_results_back = [l[0] for l in list_cross_func_back]
      
        all_result = [] 
        for results_back in list_results_back:
            index = 1
            for a_node in results_back:
                if a_node['name'] == start_name:
                    break
                else:
                    index += 1

            list_to_crossfunc_back = results_back[:index]
            list_to_crossfunc_for = results_back[index:]

            list_to_crossfunc_back, temp = process_cross_func(list_to_crossfunc_back, testID, 0, list_to_crossfunc_back, not_scan_func_list)

            list_to_crossfunc_for, temp = process_cross_func(list_to_crossfunc_for, testID, 1, list_to_crossfunc_for, not_scan_func_list)

            all_result.append(list_to_crossfunc_back + list_to_crossfunc_for)
  

        return all_result, start_line, startline_path

def candidate_slice(change_set):
    count = 1
    store_filepath = "C/test_data/4/candidate_slices.txt"
    f = open("vulnerable_points.pkl", 'rb')
    dict_unsliced_vuls = pickle.load(f)
    #print dict_unsliced_vuls
    f.close()
    candidates={}
    for key in dict_unsliced_vuls.keys():#key is testID
        #print key
        l=[]
        prev_num=0
        for _t in dict_unsliced_vuls[key]:
            #if len(candidates)>5:
            #    break
            if not prev_num==len(candidates):
                print len(candidates)
                prev_num=len(candidates)

            list_vuls_funcid = _t[0]
            pdg_funcid = _t[1]
            #print key, pdg_funcid
            vul_line = str(_t[2][0])


            slice_dir = 0
            pdg = getFuncPDGById(key, pdg_funcid)
            if pdg == False:
                print 'error'
                exit()
            try:
                list_code, startline, startline_path = program_slice(pdg, list_vuls_funcid, slice_dir, key)
            except:
                continue
            if list_code == []:
                fout = open("error.txt", 'a')
                fout.write(' found nothing! \n')
                fout.close()
            else:
                for _list in list_code:
                    try:
                        for node in _list:
                            f2 = open(node['filepath'], 'r')
                            content = f2.readlines()
                            f2.close()
                            row = int(node['location'].split(':')[0])
                            if (str(node['filepath'].split('/')[1]), row) in change_set:
                                 if not node['filepath'].split('/')[1] in candidates:
                                     candidates[node['filepath'].split('/')[1]]={}
                                 candidates[node['filepath'].split('/')[1]][int(startline)] = content[int(startline)-1]
                                 break
                        count += 1
                    except:
                        pass
    f=open(store_filepath,'w')
    for file_name in candidates:
        f.write(file_name+'\n')
        line_nums=candidates[file_name].keys()
        line_nums.sort()
        for line_num in line_nums:
            f.write(str(line_num)+' '+candidates[file_name][line_num])
        f.write('\n====================\n')
    #import pdb
    #pdb.set_trace()



def vulnerable_slice(vul_set):
    count = 1
    store_filepath = "C/test_data/4/vulnerable_slices.txt"
    f = open("all_points.pkl", 'rb')
    dict_unsliced_vuls = pickle.load(f)
    #print dict_unsliced_vuls
    f.close()
    vul_slices={}
    for key in dict_unsliced_vuls.keys():#key is testID
        print key
        l=[]
        last_len=0
        for _t in dict_unsliced_vuls[key]:
            list_vuls_funcid = _t[0]
            pdg_funcid = _t[1]
            #print(_t)
            if len(vul_slices)>last_len:
                print len(vul_slices)
                last_len=len(vul_slices)
            vul_line = str(_t[2][0])


            slice_dir = 0
            pdg = getFuncPDGById(key, pdg_funcid)
            if pdg == False:
                print 'error'
                exit()
            #import pdb
            #pdb.set_trace()
            try:
                list_code, startline, startline_path = program_slice(pdg, list_vuls_funcid, slice_dir, key)
                #if 'CWE-125_CVE-2018-20176_rdesktop_4dca546d04321a610c1835010b5dad85163b65e1_ber_parse_header' in startline_path:
                    #import pdb
                    #pdb.set_trace()
                for vul_obj in vul_set:
                    if vul_obj[0] in str(startline_path.split('/')[-1]):
                        vul_set.remove(vul_obj)
                        vul_set.add((str(startline_path.split('/')[-1]),vul_obj[1]))

                if not (str(startline_path.split('/')[-1]), int(startline)) in vul_set: #and not 'CWE-401' in str(startline_path.split('/')[-1]):
                    continue
            except:
                #print 'exception1'
                continue
            if list_code == []:
                fout = open("error.txt", 'a')
                fout.write(' found nothing! \n')
                fout.close()
            else:
                func_slice={}
                for _list in list_code:
                    try:
                        for node in _list:
                            
                            if not node['functionId']==pdg_funcid:
                                continue
                            f2 = open(node['filepath'], 'r')
                            content = f2.readlines()
                            f2.close()
                            row = int(node['location'].split(':')[0])
                            if not node['filepath'].split('/')[-1] in vul_slices:
                                vul_slices[node['filepath'].split('/')[-1]]=[]
                            func_slice[int(row)] = content[int(row)-1]
                            #vul_slices[node['filepath'].split('/')[-1]][int(row)] = content[int(row)-1]
                            '''
                            if (str(node['filepath'].split('/')[-1]), row) in vul_set:
                                 if not node['filepath'].split('/')[-1] in vul_slices:
                                     vul_slices[node['filepath'].split('/')[-1]]={}
                                 vul_slices[node['filepath'].split('/')[-1]][int(startline)] = content[int(startline)-1]
                                 break
                            '''
                        count += 1
                    except:
                        print 'err'
                        continue
                    '''
                    try:
                        get_slice_file_sequence(store_filepath, _list, count, vul_line, startline, startline_path)
                        count += 1
                    except:
                        pass
                    '''
            try:
                flag=False
                for func_slicex in vul_slices[startline_path.split('/')[-1]]:
                    if len(set(func_slice.keys()) & set(func_slicex.keys())) > 0:
                        flag=True
                        break
                if flag and not 'CWE-401' in startline_path.split('/')[-1]:
                    continue
                if 'CWE-401' in startline_path.split('/')[-1]:
                    if len(vul_slices[startline_path.split('/')[-1]])==0:
                        vul_slices[startline_path.split('/')[-1]]=[{}]
                    for l in func_slice:
                        vul_slices[startline_path.split('/')[-1]][0][l]=func_slice[l]
                else:
                    vul_slices[startline_path.split('/')[-1]].append(func_slice)
                #if 'CWE-119_CVE-2018-16392_OpenSC_360e95d45ac4123255a4c796db96337f332160ad_read_public_key_vul.c' in startline_path or 'CWE-125_CVE-2018-20174_rdesktop_4dca546d04321a610c1835010b5dad85163b65e1_ber_parse_header_vul.c' in startline_path:
                    #import pdb
                    #pdb.set_trace()

            except:
                print 'err'
                continue
    f=open(store_filepath,'w')
    for file_name in vul_slices:
        f.write(file_name+'\n')
        for j in range(len(vul_slices[file_name])-1,-1,-1):
            func_slice=vul_slices[file_name][j]
            line_nums=func_slice.keys()
            line_nums.sort()
            for line_num in line_nums:
                f.write(str(line_num)+' '+vul_slices[file_name][j][line_num])
        f.write('\n====================\n')


def api_slice():
    count = 1
    store_filepath = "C/test_data/4/api_slices.txt"
    f = open("sensifunc_slice_points.pkl", 'rb')
    dict_unsliced_sensifunc = pickle.load(f)
    f.close()
    for key in dict_unsliced_sensifunc.keys():#key is testID

        for _t in dict_unsliced_sensifunc[key]:
            list_sensitive_funcid = _t[0]
            pdg_funcid = _t[1]
            sensitive_funcname = _t[2]

            if sensitive_funcname.find("main") != -1:
                continue #todo
            else:
                slice_dir = 2
                pdg = getFuncPDGById(key, pdg_funcid)
                if pdg == False:
                    print 'error'
                    exit()
                list_code, startline, startline_path = program_slice(pdg, list_sensitive_funcid, slice_dir, key)
                #print len(list_code)

                if list_code == []:
                    fout = open("error.txt", 'a')
                    fout.write(sensitive_funcname + ' ' + str(list_sensitive_funcid) + ' found nothing! \n')
                    fout.close()
                else:
                    for _list in list_code:
                        get_slice_file_sequence(store_filepath, _list, count, sensitive_funcname, startline, startline_path)
                        count += 1

def pointers_slice():
    count = 1
    store_filepath = "C/test_data/4/pointersuse_slices.txt"
    f = open("pointuse_slice_points.pkl", 'rb')
    dict_unsliced_pointers = pickle.load(f)
    print dict_unsliced_pointers
    f.close()

    for key in dict_unsliced_pointers.keys():#key is testID
        print key
        l=[]
        if key in l:
            continue

        for _t in dict_unsliced_pointers[key]:
            list_pointers_funcid = _t[0]
            pdg_funcid = _t[1]
            print key, pdg_funcid
            pointers_name = str(_t[2])


            slice_dir = 2
            pdg = getFuncPDGById(key, pdg_funcid)
            if pdg == False:
                print 'error'
                exit()

            list_code, startline, startline_path = program_slice(pdg, list_pointers_funcid, slice_dir, key)

            if list_code == []:
                fout = open("error.txt", 'a')
                fout.write(pointers_name + ' ' + str(list_pointers_funcid) + ' found nothing! \n')
                fout.close()
            else:
                for _list in list_code:
                    get_slice_file_sequence(store_filepath, _list, count, pointers_name, startline, startline_path)
                    count += 1


def arrays_slice():
    count = 1
    store_filepath = "C/test_data/4/arraysuse_slices.txt"
    f = open("arrayuse_slice_points.pkl", 'rb')
    dict_unsliced_pointers = pickle.load(f)
    f.close()
    l = []
    for key in dict_unsliced_pointers.keys():#key is testID
       
        if key in l:
            continue

        for _t in dict_unsliced_pointers[key]:
            list_pointers_funcid = _t[0]
            pdg_funcid = _t[1]
            print pdg_funcid
            arrays_name = str(_t[2])


            slice_dir = 2
            pdg = getFuncPDGById(key, pdg_funcid)
            if pdg == False:
                print 'error'
                exit()

            list_code, startline, startline_path = program_slice(pdg, list_pointers_funcid, slice_dir, key)

            if list_code == []:
                fout = open("error.txt", 'a')
                fout.write(arrays_name + ' ' + str(list_pointers_funcid) + ' found nothing! \n')
                fout.close()
            else:
                for _list in list_code:
                    get_slice_file_sequence(store_filepath, _list, count, arrays_name, startline, startline_path)
                    count += 1


def integeroverflow_slice():
    count = 1
    store_filepath = "C/test_data/4/integeroverflow_slices.txt"
    f = open("integeroverflow_slice_points_new.pkl", 'rb')
    dict_unsliced_expr = pickle.load(f)
    f.close()

    for key in dict_unsliced_expr.keys():#key is testID
        if key in l:
            continue
        for _t in dict_unsliced_expr[key]:
            list_expr_funcid = _t[0]
            pdg_funcid = _t[1]
            print pdg_funcid
            expr_name = str(_t[2])


            slice_dir = 2
            pdg = getFuncPDGById(key, pdg_funcid)
            if pdg == False:
                print 'error'
                exit()

            list_code, startline, startline_path = program_slice(pdg, list_expr_funcid, slice_dir, key)

            if list_code == []:
                fout = open("error.txt", 'a')
                fout.write(expr_name + ' ' + str(list_expr_funcid) + ' found nothing! \n')
                fout.close()
            else:
                for _list in list_code:
                    get_slice_file_sequence(store_filepath, _list, count, expr_name, startline, startline_path)
                    count += 1
     

if __name__ == "__main__":
    vulnerable_set=set()
    f=open('ef_vullines.txt')
    vul_lines=f.readlines()
    f.close()
    for vul_line in vul_lines:
        #try:
        if not int(vul_line.split(':')[1][:-1])==-1:
            #vulnerable_set.add((vul_line.split(':')[0]+'___vul.c', int(vul_line.split(':')[1][:-1])))
            vulnerable_set.add((vul_line.split(':')[0], int(vul_line.split(':')[1][:-1])))
        #except:
            #pass
    vulnerable_slice(vulnerable_set)

    '''
    change_set=set()
    pairs=os.listdir('cves_nodup')
    for pair in pairs:
        CVE=pair.split('_')[1]
        #print('https://nvd.nist.gov/vuln/detail/'+CVE)
        files=os.listdir('cves_nodup/'+pair)
        cline=-1
        for file in files:
            if '_vul.c' in file:
                p=os.popen('diff ./cves_nodup/'+pair+'/'+file+' ./cves_nodup/'+pair+'/'+file.replace('_vul.c', '_nonvul.c'))
                lines=p.readlines()
                for i, line in enumerate(lines):
                    if line[0] == '<':
                        try:
                            #print lines[i-1], lines[i], lines[i+1], lines[i+2]
                            cline=int(lines[i-1].split('c')[0])
                            change_set.add((pair+'_vul.c', cline))
                            break
                        except:
                            os.system('rm -r ./cves_nodup/'+pair)
                            break
                break


    candidate_slice(change_set)
    '''
    #vulnerable_slice()
    '''
    api_slice()
    pointers_slice()
    arrays_slice()
    integeroverflow_slice()
    '''
