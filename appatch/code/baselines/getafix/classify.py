import os
pairs=os.listdir('cves_nodup_final2_op')
for pair in pairs:
    os.system('diff ./cves_nodup_final2_op/'+pair+'/'+pair+'_vul.c ./cves_nodup_final2_op/'+pair+'/'+pair+'_nonvul.c')
    ans=str(input())
    os.system('cp -r ./cves_nodup_final2_op/'+pair+' ./strategies/'+ans)
