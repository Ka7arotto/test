import os
pairs=os.listdir('cves_nodup_final2_op')
for pair in pairs:
    if '_ber_parse_header' in pair:
        print(pair)
        f=open('./cves_nodup_final2_op/'+pair+'/'+pair+'_vul.c')
        code=f.read()
        f.close()
        code=code.replace('ber_parse_header(STREAM s, int tagval,', 'int ber_parse_header(STREAM s, int tagval,')
        f=open('./cves_nodup_final2_op/'+pair+'/'+pair+'_vul.c','w')
        f.write(code)
        f.close()
        f=open('./cves_nodup_final2_op/'+pair+'/'+pair+'_nonvul.c')
        code=f.read()
        f.close()
        code=code.replace('ber_parse_header(STREAM s, int tagval,', 'int ber_parse_header(STREAM s, int tagval,')
        f=open('./cves_nodup_final2_op/'+pair+'/'+pair+'_nonvul.c','w')
        f.write(code)
        f.close()
