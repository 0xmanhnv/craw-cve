import pandas as pd
import random
import xlsxwriter
import re
from packaging import version

#Search Engine
def search(dte,key):
    #check data
    try:
        data='nvdcve-1.1-2021.json'
        df = pd.read_json(data)
    except:
        print('Not have data yet!')
        print('Try -h for help')
        exit()
    #Create a var to store extracted data, dt is like a row and dfr is like a table
    dt={'Affected Product':[],'CVE ID' :[], 'Description' :[], 'CVSSv2' :[], 'CVSSv3' :[], 'Severity' :[], 'Publish Date' :[], 'Last Modified Date' :[], 'cpe23Uri' :[], 'Reference Url' :[],'versionfrom':[],'versionto':[]}
    dfr= pd.DataFrame(dt)
    #Split key to each word and find it in cveid and descripton
    key=key.split()
    #xx var check if not found any cve with that keyword and date input
    xx=0
    # Start find match key and date in each CVE_Item
    for i in range(len(df['CVE_Items'])):
        #format df['CVE_Items'][i] type series to dataframe 
        d=pd.json_normalize(df['CVE_Items'][i])
        #var cy store id and description of cve, trans it to lowercase
        cy=''
        CVEid=d['cve.CVE_data_meta.ID'][0]
        CVEDescription=d['cve.description.description_data'][0][0]['value']
        cy=CVEid+' '+CVEDescription
        cy=cy.lower()
        CVELastModifiedDate=d['lastModifiedDate'][0][0:10]

        #check if this cve match key and lastmodifiedDate or not. if x=1 match, x2 is not match
        x=0
        if key==[]:
            if dte==CVELastModifiedDate:
                x=1
        else:
            for j in key:
                if j.lower() in cy  and dte==CVELastModifiedDate:
                    x=1
        if x==1:
            #ScoreV2:
            try:
                CVEScoreV2=d['impact.baseMetricV2.cvssV2.baseScore'][0]
            except:
                CVEScoreV2=' '
            #ScoreV3:
            try:
                CVEScoreV3=d['impact.baseMetricV3.cvssV3.baseScore'][0]
            except:
                CVEScoreV3=' '
            #Severity:
            try:
                CVEserivity=d['impact.baseMetricV3.cvssV3.baseSeverity'][0]
            except:
                CVEserivity=' '
            #PublishDate
            CVEPublishDate=d['publishedDate'][0][0:10]
            #cpe23Uri and product name
            CVECpe23=''
            productname=''
            versionfrom=''
            versionto=''
            numberOfcpe=0
            cpeinfo=d['configurations.nodes'][0]
            try:
                while 1:
                    ecp=cpeinfo[numberOfcpe]['children']
                    if len(ecp)==2:
                        l1=len(ecp[0]['cpe_match'])
                        for i in range(l1):
                            namecpe1=ecp[0]['cpe_match'][i]['cpe23Uri'][10:].replace(':',' ').replace('*','').replace('-',' ').replace(',','').replace('_',' ').replace('\\','').title()
                            namecpe1list=namecpe1.split(' ')
                            namecpe1=''
                            checkfrom=0
                            checkto=0
                            for namecpe1split in namecpe1list:
                                if namecpe1split not in namecpe1:
                                    namecpe1=namecpe1+namecpe1split+' '
                            if len(ecp[0]['cpe_match'][i])>3:
                                namecpe1=namecpe1+'versions '
                            #startIn
                            try:
                                namecpe1=namecpe1+'from including '+ecp[0]['cpe_match'][i]['versionStartIncluding']+' '
                                versionfrom=versionfrom+ecp[0]['cpe_match'][i]['versionStartIncluding']+'\n'
                                checkfrom=1
                            except:
                                pass
                            #startEx
                            try:
                                namecpe1=namecpe1+'from excluding '+ecp[0]['cpe_match'][i]['versionStartExcluding']+' '
                                versionfrom=versionfrom+ecp[0]['cpe_match'][i]['versionStartExcluding']+'\n'
                                checkfrom=1
                            except:
                                pass
                            #endExclu
                            try:
                                namecpe1=namecpe1+'up to excluding '+ecp[0]['cpe_match'][i]['versionEndExcluding']+' '
                                versionto=versionto+ecp[0]['cpe_match'][i]['versionEndExcluding']+'\n'
                                checkto=1
                            except:
                                pass
                            #endIxclu
                            try:
                                namecpe1=namecpe1+'up to including '+ecp[0]['cpe_match'][i]['versionEndIncluding']+' '
                                versionto=versionto+ecp[0]['cpe_match'][i]['versionEndIncluding']+'\n'
                                checkto=1
                            except:
                                pass
                            productname=productname+namecpe1+'\n'
                            if checkto==0:
                                versionto=versionto+'x'+'\n'
                            if checkfrom==0:
                                versionfrom=versionfrom+'x'+'\n'
                            CVECpe23=CVECpe23+ecp[0]['cpe_match'][i]['cpe23Uri']+'\n'
                    else:
                        l3=len(cpeinfo[numberOfcpe]['cpe_match'])
                        for i in range(l3):
                            namecpe3=cpeinfo[numberOfcpe]['cpe_match'][i]['cpe23Uri'][10:].replace(':',' ').replace('*','').replace('-',' ').replace(',','').replace('\\','').replace('_',' ').title()
                            namecpe3list=namecpe3.split(' ')
                            namecpe3=''
                            checkfrom=0
                            checkto=0
                            for namecpe3split in namecpe3list:
                                if namecpe3split not in namecpe3:
                                    namecpe3=namecpe3+namecpe3split+' '
                            if len(cpeinfo[numberOfcpe]['cpe_match'][i])>3:
                                namecpe3=namecpe3+'versions '
                            #startIn
                            try:
                                namecpe3=namecpe3+'from including '+cpeinfo[numberOfcpe]['cpe_match'][i]['versionStartIncluding']+' '
                                versionfrom=versionfrom+cpeinfo[numberOfcpe]['cpe_match'][i]['versionStartIncluding']+'\n'
                                checkfrom=1
                            except:
                                pass
                            #startEx
                            try:
                                namecpe3=namecpe3+'from excluding '+cpeinfo[numberOfcpe]['cpe_match'][i]['versionStartExcluding']+' '
                                versionfrom=versionfrom+cpeinfo[numberOfcpe]['cpe_match'][i]['versionStartExcluding']+']\n'
                                checkfrom=1
                            except:
                                pass
                            #endExclu
                            try:
                                namecpe3=namecpe3+'up to excluding '+cpeinfo[numberOfcpe]['cpe_match'][i]['versionEndExcluding']+' '
                                versionto=versionto+cpeinfo[numberOfcpe]['cpe_match'][i]['versionEndExcluding']+'\n'
                                checkto=1
                            except:
                                pass
                            #endIxclu
                            try:
                                namecpe3=namecpe3+'up to including '+cpeinfo[numberOfcpe]['cpe_match'][i]['versionEndIncluding']+' '
                                versionto=versionto+cpeinfo[numberOfcpe]['cpe_match'][i]['versionEndIncluding']+'\n'
                                checkto=1
                            except:
                                pass
                            productname=productname+namecpe3+'\n'
                            CVECpe23=CVECpe23+cpeinfo[numberOfcpe]['cpe_match'][i]['cpe23Uri']+'\n'
                            if checkto==0:
                                versionto=versionto+'x'+'\n'
                            if checkfrom==0:
                                versionfrom=versionfrom+'x'+'\n'
                    numberOfcpe=numberOfcpe+1
                    if numberOfcpe==len(cpeinfo):
                        break
                productname=re.sub(' +',' ',productname)
            except:
                pass

            #Reference Url
            try:
                CVEReferenceUrl=''
                for i in range(len(d['cve.references.reference_data'][0])):
                    CVEReferenceUrl=CVEReferenceUrl+d['cve.references.reference_data'][0][i]['url']+'\n'
            except:
                CVEReferenceUrl=' '
            #new_row store all data of this cve and add to dfr
            new_row={'Affected Product': productname, 'CVE ID' : CVEid, 'Description' :CVEDescription, 'CVSSv2' :CVEScoreV2, 'CVSSv3' :CVEScoreV3, 'Severity' :CVEserivity, 'Publish Date' :CVEPublishDate, 'Last Modified Date' :CVELastModifiedDate, 'cpe23Uri' :CVECpe23, 'Reference Url' :CVEReferenceUrl,'versionfrom':versionfrom,'versionto':versionto}
            dfr = dfr.append(new_row, ignore_index=True)
            xx=1
    if xx==1:

        #check if cpe match with product of company and add column Affected platform
        new_colm2= pd.Series([])
        new_colm3= pd.Series([])
        #data take from file "affected_product.xlsx"
        dlist=pd.read_excel('affected_product.xlsx')
        dflist= pd.DataFrame(dlist)
        cpe_list= dflist['CPE']
        affectedplatformlist= dflist['Affected platform']
        for i in range(len(cpe_list)):
            cpeproduct=cpe_list[i][10:]
            cpeproductsplit=cpeproduct.split(':')
            newcpeproduct=''
            cpeversion=''
            if '.' in cpeproductsplit[-1] or str(cpeproductsplit[-1]).isnumeric():
                cpeversion=cpeproductsplit[-1]
                for i in range(len(cpeproductsplit[:-1])):
                    newcpeproduct=newcpeproduct+cpeproductsplit[:-1][i]+':'
            else:
                newcpeproduct=cpeproduct

            for j in range(len(dfr['cpe23Uri'])):
                listcpe=dfr['cpe23Uri'][j].split('\n')
                Cpeversionsfrom=dfr['versionfrom'][j].split('\n')
                Cpeversionsto=dfr['versionto'][j].split('\n')

                for k in range(len(listcpe)):
                    if newcpeproduct+cpeversion in listcpe[k]:
                        new_colm2[j]='x'
                        new_colm3[j]=affectedplatformlist[i]
                    elif newcpeproduct in listcpe[k] and cpeversion not in listcpe[k]:
                        if Cpeversionsto[k] =='x' and Cpeversionsfrom[k] =='x':
                            new_colm2[j]='x'
                            new_colm3[j]=affectedplatformlist[i]
                        elif Cpeversionsto[k]!='x' and Cpeversionsfrom[k] =='x':
                            if version.parse(cpeversion) <= version.parse(Cpeversionsto[k]):
                                new_colm2[j]='x'
                                new_colm3[j]=affectedplatformlist[i]
                        elif Cpeversionsto[k]=='x' and Cpeversionsfrom[k] !='x':
                            if version.parse(cpeversion) >= version.parse(Cpeversionsfrom[k]):
                                new_colm2[j]='x'
                                new_colm3[j]=affectedplatformlist[i]
                        elif Cpeversionsto[k]!='x' and Cpeversionsfrom[k] !='x':
                            if version.parse(cpeversion) >= version.parse(Cpeversionsfrom[k]) and version.parse(cpeversion) <= version.parse(Cpeversionsto[k]):
                                new_colm2[j]='x'
                                new_colm3[j]=affectedplatformlist[i]
        dfr.insert(10,' ',new_colm2)
        dfr.insert(2,'Affected platform',new_colm3)


        #generate file name
        name=random.randint(111111,999999)
        name=dte+'---'+str(name)+'.xlsx'

        #formatexcel
        writer=pd.ExcelWriter(name, engine='xlsxwriter',options={'strings_to_urls': False})
        dfr.to_excel(writer, sheet_name='Sheet')
        workbook = writer.book
        worksheet=writer.sheets['Sheet']

        worksheet.set_column('B:B',40)
        worksheet.set_column('C:C',15)
        worksheet.set_column("D:D",30)
        worksheet.set_column('E:E',80)
        worksheet.set_column("I:I",17)
        worksheet.set_column("J:J",17)
        worksheet.set_column('K:K',50)
        worksheet.set_column("L:L",200)
        
        yellow_format=workbook.add_format()
        yellow_format.set_font_color('yellow')
        orange_format=workbook.add_format()
        orange_format.set_font_color('orange')
        red_format=workbook.add_format()
        red_format.set_font_color('red')
        dred_format=workbook.add_format()
        dred_format.set_font_color('#850101')
        yellow_format2=workbook.add_format()
        yellow_format2.set_bg_color('yellow')
        worksheet.conditional_format("B1:B500",{'type': 'formula',
                                            'criteria': 'LEFT($M1)="x"',
                                            'format': yellow_format2})
        worksheet.conditional_format("H1:H500",{'type': 'cell',
                                            'criteria': 'equal to',
                                            'value': '"CRITICAL"',
                                            'format': dred_format})

        worksheet.conditional_format("H1:H500",{'type': 'cell',
                                            'criteria': 'equal to',
                                            'value': '"HIGH"',
                                            'format': red_format})
        worksheet.conditional_format("H1:H500",{'type': 'cell',
                                            'criteria': 'equal to',
                                            'value': '"MEDIUM"',
                                            'format': orange_format})
        worksheet.conditional_format("H1:H500",{'type': 'cell',
                                            'criteria': 'equal to',
                                            'value': '"LOW"',
                                            'format': yellow_format})
        worksheet.set_column("M:M", options={'hidden': True})
        worksheet.set_column("N:N", options={'hidden': True})
        worksheet.set_column("O:O", options={'hidden': True})
        writer.save()
        print('-----------------')
        print('Done, check file: ',name)
    #if search() not found any cve match with this key and date
    else:
        print('Nothing, check your input and try again')
