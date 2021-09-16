import argparse
import pandas as pd
from datetime import date
import random
import xlsxwriter
import requests
import bs4 as bs
import urllib.request
import zipfile
import warnings
import ast
import re

'''Phía trên là các thư viện sử dụng'''

'''Dòng 18 này để code chạy console không hiển thị thông báo warning'''
#start
warnings.filterwarnings("ignore")


'''Đoạn code bên dưới là tạo hàm update() để download và giải nén data'''
#Download file .zip from NIST and extract
def update():
    print('Downloading...')
    url='https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.zip'
    urllib.request.urlretrieve(url, "data.zip")
    with zipfile.ZipFile('data.zip', 'r') as zip_ref:
        zip_ref.extractall()
    print('Done!')

'''Đây là hàm search() chưa code tìm kiếm và trích xuất dữ liệu'''
#Search Engine
def search(dte,key):

    '''Khởi tạo biến dt là kiểu dictionary và chuyển nó thành kiểu dataframe với biến dfr. Biến này sẽ lưu các giá trị lúc trích xuất dữ liệu'''
    dt={'Affected Product':[],'Detail':[],'CVE ID' :[], 'Description' :[], 'CVSSv2' :[], 'CVSSv3' :[], 'Severity' :[], 'Publish Date' :[], 'Last Modified Date' :[], 'cpe23Uri' :[], 'Reference Url' :[]}
    dfr= pd.DataFrame(dt)

    '''Dòng bên dưới chia keyword đã nhập ra thành 1 list các từ, trong quá trình tìm kiếm nếu match với bất kỳ từ nào trong list'''
    key=key.split()
    '''Biến xx để kiểm tra xem trong quá trình trích xuất có tìm thấy CVE nào ko (Dòng 262 và 264)'''
    xx=0

    '''df['CVE_Items'] là kiểu series nó cũng tương tự kiểu list. Mỗi 1 giá trị trong df['CVE_Items'] sẽ tương ứng với 1 CVE'''
    '''Vòng for sẽ chạy hết các CVE trong data. Nếu có key hoặc giá trị lastmodified date trùng thì nó sẽ trích dữ liệu ra biến dfr'''
    for i in range(len(df['CVE_Items'])):
        '''Biến cy sẽ lưu các giá trị là tên cve và description của cve hiện tại, sau đó chuyển thành các ký tự không in hoa'''
        '''Các giá trị key sẽ tìm kiếm và match với các từ trong biên cy này'''
        cy=''

        '''biến d sẽ chưa các giá trị của cve hiện tại tương ứng với biến i trong vòng for trên'''
        d=pd.json_normalize(df['CVE_Items'][i])

        '''Biến "mot" chứa giá trị ID hay tên của CVE. Kiểu CVE-2021-111111'''
        mot=d['cve.CVE_data_meta.ID'][0]
        '''Biến "hai" chứa giá trị description hay mô tả của CVE'''
        hai=d['cve.description.description_data'][0][0]['value']

        '''2 dòng dưới là gộp 2 biến mot và hai thành 1 string cy và cho nó về các ký tự không in hoa'''
        cy=mot+' '+hai
        cy=cy.lower()
        '''Biến "bay" chứa giá trị last modified date của CVE, lấy từ ký tự đầu tiên đến ký tự thứ 10, vd 2021-08-30'''
        '''Biên này có tác dụng khi tìm kiếm nếu nó bằng giá trị dte(cái biến ban đầu argument hay mình nhập vào) thì trích xuất dữ liệu'''
        bay=d['lastModifiedDate'][0][0:10]

        #check
        '''Đoạn code này sẽ kiểm tra giá trị dte và key truyền vào ban đầu xem có match với giá trị của CVE không. Nếu có thì nó sẽ tiếp tục
        trích xuất các giá trị khác, còn nếu không nó sẽ thoát vòng lặp thứ i'''
        '''Kiểm tra bằng biến x, nếu có key và dte trùng thì x=1'''
        x=0
        if key==[]:
            if dte==bay:
                x=1
        else:
            for j in key:
                if j.lower() in cy  and dte==bay:
                    x=1
        '''Khi x=1 tức là CVE này thỏa mãn key và dte truyền vào thì sẽ chạy tiếp phần trích xuất'''
        if x==1:
            #ScoreV2:
            '''Biến "ba" chứa giá trị ScoreV2, phải dùng exception bởi sẽ có một số cve ko có giá trị này'''
            try:
                ba=d['impact.baseMetricV2.cvssV2.baseScore'][0]
            except:
                ba=' '
            #ScoreV3:
            '''Biến "bon" tương tự biến "ba"'''
            try:
                bon=d['impact.baseMetricV3.cvssV3.baseScore'][0]
            except:
                bon=' '
            #Severity:
            '''Biến "nam" tương tự chứa giá trị severity (high, critical,medium...)'''
            try:
                nam=d['impact.baseMetricV3.cvssV3.baseSeverity'][0]
            except:
                nam=' '
            #PublishDate
            '''Biến "sau" chứa giá trị publishDate'''
            sau=d['publishedDate'][0][0:10]

            '''Đoạn code phía dưới sẽ trích xuất giá trị cpe23Uri vào biến "tam", xử lý chuỗi và tạo ra biến productname chứa tên product
            Xử lý chuỗi tạo ra biến detail nếu product có chạy trên hệ điều hành hay phần cứng cụ thể
            '''
            #cpe23Uri and product name
            tam=''
            productname=''
            detail=''
            '''Biến cpeinfo chứa giá trị về cpe23Uri, version,...'''
            cpeinfo=d['configurations.nodes'][0]
            '''Biến numberOfcpe sẽ là biến nhằm kiểm tra độ dài của cpeinfo'''
            numberOfcpe=0
            
            '''Đoạn code trong phần exception sẽ xử lý biên cpeinfo và trích xuất ra các giá trị cần thiết'''
            '''Tương tự như trên sẽ có 1 số cve không có phần này nên cho nó vào exception'''
            '''Sẽ có 2 trường hợp xảy ra:
                - product chạy trên một hệ điều hành hay hardware nào đó. vd CVE-2021-29907
                - chỉ có các product ảnh hưởng
            cpeinfo sẽ là 1 dictionary chứa 3 giá trị: 'operator', 'children', 'cpe_match'
            Nếu trường hợp 1 xảy ra thì độ dài của cpeinfo['children']==2. 1 cái là các product ảnh hưởng, 1 cái là hệ điều hành hay phần cứng mà nó chạy trên
            Nếu trường hợp 2 xảy ra thì độ dài của cpeinfo['children']==0. thay vào đó 'cpe_match' sẽ khác [] và chứa các cpe ảnh hưởng
            Trong mỗi phần sẽ có các giá trị về version:
                - versionStartIncluding (bắt đầu từ version này và bao gồm cả version này)
                - versionStartExcluding (bắt đầu từ version này và ngoại trừ version này)
                - versionEndExcluding   (Kết thúc tại version này và ngoại trừ version này)
                - versionEndIncluding   (Kết thúc tại version này và bao gồm cả version này)


            '''
            try:
                while 1:
                    ecp=cpeinfo[numberOfcpe]['children']
                    if len(ecp)==2:
                        l1=len(ecp[0]['cpe_match']) #something in l1 running on somthing in l2
                        l2=len(ecp[1]['cpe_match'])
                        #somthing on l1
                        for i in range(l1):
                            namecpe1=ecp[0]['cpe_match'][i]['cpe23Uri'][10:].replace(':',' ').replace('*','').replace('-',' ').replace(',','').replace('_',' ').replace('\\','').title()
                            namecpe1list=namecpe1.split(' ')
                            namecpe1=''
                            for namecpe1split in namecpe1list:
                                if namecpe1split not in namecpe1:
                                    namecpe1=namecpe1+namecpe1split+' '
                            if len(ecp[0]['cpe_match'][i])>3:
                                namecpe1=namecpe1+'versions '
                            #startIn
                            try:
                                namecpe1=namecpe1+'from including '+ecp[0]['cpe_match'][i]['versionStartIncluding']+' '
                            except:
                                pass
                            #startEx
                            try:
                                namecpe1=namecpe1+'from excluding '+ecp[0]['cpe_match'][i]['versionStartExcluding']+' '
                            except:
                                pass
                            #endExclu
                            try:
                                namecpe1=namecpe1+'up to excluding '+ecp[0]['cpe_match'][i]['versionEndExcluding']+' '
                            except:
                                pass
                            #endIxclu
                            try:
                                namecpe1=namecpe1+'up to including '+ecp[0]['cpe_match'][i]['versionEndIncluding']+' '
                            except:
                                pass
                            productname=productname+namecpe1+'\n'
                            if i==l1-1:
                                detail=detail+namecpe1
                            else:
                                detail=detail+namecpe1+', '
                            tam=tam+ecp[0]['cpe_match'][i]['cpe23Uri']+'\n'
                        #something on l2
                        #somthing on l2
                        namecpe2p=''
                        for i in range(l2):
                            namecpe2=ecp[1]['cpe_match'][i]['cpe23Uri'][10:].replace(':',' ').replace('*','').replace('-',' ').replace(',','').replace('_',' ').replace('\\','').title()
                            namecpe2list=namecpe2.split(' ')
                            namecpe2=''
                            for namecpe2split in namecpe2list:
                                if namecpe2split not in namecpe2:
                                    namecpe2=namecpe2+namecpe2split+' '
                            if len(ecp[1]['cpe_match'][i])>3:
                                namecpe2=namecpe2+'versions '
                            #startIn
                            try:
                                namecpe2=namecpe2+'from including '+ecp[1]['cpe_match'][i]['versionStartIncluding']+' '
                            except:
                                pass
                            #startEx
                            try:
                                namecpe2=namecpe2+'from excluding '+ecp[1]['cpe_match'][i]['versionStartExcluding']+' '
                            except:
                                pass
                            #endExclu
                            try:
                                namecpe2=namecpe2+'up to excluding '+ecp[1]['cpe_match'][i]['versionEndExcluding']+' '
                            except:
                                pass
                            #endIxclu
                            try:
                                namecpe2=namecpe2+'up to including '+ecp[1]['cpe_match'][i]['versionEndIncluding']+' '
                            except:
                                pass
                            if i==l2-1:
                                namecpe2p=namecpe2p+namecpe2
                            else:
                                namecpe2p=namecpe2p+namecpe2+', '
                            # tam=tam+ecp[1]['cpe_match'][i]['cpe23Uri']+'\n'
                        detail=detail+'\n'+'running on/with '+namecpe2p+'\n'
                    else:
                        l3=len(cpeinfo[numberOfcpe]['cpe_match'])
                        for i in range(l3):
                            namecpe3=cpeinfo[numberOfcpe]['cpe_match'][i]['cpe23Uri'][10:].replace(':',' ').replace('*','').replace('-',' ').replace(',','').replace('\\','').replace('_',' ').title()
                            namecpe3list=namecpe3.split(' ')
                            namecpe3=''
                            for namecpe3split in namecpe3list:
                                if namecpe3split not in namecpe3:
                                    namecpe3=namecpe3+namecpe3split+' '
                            if len(cpeinfo[numberOfcpe]['cpe_match'][i])>3:
                                namecpe3=namecpe3+'versions '
                            #startIn
                            try:
                                namecpe3=namecpe3+'from including '+cpeinfo[numberOfcpe]['cpe_match'][i]['versionStartIncluding']+' '
                            except:
                                pass
                            #startEx
                            try:
                                namecpe3=namecpe3+'from excluding '+cpeinfo[numberOfcpe]['cpe_match'][i]['versionStartExcluding']+' '
                            except:
                                pass
                            #endExclu
                            try:
                                namecpe3=namecpe3+'up to excluding '+cpeinfo[numberOfcpe]['cpe_match'][i]['versionEndExcluding']+' '
                            except:
                                pass
                            #endIxclu
                            try:
                                namecpe3=namecpe3+'up to including '+cpeinfo[numberOfcpe]['cpe_match'][i]['versionEndIncluding']+' '
                            except:
                                pass
                            productname=productname+namecpe3+'\n'
                            tam=tam+cpeinfo[numberOfcpe]['cpe_match'][i]['cpe23Uri']+'\n'
                    numberOfcpe=numberOfcpe+1
                    if numberOfcpe==len(cpeinfo):
                        break
                productname=re.sub(' +',' ',productname)
            except:
                pass

            '''Biến chin sẽ chứa giá trị referenceURL'''
            try:
                chin=''
                for i in range(len(d['cve.references.reference_data'][0])):
                    chin=chin+d['cve.references.reference_data'][0][i]['url']+'\n'
            except:
                chin=' '
            muoi=''

            '''Sau khi trích xuất hết các giá trị của CVE này thì sẽ đưa nó vào dfr và biến kiểm tra xx=1, tức là đã tìm ra ít nhất 1 cve'''
            new_row={'Affected Product': productname,'Detail':detail, 'CVE ID' : mot, 'Description' :hai, 'CVSSv2' :ba, 'CVSSv3' :bon, 'Severity' :nam, 'Publish Date' :sau, 'Last Modified Date' :bay, 'cpe23Uri' :tam, 'Reference Url' :chin}
            dfr = dfr.append(new_row, ignore_index=True)
            xx=1
    '''Sau khi trích xuất hết các cve'''
    if xx==1:
        '''Đoạn code phía dưới sẽ mớ file chứa product và cpe của công ty nào đó và thực hiện kiểm tra với giá trị của các cve phía trên'''
        '''Tạo ra 2 cột chứa giữ liệu new_colm2 và 3'''
        new_colm2= pd.Series([])
        new_colm3= pd.Series([])
        dlist=pd.read_excel('affected_product_2.xlsx')
        dflist= pd.DataFrame(dlist)
        '''Trích xuất 2 cột CPE và Affected platform trong file và tạo thành 2 list'''
        cpe_list= dflist['CPE']
        affectedplatformlist= dflist['Affected platform']

        '''Chạy vòng lặp list cpe trên tương ứng với chạy vòng lặp cpe của cve bên trên, nếu match thì sẽ lấy giá trị x cho newcolm2, giá trị này nhằm mục đích format excel. giá trị newcolm3 sẽ được gán với Affected platform tương ứng'''
        for i in range(len(cpe_list)):
            for j in range(len(dfr['cpe23Uri'])):
                if cpe_list[i] in dfr['cpe23Uri'][j]:
                    new_colm2[j]='x'
                    new_colm3[j]=affectedplatformlist[i]
        '''Thêm 2 cột khởi tạo phía trên vào dfr'''
        dfr.insert(11,' ',new_colm2)
        dfr.insert(2,'Affected platform',new_colm3)


        #generate file name
        name=random.randint(11111111111111111111,99999999999999999999)
        name=dte+'---'+str(name)+'.xlsx'

        #formatexcel
        writer=pd.ExcelWriter(name, engine='xlsxwriter',options={'strings_to_urls': False})
        dfr.to_excel(writer, sheet_name='Sheet')
        workbook = writer.book
        worksheet=writer.sheets['Sheet']

        format=workbook.add_format({'text_wrap' : True})
        format.set_align('left')
        format.set_align('vcenter')

        worksheet.set_column('B:B',40,format)
        worksheet.set_column("C:C",40,format)
        worksheet.set_column('D:D',40,format)
        worksheet.set_column("E:E",15)
        worksheet.set_column('F:F',80,format)
        worksheet.set_column("J:J",15)
        worksheet.set_column("K:K",15)
        worksheet.set_column('L:L',50,format)
        worksheet.set_column("M:M",200)

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
                                            'criteria': 'LEFT($N1)="x"',
                                            'format': yellow_format2})
        worksheet.conditional_format("H1:H500",{'type': 'cell',
                                            'criteria': 'equal to',
                                            'value': '"CRITICAL"',
                                            'format': dred_format})

        worksheet.conditional_format("I1:I500",{'type': 'cell',
                                            'criteria': 'equal to',
                                            'value': '"HIGH"',
                                            'format': red_format})
        worksheet.conditional_format("I1:I500",{'type': 'cell',
                                            'criteria': 'equal to',
                                            'value': '"MEDIUM"',
                                            'format': orange_format})
        worksheet.conditional_format("I1:I500",{'type': 'cell',
                                            'criteria': 'equal to',
                                            'value': '"LOW"',
                                            'format': yellow_format})
        writer.save()
        print('-----------------')
        print('Done, check file: ',name)
    else:
        print('Nothing, check your input and try again')




'''Đoạn code dưới tạo các argument cho chương trình'''
#create argument
parser = argparse.ArgumentParser(description='CVE')
parser.add_argument("-k",help='Keyword. Example: -k Linux)',default='')
parser.add_argument("-d",help='Last Modified Date. Example: - d 2022-02-22 (default is today)',default=str(date.today()))
parser.add_argument("-u",help='Download and update Data',action='store_true')
args = parser.parse_args()


'''
Đây là chương trình
- Nếu có argument "u" thì nó sẽ chạy update bởi vì giá trị "u" khởi tạo phía trên để store_true
nên nếu có option -u thì nó mới chạy, còn không thì nó không chạy
- Nếu như không có argument truyền vào thì nó sẽ chạy mặc định với giá trị -k (key) và -d (date) đã set default phía trên
'''
#main
if args.u:
    update()
else:
    '''Đoạn execption này để kiểm tra xem đã tải data chưa'''
    try:
        '''Tạo 1 dataframe df lưu trữ các giá trị trong file data đã down'''
        data='nvdcve-1.1-2021.json'
        df = pd.read_json(data)
    except:
        print('Not have data yet!')
        print('Try -h for help')
        exit()
    '''tạo 2 biến dte và key chứa giá trị argument tương ứng truyền vào'''
    dte=args.d
    key=args.k
    print('searching....')
    print('Key: '+key)
    print('Last Modified Date: '+dte)
    search(dte,key)