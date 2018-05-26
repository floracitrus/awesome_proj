import argparse
import pickle
import sys
import os
import pefile

from sklearn.externals import joblib
#Author: Flora
# DataSet1 larger input size but PE source unkonwn 
# 1. feature MajorLinkerVersion (0.234059)
# 2. feature SizeOfStackCommit (0.113248)
# 3. feature FileAlignment (0.110251)
# 4. feature SizeOfStackReserve (0.041102)
# 5. feature SizeOfHeapReserve (0.039304)
# 6. feature SizeOfImage (0.036561)
# 7. feature MajorImageVersion (0.030623)
# 8. feature NumberOfSymbols (0.030120)
# 9. feature PointerToSymbolTable (0.028437)
# 10. feature NumberOfSections (0.027913)
# 11. feature MinorOperatingSystemVersion (0.026544)
# 12. feature SizeOfInitializedData (0.026437)
# 13. feature SizeOfHeaders (0.024357)
# 14. feature DllCharacteristics (0.022569)
# 15. feature BaseOfData (0.020538)

#DataSet2 smaller input size but extract from raw PE
# 1. feature sec_rawsize_rlpack (0.109827)
# 2. feature pe_minorlink (0.045955)
# 3. feature datadir_IMAGE_DIRECTORY_ENTRY_RESOURCE_size (0.045525)
# 4. feature sec_entropy_sdata (0.044146)
# 5. feature generated_check_sum (0.043992)
# 6. feature total_size_pe (0.036956)
# 7. feature sec_entropy_tls (0.035764)
# 8. feature pe_dll (0.032011)
# 9. feature sec_entropy_data3 (0.030582)
# 10. feature pe_char (0.029859)
# 11. feature datadir_IMAGE_DIRECTORY_ENTRY_IAT_size (0.023890)
# 12. feature pe_warnings (0.023641)


def extract_important_features(file):
    pe = pefile.PE(file)
    fea = {}
    fea['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    
    fea['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    
    #fea['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    fea['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    
    fea['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    
    fea['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve

    fea['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    
    fea['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    
    fea['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    fea['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion

    fea['NumberOfSections'] = len(pe.sections)

    fea['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    
    fea['NumberOfSymbols'] = pe.FILE_HEADER.NumberOfSymbols
    try:
        fea['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except Exception as e:
       fea['BaseOfData'] = 0

   
    fea['PointerToSymbolTable'] = pe.FILE_HEADER.PointerToSymbolTable


    fea['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion

#    fea['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
#    fea['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    fea['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics

    fea['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum

    fea['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    fea['e_ss']=pe.DOS_HEADER.e_ss
    fea['e_oemid']=pe.DOS_HEADER.e_oemid
    fea['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    fea['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    fea['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    fea['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    fea['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    fea['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    fea['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    fea['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    fea['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
#   fea['SizeOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
#   fea['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode##not sure
#     if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
#        num_imported_symbols = 0
#        for module in pe.DIRECTORY_ENTRY_IMPORT:
#            num_imported_symbols += len(module.imports)
  
#        fea['number_of_import_symbols'] = num_imported_symbols
#    else:
#      fea['number_of_import_symbols'] = 0
    return fea




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Detect malicious files')
    parser.add_argument('FILE', help='File to be tested')
    args = parser.parse_args()
    # Load classifier
    clf = joblib.load(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier.pkl'
    ))

    features = pickle.loads(open(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'features.pkl'),
        'r').read()
    )

    data = extract_important_features(args.FILE)

    pe_features = map(lambda x:data[x], features)

    res = clf.predict([pe_features])[0]
    #print res

    print 'The file %s is %s' % (
        os.path.basename(sys.argv[1]),
        ['malicious', 'good'][res])
    
    # from os import listdir
    # from os.path import isfile, join
    # path_to_data = args.FILE
    # files = [path_to_data+f for f in listdir(path_to_data) if isfile(join(path_to_data, f))]

    # good_cnt = 0
    # bad_cnt = 0
    # for f in files:
        
    #     data = extract_important_features(f)
    #     # print clf
    #     # print len(features)
    #     # print len(data)
    #     # print features
    #     # print data

    #     pe_features = map(lambda x:data[x], features)
    #     # print type(pe_features)
    #     # print pe_features
        
    #     # 
    #     res = clf.predict([pe_features])[0]
    #     #print res

    #     good_cnt += [1, 0][res]
    #     bad_cnt += [0, 1][res]

    #     print 'The file %s is %s ' % (str(f),
    #         #os.path.basename(sys.argv[1]),
    #         ['malicious', 'good'][res])
    # print good_cnt, bad_cnt
