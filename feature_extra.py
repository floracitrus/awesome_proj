import pefile
import os
import sys
import math
import pandas as pd
import sklearn.ensemble
import numpy as np
import matplotlib.pyplot as plt
import sklearn.cross_validation
#No License requires
#Thanks Brian Wylie from Click Security for the class PEFile Structure, 
#it is a more decent way to handle the exception with putting the dense features, and sparse features apart. 
#Flora editted the other part of files.
#Schema:
#First need to open the PEFILE
#Second need to be able to parse the file sections
#Third need to handle the sanity of data, missing or change of position
#Fourth after clean those and convert to int or double put into the Matrix of train

class PEFileFeatures():
    ''' Create instance of PEFileFeatures class. This class pulls static
        features out of a PE file using the python pefile module.
    '''

    def __init__(self):
        ''' Init method '''
        # Set the features that I'm expected PE File to extract, note this is just
        # for sanity checking, meaning that if you don't get some of these features
        # the processing will spit out warnings for each feature not extracted.
        self._dense_feature_list = None
        self._dense_features = None

        # Okay now the sparse fields
        self._sparse_feature_list = None
        self._sparse_features = None

        # Verbose
        self._verbose = False

        # Warnings handle
        self._warnings = []
        self.set_dense_features(['check_sum', 'generated_check_sum', 'compile_date', 'debug_size', 'export_size', 'iat_rva', 'major_version', \
                                 'minor_version', 'number_of_bound_import_symbols', 'number_of_bound_imports', 'number_of_export_symbols', \
                                 'number_of_import_symbols', 'number_of_imports', 'number_of_rva_and_sizes', 'number_of_sections', 'pe_warnings', \
                                 'std_section_names', 'total_size_pe', 'virtual_address', 'virtual_size', 'virtual_size_2', \
                                 'datadir_IMAGE_DIRECTORY_ENTRY_BASERELOC_size', 'datadir_IMAGE_DIRECTORY_ENTRY_RESOURCE_size', \
                                 'datadir_IMAGE_DIRECTORY_ENTRY_IAT_size', 'datadir_IMAGE_DIRECTORY_ENTRY_IMPORT_size', \
                                 'pe_char', 'pe_dll', 'pe_driver', 'pe_exe', 'pe_i386', 'pe_majorlink', 'pe_minorlink', \
                                 'sec_entropy_data', 'sec_entropy_rdata', 'sec_entropy_reloc', 'sec_entropy_text', 'sec_entropy_rsrc', \
                                 'sec_rawptr_rsrc', 'sec_rawsize_rsrc', 'sec_vasize_rsrc', 'sec_raw_execsize', \
                                 'sec_rawptr_data', 'sec_rawptr_text', 'sec_rawsize_data', 'sec_rawsize_text', 'sec_va_execsize', \
                                 'sec_vasize_data', 'sec_vasize_text', 'size_code', 'size_image', 'size_initdata', 'size_uninit'])

        self.set_sparse_features(['imported_symbols', 'section_names', 'pe_warning_strings'])
        # Dense feature list: this only functions to ensure that all of these
        #features get extracted with a sanity check at the end.


    def set_dense_features(self, dense_feature_list):
        self._dense_feature_list = dense_feature_list

    def get_dense_features(self):
        return self._dense_features

    def set_sparse_features(self, sparse_feature_list):
        ''' Set the sparse feature list that the Python pefile module should extract.
            This is really just sanity check functionality, meaning that these
            are the features you are expecting to get, and a warning will spit
            out if you don't get some of these. '''
        self._sparse_feature_list = sparse_feature_list

    def get_sparse_features(self):
        ''' Set the sparse feature list that the Python pefile module should extract. '''
        return self._sparse_features



    def execute(self, input_data):
      
        raw_bytes = input_data
        # Have the PE File module process the file
        pefile_handle, error_str = self.open_using_pefile('unknown', raw_bytes)
        if not pefile_handle:
            return {'error': error_str}

        # Now extract the various features using pefile
        return self.extract_features_using_pefile(pefile_handle)


    def get_entropy(data):
        entropy = 0
        for count in byte_counts:
        # If no bytes of this value were seen in the value, it doesn't affect
        # the entropy of the file.
            if count == 0:
                continue
            # p is the probability of seeing this byte in the file, as a floating-
            # point number
            p = 1.0 * count / total
            entropy -= p * math.log(p, 256)
        return entropy

    # Make sure pe can parse this file
    def open_using_pefile(self, input_name, input_bytes):
        ''' Open the PE File using the Python pefile module. '''
        try:
            pe = pefile.PE(data=input_bytes, fast_load=False)
        except Exception, error:
            print 'warning: pe_fail (with exception from pefile module) on file: %s' % input_name
            error_str =  '(Exception):, %s' % (str(error))
            return None, error_str

        # Now test to see if the features are there/extractable if not return FAIL flag
        if (pe.PE_TYPE is None or pe.OPTIONAL_HEADER is None or len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) < 7):
            print 'warning: pe_fail on file: %s' % input_name
            error_str = 'warning: pe_fail on file: %s' % input_name
            return None, error_str

        # Success
        return pe, None

    # Extract various set of features using PEfile module
    def extract_features_using_pefile(self, pe):
        ''' Process the PE File using the Python pefile module. '''

        # Store all extracted features into feature lists
        extracted_dense = {}
        extracted_sparse = {}

        # Now slog through the info and extract the features
        feature_not_found_flag = -99
        feature_default_value = 0
        self._warnings = []

        # Set all the dense features and sparse features to 'feature not found'
        # value and then check later to see if it was found
        for feature in self._dense_feature_list:
            extracted_dense[feature] = feature_not_found_flag
        for feature in self._sparse_feature_list:
            extracted_sparse[feature] = feature_not_found_flag


        # Check to make sure all the section names are standard
        std_sections = ['.text', '.bss', '.rdata', '.data', '.rsrc', '.edata', '.idata', \
                        '.pdata', '.debug', '.reloc', '.stab', '.stabstr', '.tls', \
                        '.crt', '.gnu_deb', '.eh_fram', '.exptbl', '.rodata']
        for i in range(200):
            std_sections.append('/'+str(i))
        std_section_names = 1
        extracted_sparse['section_names'] = []
        
        for section in pe.sections:
            name = convertToAsciiNullTerm(section.Name).lower()
            extracted_sparse['section_names'].append(name)
            if (name not in std_sections):
                std_section_names = 0

        extracted_dense['std_section_names']      = std_section_names
        extracted_dense['debug_size']             = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size
        extracted_dense['major_version']          = pe.OPTIONAL_HEADER.MajorImageVersion
        extracted_dense['minor_version']          = pe.OPTIONAL_HEADER.MinorImageVersion
        extracted_dense['iat_rva']                = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
        extracted_dense['export_size']            = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
        extracted_dense['check_sum']              = pe.OPTIONAL_HEADER.CheckSum
        try:
            extracted_dense['generated_check_sum'] = pe.generate_checksum()
        except ValueError:
            extracted_dense['generated_check_sum'] = 0
        if (len(pe.sections) > 0):
            extracted_dense['virtual_address']     = pe.sections[0].VirtualAddress
            extracted_dense['virtual_size']        = pe.sections[0].Misc_VirtualSize
        extracted_dense['number_of_sections']      = pe.FILE_HEADER.NumberOfSections
        extracted_dense['compile_date']            = pe.FILE_HEADER.TimeDateStamp
        extracted_dense['number_of_rva_and_sizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        extracted_dense['total_size_pe']           = len(pe.__data__)


        
        # Number of import and exports
        if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
            extracted_dense['number_of_imports'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            num_imported_symbols = 0
            for module in pe.DIRECTORY_ENTRY_IMPORT:
                num_imported_symbols += len(module.imports)
            extracted_dense['number_of_import_symbols'] = num_imported_symbols

        if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
            extracted_dense['number_of_bound_imports'] = len(pe.DIRECTORY_ENTRY_BOUND_IMPORT)
            num_imported_symbols = 0
            for module in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                num_imported_symbols += len(module.entries)
            extracted_dense['number_of_bound_import_symbols'] = num_imported_symbols

        if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
            extracted_dense['number_of_export_symbols'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            symbol_set = set()
            for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                symbol_info = 'unknown'
                if (not symbol.name):
                    symbol_info = 'ordinal=' + str(symbol.ordinal)
                else:
                    symbol_info = 'name=' + symbol.name

                symbol_set.add(convertToUTF8('%s'%(symbol_info)).lower())

            # Now convert set to list and add to features
            extracted_sparse['ExportedSymbols'] = list(symbol_set)

        # Specific Import info (Note this will be a sparse field woo hoo!)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            symbol_set = set()
            for module in pe.DIRECTORY_ENTRY_IMPORT:
                for symbol in module.imports:
                    symbol_info = 'unknown'
                    if symbol.import_by_ordinal is True:
                        symbol_info = 'ordinal=' + str(symbol.ordinal)
                    else:
                        symbol_info = 'name=' + symbol.name
                        #symbol_info['hint'] = symbol.hint
                    if symbol.bound:
                        symbol_info += ' bound=' + str(symbol.bound)

                    symbol_set.add(convertToUTF8('%s:%s'%(module.dll, symbol_info)).lower())

            # Now convert set to list and add to features
            extracted_sparse['imported_symbols'] = list(symbol_set)

        # Do we have a second section
        if (len(pe.sections) >= 2):
            extracted_dense['virtual_size_2']      = pe.sections[1].Misc_VirtualSize

        extracted_dense['size_image']             = pe.OPTIONAL_HEADER.SizeOfImage
        extracted_dense['size_code']              = pe.OPTIONAL_HEADER.SizeOfCode
        extracted_dense['size_initdata']          = pe.OPTIONAL_HEADER.SizeOfInitializedData
        extracted_dense['size_uninit']            = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        extracted_dense['pe_majorlink']           = pe.OPTIONAL_HEADER.MajorLinkerVersion
        extracted_dense['pe_minorlink']           = pe.OPTIONAL_HEADER.MinorLinkerVersion
        extracted_dense['pe_driver']              = 1 if pe.is_driver() else 0
        extracted_dense['pe_exe']                 = 1 if pe.is_exe() else 0
        extracted_dense['pe_dll']                 = 1 if pe.is_dll() else 0
        extracted_dense['pe_i386']                = 1
        if pe.FILE_HEADER.Machine != 0x014c:
            extracted_dense['pe_i386'] = 0
        extracted_dense['pe_char']                = pe.FILE_HEADER.Characteristics

        # Data directory features!!
        datadirs = { 0: 'IMAGE_DIRECTORY_ENTRY_EXPORT', 1:'IMAGE_DIRECTORY_ENTRY_IMPORT', 2:'IMAGE_DIRECTORY_ENTRY_RESOURCE', 5:'IMAGE_DIRECTORY_ENTRY_BASERELOC', 12:'IMAGE_DIRECTORY_ENTRY_IAT'}
        for idx, datadir in datadirs.items():
            datadir = pefile.DIRECTORY_ENTRY[ idx ]
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= idx:
                continue

            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
            extracted_dense['datadir_%s_size' % datadir] = directory.Size

        # Section features
        section_flags = ['IMAGE_SCN_MEM_EXECUTE', 'IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_MEM_WRITE', 'IMAGE_SCN_MEM_READ']
        rawexecsize = 0
        vaexecsize = 0
        for sec in pe.sections:
            if not sec:
                continue

            for char in section_flags:
                # does the section have one of our attribs?
                if hasattr(sec, char):
                    rawexecsize += sec.SizeOfRawData
                    vaexecsize  += sec.Misc_VirtualSize
                    break

            # Take out any weird characters in section names
            secname = convertToAsciiNullTerm(sec.Name).lower()
            secname = secname.replace('.','')
            extracted_dense['sec_entropy_%s' % secname ] = sec.get_entropy()
            extracted_dense['sec_rawptr_%s' % secname] = sec.PointerToRawData
            extracted_dense['sec_rawsize_%s' % secname] = sec.SizeOfRawData
            extracted_dense['sec_vasize_%s' % secname] = sec.Misc_VirtualSize


        extracted_dense['sec_va_execsize'] = vaexecsize
        extracted_dense['sec_raw_execsize'] = rawexecsize

        # Register if there were any pe warnings
        warnings = pe.get_warnings()
        if (warnings):
            extracted_dense['pe_warnings'] = 1
            extracted_sparse['pe_warning_strings'] = warnings
        else:
            extracted_dense['pe_warnings'] = 0


        # Issue a warning if the feature isn't found
        for feature in self._dense_feature_list:
            if (extracted_dense[feature] == feature_not_found_flag):
                extracted_dense[feature] = feature_default_value
                if (self._verbose):
                    self.log('info: Feature: %s not found! Setting to %d' % (feature, feature_default_value))
                    self._warnings.append('Feature: %s not found! Setting to %d' % (feature, feature_default_value))

        # Issue a warning if the feature isn't found
        for feature in self._sparse_feature_list:
            if (extracted_sparse[feature] == feature_not_found_flag):
                extracted_sparse[feature] = feature_default_value
                if (self._verbose):
                    self.log('info: Feature: %s not found! Setting to %d' % (feature, feature_default_value))
                    self._warnings.append('Feature: %s not found! Setting to %d' % (feature, feature_default_value))


        # Set the features for the class var
        self._dense_features = extracted_dense
        self._sparse_features = extracted_sparse

        return self.get_dense_features() #, self.get_sparse_features()

# Helper functions
def convertToUTF8(s):
    if (isinstance(s, unicode)):
        return s.encode( "utf-8" )
    try:
        u = unicode( s, "utf-8" )
    except:
        return str(s)
    utf8 = u.encode( "utf-8" )
    return utf8

def convertToAsciiNullTerm(s):
    s = s.split('\x00', 1)[0]
    return s.decode('ascii', 'ignore')
    

def convertToAsciiNullTerm(s):
    s = s.split('\x00', 1)[0]
    return s.decode('ascii', 'ignore')

# Unit test: Create the class, the proper input and run the execute() method for a test
def test():
    ''' pe_features.py: Unit test'''
    my_extractor = PEFileFeatures()

    with open('data/good/090a189f4eeb3c0b76e97acdb1a71c92','rb') as f:#bad/033d91aae8ad29ed9fbb858179271232','rb') as f:
        print my_extractor.execute(f.read())

def load_files(file_list):
    features_list = []
    for filename in file_list:
        with open(filename,'rb') as f:
            features_list.append(my_extractor.execute(f.read()))
    return features_list

# Unit test: Create the class, the proper input and run the execute() method for a test
def test():
    ''' pe_features.py: Unit test'''
    my_extractor = PEFileFeatures()
    with open('data/bad/033d91aae8ad29ed9fbb858179271232','rb') as f:
        print my_extractor.execute(f.read())

def plot_cm(cm, labels):
    # Compute percentanges
    percent = (cm*100.0)/np.array(np.matrix(cm.sum(axis=1)).T)  # Derp, I'm sure there's a better way   
    print ('Confusion Matrix Stats')
    for i, label_i in enumerate(labels):
        for j, label_j in enumerate(labels):
            print( "%s/%s: %.2f%% (%d/%d)" % (label_i, label_j, (percent[i][j]), cm[i][j], cm[i].sum()))

    # Show confusion matrix
    # Thanks kermit666 from stackoverflow :)
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.grid(b=False)
    cax = ax.matshow(percent, cmap='coolwarm',vmin=0,vmax=100)
    plt.title('Confusion matrix of the classifier')
    fig.colorbar(cax)
    ax.set_xticklabels([''] + labels)
    ax.set_yticklabels([''] + labels)
    plt.xlabel('Predicted')
    plt.ylabel('True')
    plt.show()

if __name__ == "__main__":
    my_extractor = PEFileFeatures()
    bad_features = load_files([os.path.join('data/bad', child) for child in os.listdir('data/bad')])
    df_bad = pd.DataFrame.from_records(bad_features)
    df_bad['label'] = 'bad'
    df_bad.to_csv("data/pefbad.csv", sep=',',index=False)
    print ('Loaded up %d malicious PE Files' % len(bad_features))

    file_list = [os.path.join('data/good', child) for child in os.listdir('data/good')]
    good_features = load_files(file_list)
    df_good = pd.DataFrame.from_records(good_features)
    df_good['label'] = 'good'
    df_good.head()
    df_good.to_csv("data/pefgood.csv", sep=',',index=False)
    print ('Loaded up %d benign PE Files' % len(good_features))
    
    # Concatenate the info into a big pile!
    df = pd.concat([df_bad, df_good], ignore_index=True)
    df.replace(np.nan, 0, inplace=True)    
    # Get some quick summary stats and plot it!
    df.boxplot('number_of_import_symbols','label')
    plt.xlabel('bad vs. good files')
    plt.ylabel('number of import Symbols')
    plt.title('Comparision of # Import Symbols')
    plt.suptitle("")
    
    #plt.figure()
    df.boxplot('sec_entropy_data','label')
    plt.xlabel('bad vs. good files')
    plt.ylabel('sec entropy')
    plt.title('Comparision of section entropy data')
    plt.suptitle("")

    print df_good[['number_of_import_symbols']].mean(axis =0)
    print df_good[['number_of_import_symbols']].var(axis =0)

    print df_bad[['number_of_import_symbols']].mean(axis =0)
    print df_bad[['number_of_import_symbols']].var(axis =0)

    plt.figure()
    plt.title("compare of symbol import")
    plt.hist([df_good['number_of_import_symbols'], df_bad['number_of_import_symbols']],color=["green", "red"],label=["benign", "malicious"])
    plt.legend()
    plt.plot()

    plt.figure()
    plt.title("compare of section entropy")
    plt.hist([df_good['sec_entropy_data'], df_bad['sec_entropy_data']],color=["green", "red"],label=["benign", "malicious"])
    plt.legend()
    plt.plot()


    plt.figure()
    plt.title("compare of MajorLinker")
    plt.hist([df_good['pe_majorlink'], df_bad['pe_majorlink']],color=["green", "red"],label=["benign", "malicious"])
    plt.legend()
    plt.plot()
# In preparation for using scikit learn we're just going to use
# some handles that help take us from pandas land to scikit land

# List of feature vectors (scikit learn uses 'X' for the matrix of feature vectors)
    X = df.as_matrix(['number_of_import_symbols', 'sec_entropy_data','sec_rawsize_data','number_of_sections'])

# Labels (scikit learn uses 'y' for classification labels)
    y = np.array(df['label'].tolist())
    clf = sklearn.ensemble.RandomForestClassifier(n_estimators=50)
    scores = sklearn.cross_validation.cross_val_score(clf, X, y, cv=5, n_jobs=4)
    print scores

    # Typically you train/test on an 80% / 20%  split meaning you train on 80%
    # of the data and you test against the remaining 20%. In the case of this
    # exercise we have so FEW samples (50 good/50 bad) that if were going
    # to play around with predictive performance it's more meaningful
    # to train on 60% of the data and test against the remaining 40%.

    my_seed = 123
    my_tsize = .4 # 40%
    from sklearn.cross_validation import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=my_tsize, random_state=my_seed)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)



    # Now plot the results of the 60/40 split in a confusion matrix
    from sklearn.metrics import confusion_matrix
    labels = ['good', 'bad']
    cm = confusion_matrix(y_test, y_pred, labels)
    plot_cm(cm, labels)
    #test()
    #file_list = [os.path.join('data/bad', child) for child in os.listdir('data/bad')]
    #good_feature = load_files(data/good)
    #bad_feature = load_files(data/bad)

    
