import os
import re


class SmaliFeatures:
    # features
    def __init__(self):
        self.network_address = list()
        self.used_permission = list()
        self.suspicious_apicall = list()
        self.restricted_apicall = list()

    def find_feature(self, path):
        network_address = []
        used_permission = []
        suspicious_apicall = []
        restricted_apicall = []
        with open(path, 'r') as f:
            lines = f.readlines()
        for line in lines:
            line = line.split('\n')[0]
            if line:
                # network feature
                tmp = self.find_network_feature(line)
                if tmp:
                    network_address.append(tmp)
                # used permission permission
                tmp = self.find_used_permission_feature(line)
                if tmp:
                    used_permission.append(tmp)

                # Suspicious api calll
                tmp = self.find_Suspicious_api_call(line)
                if tmp:
                    suspicious_apicall.append(tmp)

                # Restricted API call
                # TODO

        return network_address, used_permission, suspicious_apicall, restricted_apicall

    def find_network_feature(self, context):
        # network feature
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        ip_pattern = r'\d+\.\d+\.\d+\.\d+'
        # IP
        item = re.search(ip_pattern, context.strip('\n'))
        if item:
            span = item.span()
            item = item.string[span[0]:span[1]]
            return item
        # URL
        item = re.search(url_pattern, context.strip('\n'))
        if item:
            span = item.span()
            item = item.string[span[0]:span[1]]
            if not re.search('http://schemas\.android\.com', item):
                return item

    def find_used_permission_feature(self, context):
        # used permission permission
        p = re.search(r'''android.permission.\w''', context)
        if p:
            span = p.span()
            p = p.string[span[0]::]
            for index, item in enumerate(p):
                if item is '"':
                    return p[0:index]

    def find_Suspicious_api_call(self, context):


        pattern = r'Landroid/(?:telephony/TelephonyManager;->(?:getNetworkOperator|getDeviceId|getPhoneType|' \
                  r'getSubscriberId|getLine1Number|getCellLocation|listen|getSimOperator)|' \
                  r'telephony/SmsManager;->sendTextMessage|' \
                  r'telephony/gsm/GsmCellLocation;->(?:getLac|getCid)|' \
                  r'app/ActivityManager;->getRunning(?:AppProcesses|Tasks)|' \
                  r'content/pm/PackageManager;->getInstalledPackages)'
        p = re.search(pattern, context, re.IGNORECASE)
        if p:
            span = p.span()
            return p.string[span[0]:]

    def listDir(self, rootDir):
        file_list = os.listdir(rootDir)
        for index, item in enumerate(file_list):
            path = os.path.join(rootDir, file_list[index])
            if os.path.isfile(path):
                # 查找权限调用
                tmp_network_address, tmp_used_permission, tmp_suspicious_apicall, tmp_restricted_apicall = self.find_feature(
                    path)
                # 去除重复值
                if tmp_network_address:
                    for tmp in tmp_network_address:
                        if tmp not in self.network_address:
                            self.network_address.append(tmp)
                if tmp_used_permission:
                    for tmp in tmp_used_permission:
                        if tmp not in self.used_permission:
                            self.used_permission.append(tmp)
                if tmp_suspicious_apicall:
                    for tmp in tmp_suspicious_apicall:
                        if tmp not in self.suspicious_apicall:
                            self.suspicious_apicall.append(tmp)
                if tmp_restricted_apicall:
                    for tmp in tmp_restricted_apicall:
                        if tmp not in self.restricted_apicall:
                            self.restricted_apicall.append(tmp)
            else:
                self.listDir(path)


def get_smali_features(rootdir):
    SF = SmaliFeatures()
    SF.listDir(rootdir)
    return SF.used_permission, SF.network_address, SF.suspicious_apicall
