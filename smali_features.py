import os
import re
import PScount.PScoutMapping as PScoutMapping


class SmaliFeatures:
    # features
    def __init__(self):
        self.network_address = set()
        self.used_permission = set()
        self.suspicious_apicall = set()
        self.restricted_apicall = set()
        self.required_permissions = set()
        self.PMap = PScoutMapping.PScoutMapping()

    def find_feature(self, path):
        # print(path)
        with open(path, 'r') as f:
            lines = f.readlines()
        network_address = self.find_network_feature(lines)
        api_call, suspicious_apicall = self.find_invoked_Android_APIs(lines)
        used_permission, restricted_apicall = self.get_permissions_and_API(api_call, self.PMap,
                                                                           self.required_permissions)
        return network_address, used_permission, suspicious_apicall, restricted_apicall

    def find_network_feature(self, instructions):
        URLDomainSet = []
        # network feature
        for instruction in instructions:
            # url_pattern = "http[s]?://([\da-z\.-]+\.[a-z\.]{2, 6}|[\d.]+)[^'\"]*"
            url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            ip_pattern = r'\d+\.\d+\.\d+\.\d+'
            # IP
            item = re.search(ip_pattern, instruction.strip('\n'))
            if item:
                span = item.span()
                Domain = item.string[span[0]:span[1]]
                URLDomainSet.append(Domain)
            # URL
            item = re.search(url_pattern, instruction.strip('\n'))
            if item:
                URL = item.group()
                Domain = re.sub("http[s]?://(.*)", "\g<1>",
                                re.search("http[s]?://([^/:\\\\]*)", URL, re.IGNORECASE).group(), 0, re.IGNORECASE)
                if not re.search('schemas\.android\.com', Domain):
                    URLDomainSet.append(Domain)
        return URLDomainSet

    def get_permissions_and_API(self, ApiList, PMap, RequestedPermissionList):
        '''
        Get Android Permissions used by a list of android APIs
        and meanwhile Get RestrictedApiSet and SuspiciousApiSet

        :param List ApiList
        :param PScoutMapping.PScoutMapping PMap
        :param RequestedPermissionList List([String])
        :return PermissionSet
        :rtype Set<String>
        :return RestrictedApiSet
        :rtype Set([String])
        '''
        PermissionSet = set()
        RestrictedApiSet = set()
        # SuspiciousApiSet=set()
        for Api in ApiList:
            ApiClass = Api['ApiClass'].replace("/", ".").replace("Landroid", "android").strip()
            Permission = PMap.GetPermFromApi(ApiClass, Api['ApiName'])
            if Permission != None:
                if Permission in RequestedPermissionList:
                    PermissionSet.add(Permission)
                else:
                    RestrictedApiSet.add(ApiClass + "." + Api["ApiName"])
        return PermissionSet, RestrictedApiSet

    def find_invoked_Android_APIs(self, DalvikCodeList):
        '''
        Get the android APIs invoked by a list of instrcutions and return these APIs and Suspicious API set.
        :param List<String> DalvikCodeList
        :return ApiList
        :rtype List
        :return SuspiciousApiSet
        :rtype Set([String])
        '''
        DalvikCodeList = set(DalvikCodeList)
        ApiList = []
        SuspiciousApiSet = set()
        AndroidSuspiciousApiNameList = ["getExternalStorageDirectory", "getSimCountryIso", "execHttpRequest",
                                        "sendTextMessage", "getSubscriberId", "getDeviceId", "getPackageInfo",
                                        "getSystemService", "getWifiState",
                                        "setWifiEnabled", "setWifiDisabled", "Cipher"]
        OtherSuspiciousApiNameList = ["Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;)",
                                      "Ljava/net/HttpURLconnection",
                                      "Lorg/apache/http/client/methods/HttpPost",
                                      "Landroid/telephony/SmsMessage;->getMessageBody",
                                      "Ljava/io/IOException;->printStackTrace", "Ljava/lang/Runtime;->exec"]
        NotLikeApiNameList = ["system/bin/su", "android/os/Exec"]
        for DalvikCode in DalvikCodeList:
            if "invoke-" in DalvikCode:
                Parts = DalvikCode.split(",")
                for Part in Parts:
                    if ";->" in Part:
                        Part = Part.strip()
                        if Part.startswith('Landroid'):
                            FullApi = Part
                            ApiParts = FullApi.split(";->")
                            ApiClass = ApiParts[0].strip()
                            ApiName = ApiParts[1].split("(")[0].strip()
                            ApiDetails = {}
                            ApiDetails['FullApi'] = FullApi
                            ApiDetails['ApiClass'] = ApiClass
                            ApiDetails['ApiName'] = ApiName
                            ApiList.append(ApiDetails)
                            if ApiName in AndroidSuspiciousApiNameList:
                                SuspiciousApiSet.add(ApiClass + "." + ApiName)
                    for Element in OtherSuspiciousApiNameList:
                        if (Element in Part):
                            SuspiciousApiSet.add(Element)
            for Element in NotLikeApiNameList:
                if Element in DalvikCode:
                    SuspiciousApiSet.add(Element)

        return ApiList, SuspiciousApiSet

    def listDir(self, rootDir):
        file_list = os.listdir(rootDir)
        for index, item in enumerate(file_list):
            path = os.path.join(rootDir, file_list[index])
            if os.path.isfile(path):
                # 查找权限调用
                tmp_network_address, tmp_used_permission, tmp_suspicious_apicall, tmp_restricted_apicall = \
                    self.find_feature(path)
                self.network_address = self.network_address.union(tmp_network_address)
                self.used_permission = self.used_permission.union(tmp_used_permission)
                self.suspicious_apicall = self.suspicious_apicall.union(tmp_suspicious_apicall)
                self.restricted_apicall = self.restricted_apicall.union(tmp_restricted_apicall)
            else:
                self.listDir(path)


def get_smali_features(rootdir, required_permissions):
    SF = SmaliFeatures()
    SF.required_permissions = required_permissions
    SF.listDir(rootdir)
    return SF.used_permission, SF.network_address, SF.suspicious_apicall, SF.restricted_apicall
