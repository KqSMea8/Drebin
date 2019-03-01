from manifest_features import get_manifest_fetures
from smali_features import get_smali_features

if __name__ == '__main__':
    APK_File = r'E:\apktool\buptyx\\'
    required_permissions, hardware_components, intents, components = get_manifest_fetures(
        APK_File + r'AndroidManifest.xml')
    used_permission, network_address, suspicious_apicall = get_smali_features(APK_File + r'smali')
    with open('result_buptyx', 'w') as f:
        for p in required_permissions:
            f.write('Required_Permission::' + str(p) + '\n')
        for p in hardware_components:
            f.write('Hareware::' + str(p) + '\n')
        for p in intents:
            f.write('Intent::' + str(p) + '\n')

        kind = [r'Activity::', r'Service::', r'Provider::', r'Receiver::']
        for k in kind:
            for p in components[k.lower()[:-2]]:
                f.write(str(k) + str(p) + '\n')

        for p in used_permission:
            f.write('Used_Permission::' + str(p) + '\n')
        for p in network_address:
            f.write('Net_Address::' + str(p) + '\n')
        for p in suspicious_apicall:
            f.write('suspicious_API::' + str(p) + '\n')
