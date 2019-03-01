from bs4 import BeautifulSoup
import re


def get_required_permission(soup):
    #  required permission
    tmp = soup.find_all(name='uses-permission')
    res = []
    for t in tmp:
        res.append(t['android:name'])
    return res


def get_hardware_component(soup):
    # hardware component
    tmp = soup.find_all(name='uses-feature')
    res = []
    for t in tmp:
        if re.search(r'android\.hardware\.\w', t['android:name']):
            res.append(t['android:name'])
    return res


def get_intent(soup):
    # intent
    tmp = soup.find_all(name='action')
    res = []
    for t in tmp:
        if re.search(r'android\.intent\.\w', t['android:name']):
            res.append(t['android:name'])
    return res


def get_components(soup):
    # activity
    kind = [r'activity', r'service', r'provider', r'receiver']
    res = {}
    for k in kind:
        kk = soup.find_all(name=k)
        tmp = []
        for t in kk:
            tmp.append(t['android:name'])
        res[k] = tmp
    return res


def get_manifest_fetures(file):
    # 待检测的xml文件
    xmlFile = open(file, 'r', encoding='utf-8')
    soup = BeautifulSoup(xmlFile, 'html.parser')

    # features
    required_permissions = get_required_permission(soup)
    hardware_components = get_hardware_component(soup)
    intents = get_intent(soup)
    activities = get_components(soup)

    return required_permissions, hardware_components, intents, activities
