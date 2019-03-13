from bs4 import BeautifulSoup
import re


def get_required_permission(soup):
    #  required permission
    tmp = soup.find_all(name='uses-permission')
    res = set()
    for t in tmp:
        if t.has_attr('android:name'):
            res.add(t['android:name'])
    return res


def get_hardware_component(soup):
    # hardware component
    tmp = soup.find_all(name='uses-feature')
    res = set()
    for t in tmp:
        if t.has_attr('android:name'):
            res.add(t['android:name'])
    return res


def get_intent(soup):
    # intent
    tmp = soup.find_all(name='action')
    res = set()
    for t in tmp:
        if t.has_attr('android:name'):
            res.add(t['android:name'])
    return res


def get_components(soup):
    # activity
    kind = [r'activity', r'service', r'provider', r'receiver']
    res = {}
    for k in kind:
        kk = soup.find_all(name=k)
        tmp = set()
        for t in kk:
            if t.has_attr('android:name'):
                tmp.add(t['android:name'])
        res[k] = tmp
    return res


def get_manifest_fetures(file):
    # 待检测的xml文件
    xmlFile = open(file, 'r', encoding='utf-8')
    soup = BeautifulSoup(xmlFile, 'html.parser')

    # features from manifest.xml including S1 S2 S3 S4
    required_permissions = get_required_permission(soup)
    hardware_components = get_hardware_component(soup)
    intents = get_intent(soup)
    activities = get_components(soup)

    return required_permissions, hardware_components, intents, activities
