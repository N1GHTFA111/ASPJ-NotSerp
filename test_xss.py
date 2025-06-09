
from difflib import SequenceMatcher
from Detection_System.sentinel import detect_xss

def xss_detection(func):
    def detector(form_info):
        with open('Detection_System/xss-payload-list.txt', 'r', encoding="utf8") as f:
            if form_info in f.read():
                print("XSS detected")
                return None
        func()
    return detector

def detection(form_info):
    with open('Detection_System/xss-payload-list.txt', 'r', encoding="utf8") as f:
        if form_info in f.read():
            print("XSS detected")
            return True
    return False

def xss_vuln():
    if detection("<Script>alert('hi')</scripT>"):
        print("XSS detected")
    print("Done executing")

#
# xss_vuln()
#
# print(SequenceMatcher(None, "<Script>alert('')</scripT>", "<Script>alert('')</scripT>").ratio())
import codecs
#
total = 0
detected = 0
with codecs.open('Detection_System/xss-payload-list.txt', 'r', 'utf-8') as f:
    for line in f.readlines():
        # print(line)
        if detect_xss(line):
            # print("XSS detected")
            total += 1
            detected += 1
            # print("\n")
        else:
            # print("Not detected")
            total += 1
            print(line)

print(f"Ratio:{detected} / {total}")



