import re

pattern = r'<.*?\b(?:src|href|formaction)\b\s*=\s*[\'"]?(?:javascript:|data:|.*?&#[xX]0*(?:6(?:0|f)|3[aA])[^;"\']*(?:(?:\'|")[^\'"]*)*)[\'"]?[^>]*>'
text = """<script>alert(1)</script>
<script src=javascript:alert(1)>
<iframe src=javascript:alert(1)>
<embed src=javascript:alert(1)>
<a href=javascript:alert(1)>click
<math><brute href=javascript:alert(1)>click
<form action=javascript:alert(1)><input type=submit>
<isindex action=javascript:alert(1) type=submit value=click>
<form><button formaction=javascript:alert(1)>click
<form><input formaction=javascript:alert(1) type=submit value=click>
<form><input formaction=javascript:alert(1) type=image value=click>
<form><input formaction=javascript:alert(1) type=image src=SOURCE>
<isindex formaction=javascript:alert(1) type=submit value=click>
<object data=javascript:alert(1)>
<iframe srcdoc=<svg/o&#x6Eload&equals;alert&lpar;1)&gt;>
<svg><script xlink:href=data:,alert(1) />
<math><brute xlink:href=javascript:alert(1)>click
<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=?><circle r=400 /><animate attributeName=xlink:href begin=0 from=javascript:alert(1) to=&>
<html ontouchstart=alert(1)>
<html ontouchend=alert(1)>
<html ontouchmove=alert(1)>
<html ontouchcancel=alert(1)>
<body onorientationchange=alert(1)>
"><img src=1 onerror=alert(1)>.gif
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;"""

matches = re.findall(pattern, text)
print(matches)
