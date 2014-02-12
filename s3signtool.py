import getopt
import sys
import hmac
import base64
import urllib
import hashlib
import collections

url = None
awskey = None
secret = None
expires = None
fullurl = None

def usage():
     print("")
     print("Required Options:")
     print("-u / --url:    Url to the resource")
     print("-k / --key:    AWS Access Key")
     print("-s / --secret: AWS Secret")
     print("")
     print("Example: 'signtool.py --url https://s3-us-west-2.amazonaws.com/s3bucket/s3file.ext --key AKAIFDSSHEIEFKLSJFEEXAMPLEKEY --secret AWSSECRET'")
     print("Result:  ''")


try:
     opts, args = getopt.getopt(sys.argv[1:], "u:k:s:t:", ["url=", "key=", "secret=", "timestamp="])
     
     # Check for required params
     ro = { "url": False, "key": False, "secret": False, "expires": False } 
     for o,a in opts:
          if (o == '-u' or o == '--url'):       ro["url"] = True
          if (o == '-k' or o == '--key'):       ro["key"] = True
          if (o == '-s' or o == '--secret'):    ro["secret"] = True
          if (o == '-t' or o == '--timestamp'): ro["expires"] = True
     if not (ro["url"] and ro["key"] and ro["secret"] and ro["expires"]):
          usage()
          sys.exit(2)
except:
     usage()
     sys.exit(2)


for o,a in opts:
     if o in ["--url", "-u"]:
          fullurl = a
          tempurl = fullurl.replace("http://","").replace("https://","") 
          if ("/" in tempurl):
               slashIndex = tempurl.index('/')
               url = tempurl[0:slashIndex]
               path = tempurl[slashIndex:] 
          else:
               url = tempurl
               path = "/"
     elif o in ["--key","-k"]:
          awskey = a
     elif o in ["--secret","-s"]:
          secret = a
     elif o in ["--timestamp","-t"]:
          expires = a


stringToSign = "GET\n\n\n%s\n%s" % (expires, path)

# hmacSHA256 hash it
h = hmac.new(secret, stringToSign, hashlib.sha1)
d = h.digest()

# base64 encode it (adds a linefeed - known bug in base64: http://bugs.python.org/issue17714)
e = d.encode('base64', 'strict').rstrip("\n")

# http encode it
signature = urllib.quote(e)

proto = None
if "https" in fullurl: 
     proto = "https://"
else:
     proto = "http://"

sys.stdout.write(proto + url + path + "?AWSAccessKeyId=" + awskey + "&Expires=" + expires + "&Signature=" + signature)
