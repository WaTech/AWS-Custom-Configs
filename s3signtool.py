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
useFullUrl = False

def usage():
     print("")
     print("Required Options:")
     print("-u / --url:    <Url to the resource>")
     print("-k / --key:    <AWS Access Key>")
     print("-s / --secret: <AWS Secret>")
     print("-e / --expires: <Unix Timestamp>")
     print("-f / --full: Print full signature (instead of just signature)")
     print("")
     print("Example: 'signtool.py --url https://s3-us-west-2.amazonaws.com/s3bucket/s3file.ext --key AKAIFDSSHEIEFKLSJFEEXAMPLEKEY --secret AWSSECRET'")
     print("Result:  ''")


try:
     opts, args = getopt.getopt(sys.argv[1:], "u:k:s:e:f", ["url=", "key=", "secret=", "expires=", "full"])
     
     # Check for required params
     ro = { "url": False, "key": False, "secret": False, "expires": False } 
     for o,a in opts:
          if (o == '-u' or o == '--url'):       ro["url"] = True
          if (o == '-k' or o == '--key'):       ro["key"] = True
          if (o == '-s' or o == '--secret'):    ro["secret"] = True
          if (o == '-e' or o == '--expires'):   ro["expires"] = True
     if not (ro["url"] and ro["key"] and ro["secret"] and ro["expires"]):
          usage()
          sys.exit(2)
          
except getopt.GetoptError as err:
     print(str(err))
     usage()
     sys.exit(2)

# Load variable from opts
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
     elif o in ["--expires","-e"]:
          expires = a
     elif o in ["--full","-f"]:
          useFullUrl = True;


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

	if useFullUrl:
	   sys.stdout.write(proto + url + path + "?AWSAccessKeyId=" + awskey + "&Expires=" + expires + "&Signature=" + signature)
	else:
		sys.stdout.write(signature)