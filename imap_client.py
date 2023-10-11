import imaplib
from imapclient import imap_utf7

server = "imap.gmail.com"
imap_client = imaplib.IMAP4_SSL(server)
result, data = imap_client.login("admin@hermancorp.biz", "DavidPrintedA3DThing!")
print(result, data)
result, data = imap_client.select('"{}"'.format(imap_utf7.encode("inbox").decode()), True)
print(result, data[0])