"""
Handles the authentication and simple interaction
with the E*Trade API.
"""
import sys
from configparser import ConfigParser
import getpass
import logging
from pathlib import Path

import requests
from requests_oauthlib import OAuth1Session
from bs4 import BeautifulSoup
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto import Random

class ETradeAPI(object):
    """
    Encapsulates the authentication routines.

    Attributes:
        oauth_consumer_key (str): consumer token (app key given by E*Trade).
        consumer_secret (str): consumer secret (app secret given by E*Trade).
        sandbox_url (str): current E*Trade sandbox environment URL.
        prod_url (str): current E*Trade production environment URL.
        oauth (OAuth1Session): session to send API requests on. This
            object will only be functional after a call to ``init_access``.
    """
    def __init__(self, oauth_consumer_key, consumer_secret, *,
                 logfile='~/.etrade.log'):
        self.oauth_consumer_key = oauth_consumer_key
        self.consumer_secret = consumer_secret
        self.sandbox_url = 'https://etwssandbox.etrade.com/'
        self.prod_url = 'https://etws.etrade.com/'
        self.oauth = None

        # Setup logging
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.ERROR)
        root_logger.addHandler(console_handler)
        file_handler = logging.FileHandler(Path(logfile).expanduser())
        root_logger.addHandler(file_handler)

    def user_auth(self, username, password, app_auth_token):
        """Simulate user interacting with the E*Trade web API login form.

        Args:
            username (str): valid E*Trade username
            password (str): valid E*Trade password
            app_auth_token (str): Token given after app authenticates against E*Trade.
        Returns:
            str 5-character verification code displayed to the user in a normal
                login routine.
        """
        auth_url = (f'https://us.etrade.com/e/t/etws/authorize?'
                    f'key={self.oauth_consumer_key}&token={app_auth_token}')
        with requests.Session() as user_sess:
            # Get to the login page
            resp = user_sess.get(auth_url)
            page = BeautifulSoup(resp.text, 'html.parser')
            # if has recently logged in, they'll go to the second step automatically
            # if page.find('input', attrs={'ID': 'user_orig'}):
            payload = {'USE_IDENTITY_TOKEN': 'false',
                       'USER': username,
                       'PASSWORD': password,
                       'TARGET': ('/e/t/user/xfr?Target=/e/t/etws/authorize'
                                  f'?key={self.oauth_consumer_key}'
                                  f'&token={app_auth_token}')}
            resp = user_sess.post('https://us.etrade.com/login?b',
                                  data=payload)
            page = BeautifulSoup(resp.text, 'html.parser')
            # Parse the Accept/Decline page
            value = page.find('input', attrs={'name': 'stk1'})['value']
            payload = {'stk1': value,
                       'formpost': 1,
                       'submit': 'Accept'}
            resp = user_sess.post('https://us.etrade.com/e/t/etws/TradingAPICustomerInfo',
                                  data=payload)
            # Parse the verification code page
            page = BeautifulSoup(resp.text, 'html.parser')
            verif = page.find('input', attrs={'type': 'text'})['value'].strip()
        return verif

    def init_access(self, username, password):
        """ Get an access token to create a session for API interactions.

        Args:
            username (str): valid E*Trade username
            password (str): valid E*Trade password

        Returns:
            None. Side-effect is initializing the ``self.oauth`` session
                object to facilitate API calls.
        """
        auth = OAuth1Session(
            self.oauth_consumer_key,
            client_secret=self.consumer_secret,
            callback_uri='oob')
        response = auth.fetch_request_token(f'{self.prod_url}oauth/request_token')
        owner_token = response.get('oauth_token')
        response = auth.fetch_access_token(f'{self.prod_url}oauth/access_token',
                                           verifier=self.user_auth(
                                               username,
                                               password,
                                               owner_token))
        access_token = response.get('oauth_token')
        access_secret = response.get('oauth_token_secret')
        self.oauth = OAuth1Session(
            self.oauth_consumer_key,
            client_secret=self.consumer_secret,
            resource_owner_key=access_token,
            resource_owner_secret=access_secret)
        return None

    def generic_call(self, module, method, sandbox=True):
        """ Prepare the basic URL for API requests.

        Args:
            module (str): module name in {accounts, market, order,
                streaming, statuses, notification}.
            method (str): See the API_.
            sandbox (bool): True for the sandbox API, False for prod.

            .. API_: https://developer.etrade.com/ctnt/dev-portal/\
                    getArticleByCategory?category=Documentation.
        Returns:
            string url.
        """
        if sandbox:
            return f'{self.sandbox_url}{module}/sandbox/rest/{method}'
        return f'{self.prod_url}{module}/rest/{method}'


class TerminalDriver(object):
    """ The setup and execution of a text-driven API interaction.

    This class primarily supports command line exploration of the
    API to test the development of automated functions.

    TODO: pull in the `E*Trade developer pages`_ since they are organized
    by text module and method names (although not identical) and
    we could simple pull and parse this information to have handy.

    .. _E*Trade developer pages: https://developer.etrade.com/ctnt/dev-portal/getDetail?contentUri=V0_Documentation-AccountsAPI-ListAccounts

    Attributes:
        config_file (str): the name of the configuration file.
        privkey (str): the location in the filesystem of the private RSA key.
        user_file (str): file name to the encrypted E*Trade account username.
        pass_file (str): file name to the encrypted E*Trade account password.
    """
    def __init__(self, args):
        if len(args) != 3:
            print('Usage: wrapper.py <config_file_path> <rsa private key loc>')
            sys.exit(1)
        self.config_file = args[1]
        self.privkey = args[2]
        self.user_file = f'{self.config_file}.u'
        self.pass_file = f'{self.config_file}.p'

    @staticmethod
    def _encrypt(value, key_loc, *, enc='utf8'):
        """ Encrypt ``value`` using the key found at ``key_loc``.

        Following the example found on PyCrypto's_ documentation for
        PKCS1_v1_5.

        ** _PyCrypto's: https://www.dlitz.net/software/pycrypto/api/current/

        Args:
            value (str): String assumed to be compatible with encoding
                using ``enc``.
            key_loc (str): Path to the file like ``id_rsa``.
            enc (str): valid encoding option for the ``encode`` method of str.
        Returns:
            Encrypted bytestring ciphertext of ``value``.
        """
        hashed = SHA.new(value.encode(enc))
        key = RSA.importKey(open(key_loc, 'r').read())
        cipher = PKCS1_v1_5.new(key)
        return cipher.encrypt(value.encode(enc) + hashed.digest())

    @staticmethod
    def _decrypt(ciphertext, key_loc, *, enc='utf8'):
        """ Decrypt ``ciphertext`` using the key found at ``key_loc``.

        Following the example found on PyCrypto's_ documentation for
        PKCS1_v1_5.

        ** _PyCrypto's: https://www.dlitz.net/software/pycrypto/api/current/

        Args:
            ciphertext (str): Bytestring data to decrypt.
            key_loc (str): Path to the file like ``id_rsa.pub``.
            enc (str): valid encoding option for the ``encode`` method of str.
        Returns:
            Encrypted bytestring ciphertext of ``value``.
        """
        key = RSA.importKey(open(key_loc, 'r').read())
        dsize = SHA.digest_size
        sentinel = Random.new().read(15+dsize)
        cipher = PKCS1_v1_5.new(key)
        return cipher.decrypt(ciphertext, sentinel)[:-1*dsize].decode(enc)

    def parse_args(self):
        """Parse arguments and configuration file parameters.

        Assumes that the public key is the same as private key with .pub suffixed.

        Returns:
            ConfigParser object with necessary fields completed.
        """
        # Get config file
        config = ConfigParser()
        config.read(self.config_file)
        # Check if there's a username/password field.
        # If not, get it and store it for later use
        all_sections = [section for (section, _) in config.items()]
        if 'etrade' not in all_sections:
            username = input('Enter your E*Trade username: ')
            password = getpass.getpass('E*Trade password: ')
            config.add_section('etrade')
            config.set('etrade', 'username', self.user_file)
            config.set('etrade', 'password', self.pass_file)
            with open(self.config_file, 'w') as cfgfile:
                config.write(cfgfile)
            with open(self.user_file, 'wb') as userfile:
                userfile.write(TerminalDriver._encrypt(username, f'{self.privkey}.pub'))
            with open(self.pass_file, 'wb') as passfile:
                passfile.write(TerminalDriver._encrypt(password, f'{self.privkey}.pub'))
        return config

    def loop(self):
        """ Simple terminal driver for testing API calls manually.

        * First entry is a module: (accounts, market, order, etc.)
        * Second entry is a method: (accountlist, quote, etc.)
        * Next, parameter and value pairs are requested until q, Q, or quit
            is given for the parameter name.

        You must use ``^+C to quit the program.

        Returns:
            None. Infinite loop until user termination (or bug in the code).
        """
        # Get the info we need to get access tokens to start making
        # API calls
        config = self.parse_args()
        username = TerminalDriver._decrypt(
            open(config.get('etrade', 'username'), 'rb').read(),
            self.privkey)
        password = TerminalDriver._decrypt(
            open(config.get('etrade', 'password'), 'rb').read(),
            self.privkey)
        # Initiate the connections with E*Trade
        sess = ETradeAPI(config.get('secret', 'oauth_consumer_key'),
                         config.get('secret', 'consumer_secret'))
        sess.init_access(username, password)

        # Do the command line driver work
        while True:
            module = input('Enter module: ')
            method = input('Enter method: ')
            names = []
            values = []
            quits = ['q', 'Q', 'quit']
            while not names or names[-1] not in quits:
                names.append(input('Enter parameter name: '))
                if names[-1] not in quits:
                    values.append(input(f'Enter {names[-1]} value: '))
            base = sess.generic_call(module, method)
            # If there are parameters, insert a /
            if len(names) > 1:
                base += '/'
            params = dict(zip(names, values))
            # If accountId is present, it always goes first
            if 'accountId' in params:
                base += params['accountId']
            params.pop('accountId', None)
            # Quote takes a list of , separated stock symbols.
            if method == 'quote':
                if '' not in params:
                    print('Error, `quote` must have an unnammed parameter.')
                    continue
                base += params['']
                params.pop('', None)
            print(base)
            print(params)
            response = sess.oauth.get(base+'.json', params=params)
            print(response.status_code)
            if response.status_code == 200:
                print(response.content)
        return None


# LOGIC:
# See if there are any COF stocks over 1 year old.
# If there are, see the buy price.
# If the current price > buy price, then sell.
if __name__ == '__main__':
    TerminalDriver(sys.argv).loop()
