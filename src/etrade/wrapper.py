"""
Houses the methods needed to interact with
the E*Trade API.
"""
from configparser import ConfigParser
# import json
# import requests
from requests_oauthlib import OAuth1Session

class Wrapper(object):
    """
    Encapsulates the authentication routines.
    """
    def __init__(self, oauth_consumer_key, consumer_secret):
        self.oauth_consumer_key = oauth_consumer_key
        self.consumer_secret = consumer_secret
        self.sandbox_url = 'https://etwssandbox.etrade.com/'
        self.prod_url = 'https://etws.etrade.com/'
        self.oauth = None

    def init_access(self):
        """ Get an access token for this session.

        This method currently requires the user to follow a link
        and return the 5 character code to the standard input.

        TODO future improvement:

        1. Start a session with the url created
        2. get the page, check if it is the login page, else step 4
        3. pass the E*Trade username and password to the page
        4. pass the accept button info
        5. parse the field where the 5 character code is to complete the trxn.
        """
        auth = OAuth1Session(
            self.oauth_consumer_key, client_secret=self.consumer_secret,
            callback_uri='oob')
        response = auth.fetch_request_token(f'{self.prod_url}oauth/request_token')
        owner_token = response.get('oauth_token')
        # owner_secret = response.get('oauth_token_secret')
        auth_url = (f'https://us.etrade.com/e/t/etws/authorize?'
                    f'key={self.oauth_consumer_key}&token={owner_token}')
        print(auth_url)
        verif = input('Verification code: ').strip()
        response = auth.fetch_access_token(f'{self.prod_url}oauth/access_token',
                                           verifier=verif)
        access_token = response.get('oauth_token')
        access_secret = response.get('oauth_token_secret')
        self.oauth = OAuth1Session(
            self.oauth_consumer_key,
            client_secret=self.consumer_secret,
            resource_owner_key=access_token,
            resource_owner_secret=access_secret)

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

# LOGIC:
# See if there are any COF stocks over 1 year old.
# If there are, see the buy price.
# If the current price > buy price, then sell.

def main():
    """ Simple terminal driver for testing API calls manually.
    """
    config = ConfigParser()
    config.read('/home/sloscal1/workspace/etrade_app/.local_info.txt')
    sess = Wrapper(config.get('secret', 'oauth_consumer_key'),
                   config.get('secret', 'consumer_secret'))
    sess.init_access()
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
        if method == 'quote':
            base += params['']
            params.pop('', None)
        print(base)
        print(params)
        response = sess.oauth.get(base, params=params)
        print(response.status_code)
        if response.status_code == 200:
            print(response.content)

if __name__ == '__main__':
    main()
