import logging
import uuid
import json
import ssl
import threading
from OpenSSL import crypto
from socket import gethostname
from os.path import exists, join
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

from grr import config
from grr.lib import registry
from subprocess import Popen

OSQUERY_CERT_FILE = "osquery-service.crt"
OSQUERY_KEY_FILE = "osquery-service.key"
ENROLL_SECRET = "HostBasedForensics"
ENROLL_SECRET_ENV = "GRR_OSQUERY_ENROLL_SECRET"

osQueryService = None

class OSQueryServiceInit(registry.InitHook):

  lock = threading.RLock()

  osquery_args = {
      "verbose" : "False",
      "ephemeral": "True",
      "tls_hostname" : "",
      "config_tls_endpoint": "/config",
      "logger_tls_endpoint": "/logger",
      "enroll_tls_endpoint": "/enroll",
      "enroll_secret_env": ENROLL_SECRET_ENV,
      "logger_plugin": "tls",
      "tls_server_certs": "%s/%s" % ("/tmp", OSQUERY_CERT_FILE),
      "disable_distributed": "false",
      "distributed_plugin": "tls",
      "distributed_tls_read_endpoint": "/distributed_read",
      "distributed_tls_write_endpoint": "/distributed_write",
      "distributed_interval": "60",
      "config_plugin" : "tls",
      "config_tls_refresh" : "60"
    }

  def RunOnce(self):
    global osQueryService

    if config.CONFIG["Client.labels"] and "osquery" in config.CONFIG["Client.labels"]:
      logging.info("Starting OSQuery Service ...")
      osQueryService = OSQueryService()
      osQueryService.start()

      #Now start osqueryd
      self.osquery_args["tls_hostname"] = osQueryService.getHTTPEndpoint()
      osqueryArgs = ["osqueryd"]
      for param, value in self.osquery_args.iteritems():
        osqueryArgs.append("--%s=%s" % (param, value))

      logging.info("Starting osqueryd with:  %s" % ' '.join(osqueryArgs))

      pid = Popen(osqueryArgs, env={ENROLL_SECRET_ENV: ENROLL_SECRET}).pid
      logging.info("osqueryd starting with process %d" % pid)

    else:
      logging.info("OSQuery label not found, not staring OSQuery Service:  %s ..."
                   % ','.join(config.CONFIG["Client.labels"]))


OSQUERY_CONFIG = {
    "schedule": {},
    "node_invalid": False,
}

OSQUERY_DISTRIBUTED = {
    "queries": {},
    "node_invalid": False,
}

BUFFERED_RESULTS = {} 

class OSQueryService(threading.Thread):

  def __init__(self):
    threading.Thread.__init__(self)
    self.httpd = None
    self.daemon = True
    self.name = "OSQuery Service"
    self.httpd = HTTPServer(('127.0.0.1', 0), OSQueryHandler)
    create_self_signed_cert("/tmp", OSQUERY_CERT_FILE, OSQUERY_KEY_FILE)

    self.httpd.socket = ssl.wrap_socket(self.httpd.socket,
                       ca_certs="%s/%s" % ("/tmp", OSQUERY_CERT_FILE),
                       ssl_version=ssl.PROTOCOL_SSLv23,
                       certfile="%s/%s" % ("/tmp", OSQUERY_CERT_FILE),
                       keyfile="%s/%s" % ("/tmp", OSQUERY_KEY_FILE),
                       server_side=True)
    self.waitingActions = {}
    self.waitingActionsLock = threading.Lock()

  def getHTTPEndpoint(self):
    return "%s:%s" % ("127.0.0.1", self.httpd.server_port)

  def getQueryResults(self, query):
    global OSQUERY_DISTRIBUTED

    query_id = str(id(query))
    with self.waitingActionsLock:
      self.waitingActions[query_id] = threading.Event()
      OSQUERY_DISTRIBUTED["queries"][query_id] = query

    event = self.waitingActions[query_id]
    logging.debug("Query Request %s is waiting" % query_id)
    #wait for osquery to deliver the results to the service
    event.wait()
    logging.debug("Query Request %s awakened and returning data ..." % query_id)
    with self.waitingActionsLock:
      return self.waitingActions[query_id]

  def scheduleQuery(self,query_id,query,interval):
    global OSQUERY_CONFIG

    logging.debug("Scheduling a query, query_id: %s, query: %s, interval: %d ..." % (query_id,query,interval))
    OSQUERY_CONFIG["schedule"][query_id]={"query": query, "interval": interval}
    logging.debug("dumping CONFIG ...")
    logging.debug("\n%s" % json.dumps(OSQUERY_CONFIG, indent=2))
    return "added to config list"

  def removeScheduledQuery(self,query_id):
    global OSQUERY_CONFIG
    global BUFFERED_RESULTS

    logging.debug("Removing query: %s ..." % (query_id))
    OSQUERY_CONFIG["schedule"].pop(query_id,None)
    BUFFERED_RESULTS.pop(query_id,None) 
    return "Removed"

  def pullScheduledQuery(self, query_id):
    global BUFFERED_RESULTS
    logging.debug("Pulling query: %s ..." % (query_id))
    ToSend = BUFFERED_RESULTS[query_id]
    BUFFERED_RESULTS.pop(query_id,None)
    return ToSend

  def listScheduledQueries(self):
    global OSQUERY_CONFIG
    logging.debug("Listing scheduled queries ...")
    return OSQUERY_CONFIG["schedule"]

  def submitQueryResult(self, query_id, data):
    global OSQUERY_DISTRIBUTED

    with self.waitingActionsLock:
      del OSQUERY_DISTRIBUTED["queries"][query_id]
      event = self.waitingActions[query_id]
      self.waitingActions[query_id] = data
      logging.debug("Query Request %s is being awakened ..." % query_id)
      event.set()


  def run(self):
    logging.debug("Starting TLS/HTTPS server on TCP port: %d" % self.httpd.server_port)

    self.httpd.serve_forever()

class OSQueryHandler(BaseHTTPRequestHandler):

    enrolled_clients = []

    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        logging.debug("OSQueryHandler::get %s" % self.path)
        self._set_headers()
        if self.path == '/config':
            content_len = int(self.headers.getheader('content-length', 0))
            body = self.rfile.read(content_len)
            request = json.loads(body)
            self.config(request, node=True)
        else:
            self._reply({})

    def do_HEAD(self):
        logging.debug("OSQueryHandler::head %s" % self.path)
        self._set_headers()

    def do_POST(self):
        logging.debug("OSQueryHandler::post %s" % self.path)
        self._set_headers()
        content_len = int(self.headers.getheader('content-length', 0))

        body = self.rfile.read(content_len)
        request = json.loads(body)

        logging.debug("Request: %s" % str(request))

        if self.path == '/enroll':
            self.enroll(request)
        elif self.path == '/config':
            self.config(request)
        elif self.path == '/logger':
            self.log(request)
        elif self.path == '/distributed_read':
            self.distributed_read(request)
        elif self.path == '/distributed_write':
            self.distributed_write(request)
        elif self.path == '/create_squery':
            self.create_squery(request)
        else:
            logging.error("Unrecognized path POSTed by osqueryd:  %s" % self.path)
            self._reply({})

    def create_squery(self, request):
        '''This endpoint is called by teh client_action to schecule a new query'''
        logging.debug("create_squery, query_name: %s query: %s  interval: %d" % (request["query_name"],request["query"],request["interval"]))
        OSQUERY_CONFIG["schedule"][request["query_name"]]={"query": request["query"], "interval": request["interval"]}
        logging.debug("\n%s" % (json.dumps(OSQUERY_CONFIG, indent=2)))
        self._reply({})



    def enroll(self, request):
        '''A basic enrollment endpoint'''

        # This endpoint expects an "enroll_secret" POST body variable.
        # Over TLS, this string may be a shared secret value installed on every
        # managed host in an enterprise.

        # Alternatively, each client could authenticate with a TLS client cert.
        # Then, access to the enrollment endpoint implies the required auth.
        # A generated node_key is still supplied for identification.
        if ENROLL_SECRET != request["enroll_secret"]:
            logging.error("Failed Enrollment secret from osqueryd")
            self._reply({"node_invalid": True})
            return

        node_key = str(uuid.uuid4())
        self.enrolled_clients.append(node_key)
        logging.error("Successful Enrollment of osqueryd! Assigned node key = %s" % node_key)

        self._reply({"node_key": node_key})

    def config(self, request, node=False):
        '''A basic config endpoint'''

        # This endpoint responds with a JSON body that is the entire config
        # content. There is no special key or status.

        # The osquery TLS config plugin calls the TLS enroll plugin to retrieve
        # a node_key, then submits that key alongside config/logger requests.
        if "node_key" not in request or request["node_key"] not in self.enrolled_clients:
            self._reply({"node_invalid": True})
            return

        if node:
            self._reply(OSQUERY_CONFIG)
            return
        self._reply(OSQUERY_CONFIG)

    def distributed_read(self, request):
        '''A basic distributed read endpoint'''
        if "node_key" not in request or request["node_key"] not in self.enrolled_clients:
            self._reply({"node_invalid": True})
            return
        else:
          self._reply(OSQUERY_DISTRIBUTED)

    def distributed_write(self, request):
        '''A basic distributed write endpoint'''

        if "queries" in request:
          for query_id, data in request["queries"].iteritems():
              osQueryService.submitQueryResult(query_id, data)

        self._reply({})

    def log(self, request):
        global osQueryService
        global BUFFERED_RESULTS
        global OSQUERY_CONFIG

        for entry in request['data']:
          # check if this log entry is a result of a scheduled query
          if 'name' in entry and entry['name'] in OSQUERY_CONFIG['schedule']:
            # If this is a new scheduled query running for the first time, create a key for it in BUFFERED_RESULTS
            if entry['name'] not in BUFFERED_RESULTS:
              BUFFERED_RESULTS.update({entry['name']:[]})
            # add the new entry
            BUFFERED_RESULTS[entry['name']].append(entry)
            logging.debug("BUFFERED_RESULTS updated.. dumping buffer ...")
            logging.debug("\n%s" % (json.dumps(BUFFERED_RESULTS, indent=2)))
        self._reply({})

    def _reply(self, response):
        logging.debug("Replying: %s" % (str(response)))
        self.wfile.write(json.dumps(response))


def create_self_signed_cert(cert_dir, cert_file, key_file):
    """
    If datacard.crt and datacard.key don't exist in cert_dir, create a new
    self-signed cert and keypair and write them into that directory.
    """

    if not exists(join(cert_dir, cert_file)) \
            or not exists(join(cert_dir, key_file)):

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 1024)

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "Pennsylvania"
        cert.get_subject().L = "Pittsburgh"
        cert.get_subject().O = "GRR+OSQuery"
        cert.get_subject().OU = "Engineering"
        cert.get_subject().CN = gethostname()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')

        open(join(cert_dir, cert_file), "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open(join(cert_dir, key_file), "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
