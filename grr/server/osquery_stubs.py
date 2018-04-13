"""
Stubs of OSQuery client actions.

Similar pattern as server_stubs

@author: ashaman
"""
from grr.server.server_stubs import ClientActionStub
from grr.lib.rdfvalues import osquery as rdf_client_osquery

class ExecuteOSQuerySQL(ClientActionStub):
  """Run an OSQuery"""

  in_rdfvalue = rdf_client_osquery.OSQueryRunQueryArgs
  out_rdfvalues = [rdf_client_osquery.OSQueryRunQueryResult]

class ExecuteScheduledQuery(ClientActionStub):
  """Run an OSQuery"""

  in_rdfvalue = rdf_client_osquery.OSQueryScheduledQueryArgs
  out_rdfvalues = [rdf_client_osquery.OSQueryScheduledQueryResult]

class ExecuteRemoveScheduledQuery(ClientActionStub):
  """Run an OSQuery"""

  in_rdfvalue = rdf_client_osquery.OSQueryRemoveScheduledQueryArgs
  out_rdfvalues = [rdf_client_osquery.OSQueryRemoveScheduledQueryResult]

class ExecuteListScheduledQueries(ClientActionStub):
  """Run an OSQuery"""

  in_rdfvalue = None
  out_rdfvalues = [rdf_client_osquery.OSQueryListScheduledQueriesResult]

class ExecutePullScheduledQuery(ClientActionStub):
  """Run an OSQuery"""

  in_rdfvalue = rdf_client_osquery.OSQueryPullScheduledQueryArgs
  out_rdfvalues = [rdf_client_osquery.OSQueryPullScheduledQueryResult]
