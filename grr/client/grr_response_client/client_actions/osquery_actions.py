#!/usr/bin/env python
"""Execute OSQuery SQL."""

from grr_response_client import actions
from grr.lib.rdfvalues import osquery as rdf_osquery
from grr_response_client.plugins import osquery


class ExecuteOSQuerySQL(actions.ActionPlugin):
  """Execute OSQuery SQL."""
  in_rdfvalue = rdf_osquery.OSQueryRunQueryArgs
  out_rdfvalues = [rdf_osquery.OSQueryRunQueryResult]

  def Run(self, args):
    data = osquery.osQueryService.getQueryResults(args.query)

    for row in data:
      result = rdf_osquery.OSQueryRunQueryResult()
      for key, value in row.items():
        resultult_field = getattr(result,key)
        resultult_field.append(value)

      self.SendReply(result)

class ExecuteScheduledQuery(actions.ActionPlugin):
  """Execute OSQuery SQL."""
  in_rdfvalue = rdf_osquery.OSQueryScheduledQueryArgs
  out_rdfvalues = [rdf_osquery.OSQueryScheduledQueryResult]

  def Run(self, args):
    status = osquery.osQueryService.scheduleQuery(args.query_id,args.query,args.interval)
    result = rdf_osquery.OSQueryScheduledQueryResult()
    result.status = status
    self.SendReply(result)

class ExecuteRemoveScheduledQuery(actions.ActionPlugin):
  """Execute OSQuery SQL."""
  in_rdfvalue = rdf_osquery.OSQueryRemoveScheduledQueryArgs
  out_rdfvalues = [rdf_osquery.OSQueryRemoveScheduledQueryResult]

  def Run(self, args):
    status = osquery.osQueryService.removeScheduledQuery(args.query_id)
    result = rdf_osquery.OSQueryRemoveScheduledQueryResult()
    result.status = status
    self.SendReply(result)

class ExecuteListScheduledQueries(actions.ActionPlugin):
  """Execute OSQuery SQL."""
  in_rdfvalue = None
  out_rdfvalues = [rdf_osquery.OSQueryListScheduledQueriesResult]

  def Run(self, args):
    data = osquery.osQueryService.listScheduledQueries()
    for key, row in data.items():
      result = rdf_osquery.OSQueryListScheduledQueriesResult()
      result.query_id = key
      result.query = row['query']
      result.interval = row['interval']
      self.SendReply(result)

class ExecutePullScheduledQuery(actions.ActionPlugin):
  """Execute OSQuery SQL."""
  in_rdfvalue = rdf_osquery.OSQueryPullScheduledQueryArgs
  out_rdfvalues = [rdf_osquery.OSQueryPullScheduledQueryResult]

  def Run(self, args):
    data = osquery.osQueryService.pullScheduledQuery(args.query_id)
    for entry in data:
      result = rdf_osquery.OSQueryPullScheduledQueryResult()
      result.name = entry['name']
      result.calendarTime = entry['calendarTime']
      result.counter = entry['counter']
      result.epoch = entry['epoch']
      result.unixTime = entry['unixTime']
      result.action = entry['action']
      for key, value in entry['columns'].items():
        resultult_field = getattr(result.row,key)
        resultult_field.append(value)
      self.SendReply(result)
