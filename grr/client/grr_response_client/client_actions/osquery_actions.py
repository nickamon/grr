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
