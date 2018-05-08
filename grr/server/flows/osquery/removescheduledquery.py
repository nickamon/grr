'''
Created on April 7, 2018

@author: Mohammed Almodawah
'''
#!/usr/bin/env python
"""These are OSQuery related flows."""

from grr.lib.rdfvalues import osquery as rdf_osquery
from grr.server import flow
from grr.server import osquery_stubs
from grr.server.flows.osquery import osqueryCron

class RemoveScheduledQuery(flow.GRRFlow):
  """Retrieve system data from OSQuery"""

  category = "/OSQuery/"
  behaviours = flow.GRRFlow.behaviours + "BASIC"
  args_type = rdf_osquery.OSQueryRemoveScheduledQueryArgs

  @flow.StateHandler()
  def Start(self):
    """Start processing."""
    self.CallClient(
      osquery_stubs.ExecuteRemoveScheduledQuery,
      query_id=self.args.query_id,
      next_state="ValidateSQLResult")

    job="aff4:/cron/ScheduleOSQueryPull"+str(self.args.query_id)
    cron=osqueryCron.ScheduledQuery()
    cron.removeCron(job, self.token)

  @flow.StateHandler()
  def ValidateSQLResult(self, responses):
    if not responses.success:
      self.Log(responses.status)
    else:
      for response in responses:
        self.SendReply(response)

  def NotifyAboutEnd(self):
    self.Notify("ViewObject", self.urn, "SQL Result")

  @flow.StateHandler()
  def End(self):
    self.Log("Successfully executed SQL")