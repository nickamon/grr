#!/usr/bin/env python

from grr.lib.rdfvalues import osquery as rdf_osquery
from grr.server.flows.osquery import pullscheduledquery
from grr.server.aff4_objects import cronjobs
from grr.server.hunts import standard as hunts

class ScheduledQuery():

  def scheduleCron(self, interval, query_id, client_id, token):

    flow_args = hunts.CreateGenericHuntFlowArgs()
    flow_args.hunt_args.flow_args = rdf_osquery.OSQueryPullScheduledQueryArgs(
        query_id=query_id)
    flow_args.hunt_args.flow_runner_args.flow_name=pullscheduledquery.PullScheduledQuery.__name__
    flow_args.hunt_args.flow_runner_args.client_id=client_id

    flow_args.hunt_runner_args.hunt_name="GenericHunt"

    huntName=hunts.CreateAndRunGenericHuntFlow.__name__
    job="ScheduleOSQueryPull"+str(query_id)
    cron_args = cronjobs.CreateCronJobFlowArgs(
        periodicity=interval, lifetime="1d", allow_overruns=False)

    cron_args.flow_runner_args.flow_name=huntName
    cron_args.flow_runner_args.client_id=client_id

    cron_args.flow_args = flow_args

    cronjobs.CRON_MANAGER.ScheduleFlow(
        cron_args, job_name=job, token=token)


  def removeCron(self, job, token):

    cron_manager = cronjobs.CronManager()
    cron_manager.DisableJob(job, token=token)
    cron_manager.DeleteJob(job, token=token)