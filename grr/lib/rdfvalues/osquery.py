'''
AFF4 RDFValue implementations for OSQuery client information.


Created on Mar 23, 2018

@author: ashaman
'''

from grr.lib.rdfvalues import structs
from grr_response_proto import osquery_pb2


class OSQueryRunQueryResult(structs.RDFProtoStruct):
  """Result of OSQuery SQL."""
  protobuf = osquery_pb2.OSQueryRunQueryResult


class OSQueryRunQueryArgs(structs.RDFProtoStruct):
  """Execute OSQuery SQL."""
  protobuf = osquery_pb2.OSQueryRunQueryArgs

class OSQueryScheduledQueryResult(structs.RDFProtoStruct):
  """Scheduled Query Result."""
  protobuf = osquery_pb2.OSQueryScheduledQueryResult

class OSQueryScheduledQueryArgs(structs.RDFProtoStruct):
  """Scheduled Query Args"""
  protobuf = osquery_pb2.OSQueryScheduledQueryArgs

class OSQueryRemoveScheduledQueryArgs(structs.RDFProtoStruct):
  """Scheduled Query Args"""
  protobuf = osquery_pb2.OSQueryRemoveScheduledQueryArgs

class OSQueryRemoveScheduledQueryResult(structs.RDFProtoStruct):
  """Scheduled Query Result."""
  protobuf = osquery_pb2.OSQueryRemoveScheduledQueryResult

class OSQueryListScheduledQueriesResult(structs.RDFProtoStruct):
  """Scheduled Query Result."""
  protobuf = osquery_pb2.OSQueryListScheduledQueriesResult

class OSQueryPullScheduledQueryArgs(structs.RDFProtoStruct):
  """Scheduled Query Result."""
  protobuf = osquery_pb2.OSQueryPullScheduledQueryArgs

class OSQueryPullScheduledQueryResult(structs.RDFProtoStruct):
  """Scheduled Query Result."""
  protobuf = osquery_pb2.OSQueryPullScheduledQueryResult
  rdf_deps = [
    OSQueryRunQueryResult,
]
