#!/usr/bin/env python
"""The client keys file."""

# Certificates: Separate CA certificates are stored here. The --camode argument
# in the client sets which one of these the client trusts. The default
# of --camode is set by the CAMODE value below.
# This provides enforced isolation of the environments.

CAMODE = "TEST"

CACERTS = {
    "TEST": """
-----BEGIN CERTIFICATE-----
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
ImKbVCFIXYW/vECT2R/v
-----END CERTIFICATE-----
"""
}

# Key for controlling code execution.
EXEC_SIGNING_KEY = {
    "TEST": """
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMQpeVjrxmf6nPmsjHjULWhLmquSgTDK
GpJgTFkTIAgX0Ih5lxoFB5TUjUfJFbBkSmKQPRA/IyuLBtCLQgwkTNkCAwEAAQ==
-----END PUBLIC KEY-----
"""}

# Key for controlling driver execution.
DRIVER_SIGNING_KEY = {
    "TEST": """
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALnfFW1FffeKPs5PLUhFOSkNrr9TDCOD
QAI3WluLh0sW7/ro93eoIZ0FbipnTpzGkPpriONbSOXmxWNTo0b9ma8CAwEAAQ==
-----END PUBLIC KEY-----
"""}