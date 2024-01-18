import trustpoint_client.trustpoint_client as tc

# callback functionality so that some external process can be optionally triggered after part of provisioning is complete
def testCallback(a :tc.ProvisioningState):
  print("callback: " + tc.ProvisioningState(a).name)