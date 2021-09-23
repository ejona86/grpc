# Copyright 2021 gRPC authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging

from absl import flags
from absl.testing import absltest

from framework import xds_k8s_testcase
from framework.helpers import rand

logger = logging.getLogger(__name__)
flags.adopt_module_key_flags(xds_k8s_testcase)

# Type aliases
_XdsTestServer = xds_k8s_testcase.XdsTestServer
_XdsTestClient = xds_k8s_testcase.XdsTestClient
_SecurityMode = xds_k8s_testcase.SecurityXdsKubernetesTestCase.SecurityMode


class AuthzTest(xds_k8s_testcase.SecurityXdsKubernetesTestCase):

    def test_authz(self):
        """Authz test.

        Both client and server configured to use TLS and mTLS. Then check authz results.
        """
        self.setupTrafficDirectorGrpc()
        #self.td.setup_client_security(server_namespace=self.server_namespace,
        #                              server_name=self.server_name,
        #                              tls=True,
        #                              mtls=True)
        #self.td.create_server_tls_policy(tls=True, mtls=True)
        #    self.td.create_authz_policy(action='ALLOW', rules=[])
        #self.td.create_endpoint_policy(server_namespace=self.server_namespace,
        #                               server_name=self.server_name,
        #                               server_port=self.server_port)

        self.setupSecurityPolicies(server_tls=True,
                                   server_mtls=True,
                                   client_tls=True,
                                   client_mtls=True)

        test_server: _XdsTestServer = self.startSecureTestServer()
        self.setupServerBackends()
        test_client: _XdsTestClient = self.startSecureTestClient(test_server)

        self.assertTestAppSecurity(_SecurityMode.MTLS, test_client, test_server)
        self.assertSuccessfulRpcs(test_client)
        logger.info('[SUCCESS] mTLS security mode confirmed.')


if __name__ == '__main__':
    absltest.main()
