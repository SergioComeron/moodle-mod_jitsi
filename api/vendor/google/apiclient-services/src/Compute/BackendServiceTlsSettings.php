<?php
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

namespace Google\Service\Compute;

class BackendServiceTlsSettings extends \Google\Collection
{
  protected $collection_key = 'subjectAltNames';
  /**
   * Reference to the BackendAuthenticationConfig resource from the
   * networksecurity.googleapis.com namespace. Can be used in authenticating TLS
   * connections to the backend, as specified by the authenticationMode field.
   * Can only be specified if authenticationMode is not NONE.
   *
   * @var string
   */
  public $authenticationConfig;
  /**
   * Assigns the Managed Identity for the BackendService Workload.
   *
   * Use this property to configure the load balancer back-end to use
   * certificates and roots of trust provisioned by the Managed Workload
   * Identity system.
   *
   *  The `identity` property is the fully-specified SPIFFE ID to use in the
   * SVID presented by the Load Balancer Workload.
   *
   *  The SPIFFE ID must be a resource starting with the `trustDomain` property
   * value, followed by the path to the Managed Workload Identity.
   *
   *  Supported SPIFFE ID format:         - ns//sa/
   *
   * The Trust Domain within the Managed Identity must refer to a valid Workload
   * Identity Pool. The TrustConfig and CertificateIssuanceConfig will be
   * inherited from the Workload Identity Pool.
   *
   *  Restrictions:         - If you set the `identity` property, you cannot
   * manually set    the following fields:         - tlsSettings.sni       -
   * tlsSettings.subjectAltNames       - tlsSettings.authenticationConfig
   *
   * When defining a `identity` for a RegionBackendServices, the corresponding
   * Workload Identity Pool must have a ca_pool configured in the same region.
   *
   *  The system will set up a read-onlytlsSettings.authenticationConfig for the
   * Managed Identity.
   *
   * @var string
   */
  public $identity;
  /**
   * Server Name Indication - see RFC3546 section 3.1. If set, the load balancer
   * sends this string as the SNI hostname in the TLS connection to the backend,
   * and requires that this string match a Subject Alternative Name (SAN) in the
   * backend's server certificate. With a Regional Internet NEG backend, if the
   * SNI is specified here, the load balancer uses it regardless of whether the
   * Regional Internet NEG is specified with FQDN or IP address and port. When
   * both sni and subjectAltNames[] are specified, the load balancer matches the
   * backend certificate's SAN only to subjectAltNames[].
   *
   * @var string
   */
  public $sni;
  protected $subjectAltNamesType = BackendServiceTlsSettingsSubjectAltName::class;
  protected $subjectAltNamesDataType = 'array';

  /**
   * Reference to the BackendAuthenticationConfig resource from the
   * networksecurity.googleapis.com namespace. Can be used in authenticating TLS
   * connections to the backend, as specified by the authenticationMode field.
   * Can only be specified if authenticationMode is not NONE.
   *
   * @param string $authenticationConfig
   */
  public function setAuthenticationConfig($authenticationConfig)
  {
    $this->authenticationConfig = $authenticationConfig;
  }
  /**
   * @return string
   */
  public function getAuthenticationConfig()
  {
    return $this->authenticationConfig;
  }
  /**
   * Assigns the Managed Identity for the BackendService Workload.
   *
   * Use this property to configure the load balancer back-end to use
   * certificates and roots of trust provisioned by the Managed Workload
   * Identity system.
   *
   *  The `identity` property is the fully-specified SPIFFE ID to use in the
   * SVID presented by the Load Balancer Workload.
   *
   *  The SPIFFE ID must be a resource starting with the `trustDomain` property
   * value, followed by the path to the Managed Workload Identity.
   *
   *  Supported SPIFFE ID format:         - ns//sa/
   *
   * The Trust Domain within the Managed Identity must refer to a valid Workload
   * Identity Pool. The TrustConfig and CertificateIssuanceConfig will be
   * inherited from the Workload Identity Pool.
   *
   *  Restrictions:         - If you set the `identity` property, you cannot
   * manually set    the following fields:         - tlsSettings.sni       -
   * tlsSettings.subjectAltNames       - tlsSettings.authenticationConfig
   *
   * When defining a `identity` for a RegionBackendServices, the corresponding
   * Workload Identity Pool must have a ca_pool configured in the same region.
   *
   *  The system will set up a read-onlytlsSettings.authenticationConfig for the
   * Managed Identity.
   *
   * @param string $identity
   */
  public function setIdentity($identity)
  {
    $this->identity = $identity;
  }
  /**
   * @return string
   */
  public function getIdentity()
  {
    return $this->identity;
  }
  /**
   * Server Name Indication - see RFC3546 section 3.1. If set, the load balancer
   * sends this string as the SNI hostname in the TLS connection to the backend,
   * and requires that this string match a Subject Alternative Name (SAN) in the
   * backend's server certificate. With a Regional Internet NEG backend, if the
   * SNI is specified here, the load balancer uses it regardless of whether the
   * Regional Internet NEG is specified with FQDN or IP address and port. When
   * both sni and subjectAltNames[] are specified, the load balancer matches the
   * backend certificate's SAN only to subjectAltNames[].
   *
   * @param string $sni
   */
  public function setSni($sni)
  {
    $this->sni = $sni;
  }
  /**
   * @return string
   */
  public function getSni()
  {
    return $this->sni;
  }
  /**
   * A list of Subject Alternative Names (SANs) that the Load Balancer verifies
   * during a TLS handshake with the backend. When the server presents its X.509
   * certificate to the Load Balancer, the Load Balancer inspects the
   * certificate's SAN field, and requires that at least one SAN match one of
   * the subjectAltNames in the list. This field is limited to 5 entries. When
   * both sni and subjectAltNames[] are specified, the load balancer matches the
   * backend certificate's SAN only to subjectAltNames[].
   *
   * @param BackendServiceTlsSettingsSubjectAltName[] $subjectAltNames
   */
  public function setSubjectAltNames($subjectAltNames)
  {
    $this->subjectAltNames = $subjectAltNames;
  }
  /**
   * @return BackendServiceTlsSettingsSubjectAltName[]
   */
  public function getSubjectAltNames()
  {
    return $this->subjectAltNames;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(BackendServiceTlsSettings::class, 'Google_Service_Compute_BackendServiceTlsSettings');
