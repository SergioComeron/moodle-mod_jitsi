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

class WorkloadIdentityConfig extends \Google\Model
{
  public const IDENTITY_TYPE_AGENT_IDENTITY = 'AGENT_IDENTITY';
  public const IDENTITY_TYPE_IDENTITY_TYPE_UNSPECIFIED = 'IDENTITY_TYPE_UNSPECIFIED';
  public const IDENTITY_TYPE_SERVICE_ACCOUNT = 'SERVICE_ACCOUNT';
  /**
   * @var string
   */
  public $identity;
  /**
   * @var bool
   */
  public $identityCertificateEnabled;
  /**
   * @var string
   */
  public $identityType;

  /**
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
   * @param bool $identityCertificateEnabled
   */
  public function setIdentityCertificateEnabled($identityCertificateEnabled)
  {
    $this->identityCertificateEnabled = $identityCertificateEnabled;
  }
  /**
   * @return bool
   */
  public function getIdentityCertificateEnabled()
  {
    return $this->identityCertificateEnabled;
  }
  /**
   * @param self::IDENTITY_TYPE_* $identityType
   */
  public function setIdentityType($identityType)
  {
    $this->identityType = $identityType;
  }
  /**
   * @return self::IDENTITY_TYPE_*
   */
  public function getIdentityType()
  {
    return $this->identityType;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(WorkloadIdentityConfig::class, 'Google_Service_Compute_WorkloadIdentityConfig');
