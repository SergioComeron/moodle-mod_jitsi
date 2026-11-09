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

class BackendServiceDynamicForwardingForwardProxy extends \Google\Model
{
  /**
   * Dynamic forwarding directly to Cloud Run services.
   */
  public const PROXY_MODE_CLOUD_RUN = 'CLOUD_RUN';
  /**
   * Dynamic forwarding based on the Http Host header.
   */
  public const PROXY_MODE_DIRECT_FORWARDING = 'DIRECT_FORWARDING';
  /**
   * A boolean flag enabling dynamic forwarding proxy.
   *
   * @var bool
   */
  public $enabled;
  /**
   * Determines the dynamic forwarding proxy mode.
   *
   * @var string
   */
  public $proxyMode;

  /**
   * A boolean flag enabling dynamic forwarding proxy.
   *
   * @param bool $enabled
   */
  public function setEnabled($enabled)
  {
    $this->enabled = $enabled;
  }
  /**
   * @return bool
   */
  public function getEnabled()
  {
    return $this->enabled;
  }
  /**
   * Determines the dynamic forwarding proxy mode.
   *
   * Accepted values: CLOUD_RUN, DIRECT_FORWARDING
   *
   * @param self::PROXY_MODE_* $proxyMode
   */
  public function setProxyMode($proxyMode)
  {
    $this->proxyMode = $proxyMode;
  }
  /**
   * @return self::PROXY_MODE_*
   */
  public function getProxyMode()
  {
    return $this->proxyMode;
  }
}

// Adding a class alias for backwards compatibility with the previous class name.
class_alias(BackendServiceDynamicForwardingForwardProxy::class, 'Google_Service_Compute_BackendServiceDynamicForwardingForwardProxy');
